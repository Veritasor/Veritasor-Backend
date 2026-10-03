// ─── Razorpay Connect Initiation: State Validation & Redirect URL Safety ──────
//
// Issue #249 — covers:
//   • initiateRazorpayConnect: redirect URL allowlist validation (open-redirect prevention)
//   • initiateRazorpayConnect: CSRF-safe state token generation
//   • validateRazorpayState:   structural rejection (null bytes, oversized, wrong type)
//   • validateRazorpayState:   single-use / replay prevention
//   • validateRazorpayState:   expiry enforcement
//   • validateRazorpayState:   cross-user state isolation
//   • validateRazorpayState:   forged / enumerated state rejection
//
// All tests use a dedicated Express app that mounts only the Razorpay-initiation
// route so they remain isolated from the broader integrations suite.

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import request from 'supertest'
import express, { Express, Request, Response, NextFunction } from 'express'

import {
  initiateRazorpayConnect,
  validateRazorpayState,
  _clearOAuthStateStore,
  _seedOAuthState,
} from '../../src/services/integrations/razorpay/connect.js'

// ─── Test app factory ─────────────────────────────────────────────────────────

/**
 * Build a minimal Express app that mounts `initiateRazorpayConnect` under
 * POST /initiate and injects `userId` via a simple header-based mock auth.
 */
function buildApp(userId?: string): Express {
  const app = express()
  app.use(express.json())

  // Lightweight auth shim: reads x-user-id header (mirrors existing test pattern).
  app.use((req: Request, _res: Response, next: NextFunction) => {
    const id = userId ?? (req.headers['x-user-id'] as string | undefined)
    if (id) (req as any).user = { userId: id }
    next()
  })

  app.post('/initiate', initiateRazorpayConnect)
  return app
}

// ─── Environment helpers ──────────────────────────────────────────────────────

const ALLOWED_ORIGIN = 'https://app.veritasor.com'
const ALLOWED_STAGING = 'https://staging.veritasor.com'
const CLIENT_ID = 'rzp_client_test_123'

function setEnv(origins: string = ALLOWED_ORIGIN, clientId: string = CLIENT_ID) {
  process.env.RAZORPAY_ALLOWED_REDIRECT_ORIGINS = origins
  process.env.RAZORPAY_CLIENT_ID = clientId
}

function clearEnv() {
  delete process.env.RAZORPAY_ALLOWED_REDIRECT_ORIGINS
  delete process.env.RAZORPAY_CLIENT_ID
}

// ─── Suite setup ──────────────────────────────────────────────────────────────

beforeEach(() => {
  _clearOAuthStateStore()
})

afterEach(() => {
  clearEnv()
  vi.restoreAllMocks()
})

// ═════════════════════════════════════════════════════════════════════════════
// 1. Authentication guard
// ═════════════════════════════════════════════════════════════════════════════

describe('initiateRazorpayConnect — authentication', () => {
  it('returns 401 when no user is authenticated', async () => {
    setEnv()
    const app = express()
    app.use(express.json())
    app.post('/initiate', initiateRazorpayConnect) // no auth shim → req.user is undefined

    const res = await request(app)
      .post('/initiate')
      .send({ redirectUrl: `${ALLOWED_ORIGIN}/callback` })
      .expect(401)

    expect(res.body.error).toMatch(/unauthorized/i)
  })
})

// ═════════════════════════════════════════════════════════════════════════════
// 2. Redirect URL validation (open-redirect prevention)
// ═════════════════════════════════════════════════════════════════════════════

describe('initiateRazorpayConnect — redirect URL validation', () => {
  const userId = 'user-redirect-tests'

  beforeEach(() => setEnv(`${ALLOWED_ORIGIN},${ALLOWED_STAGING}`))

  it('accepts a redirect URL whose origin is in the allowlist', async () => {
    const res = await request(buildApp(userId))
      .post('/initiate')
      .send({ redirectUrl: `${ALLOWED_ORIGIN}/oauth/razorpay/callback` })
      .expect(200)

    expect(res.body).toHaveProperty('authUrl')
    expect(res.body).toHaveProperty('state')
    expect(res.body).toHaveProperty('expiresAt')
  })

  it('accepts a second allowed origin from the allowlist', async () => {
    const res = await request(buildApp(userId))
      .post('/initiate')
      .send({ redirectUrl: `${ALLOWED_STAGING}/oauth/callback` })
      .expect(200)

    expect(res.body).toHaveProperty('authUrl')
  })

  it('rejects a redirect URL whose origin is NOT in the allowlist (open-redirect)', async () => {
    const res = await request(buildApp(userId))
      .post('/initiate')
      .send({ redirectUrl: 'https://evil.com/steal-code' })
      .expect(400)

    expect(res.body.error).toMatch(/not in the allowed list/i)
  })

  it('rejects a redirect URL that uses a javascript: scheme', async () => {
    // The URL constructor should either throw (handled) or produce a non-matching origin.
    const res = await request(buildApp(userId))
      .post('/initiate')
      .send({ redirectUrl: 'javascript:alert(1)' })
      .expect(400)

    expect(res.body).toHaveProperty('error')
  })

  it('rejects a redirect URL that uses a data: scheme', async () => {
    const res = await request(buildApp(userId))
      .post('/initiate')
      .send({ redirectUrl: 'data:text/html,<h1>hi</h1>' })
      .expect(400)

    expect(res.body).toHaveProperty('error')
  })

  it('rejects a protocol-relative URL (//evil.com)', async () => {
    const res = await request(buildApp(userId))
      .post('/initiate')
      .send({ redirectUrl: '//evil.com/callback' })
      .expect(400)

    expect(res.body).toHaveProperty('error')
  })

  it('rejects a non-URL string', async () => {
    const res = await request(buildApp(userId))
      .post('/initiate')
      .send({ redirectUrl: 'not-a-url' })
      .expect(400)

    expect(res.body).toHaveProperty('error')
  })

  it('rejects a missing redirectUrl field', async () => {
    const res = await request(buildApp(userId))
      .post('/initiate')
      .send({})
      .expect(400)

    expect(res.body.error).toMatch(/validation error/i)
  })

  it('rejects when redirectUrl is a number', async () => {
    const res = await request(buildApp(userId))
      .post('/initiate')
      .send({ redirectUrl: 12345 })
      .expect(400)

    expect(res.body).toHaveProperty('error')
  })

  it('rejects when the allowlist is empty (fail-closed)', async () => {
    // Override to empty allowlist
    process.env.RAZORPAY_ALLOWED_REDIRECT_ORIGINS = ''

    const res = await request(buildApp(userId))
      .post('/initiate')
      .send({ redirectUrl: `${ALLOWED_ORIGIN}/callback` })
      .expect(400)

    // Module reads env at boot; for this test we work around via a fresh import
    // or accept that behavior depends on module initialization order.
    // The structural check still fires — origin not in set.
    expect(res.body).toHaveProperty('error')
  })

  it('includes the redirect origin in the generated authUrl', async () => {
    const redirectUrl = `${ALLOWED_ORIGIN}/oauth/razorpay/callback`
    const res = await request(buildApp(userId))
      .post('/initiate')
      .send({ redirectUrl })
      .expect(200)

    const parsedAuth = new URL(res.body.authUrl as string)
    expect(parsedAuth.searchParams.get('redirect_uri')).toBe(redirectUrl)
  })
})

// ═════════════════════════════════════════════════════════════════════════════
// 3. State token generation
// ═════════════════════════════════════════════════════════════════════════════

describe('initiateRazorpayConnect — CSRF state token generation', () => {
  const userId = 'user-state-gen'

  beforeEach(() => setEnv())

  it('returns a 64-hex-character state token (256-bit entropy)', async () => {
    const res = await request(buildApp(userId))
      .post('/initiate')
      .send({ redirectUrl: `${ALLOWED_ORIGIN}/callback` })
      .expect(200)

    expect(res.body.state).toMatch(/^[a-f0-9]{64}$/)
  })

  it('generates unique state tokens across multiple initiations', async () => {
    const redirectUrl = `${ALLOWED_ORIGIN}/callback`
    const app = buildApp(userId)

    const states = await Promise.all(
      Array.from({ length: 5 }, () =>
        request(app)
          .post('/initiate')
          .send({ redirectUrl })
          .then((r) => r.body.state as string),
      ),
    )

    expect(new Set(states).size).toBe(5)
  })

  it('generates unique state tokens for different users', async () => {
    const redirectUrl = `${ALLOWED_ORIGIN}/callback`

    const [r1, r2] = await Promise.all([
      request(buildApp('user-A')).post('/initiate').send({ redirectUrl }),
      request(buildApp('user-B')).post('/initiate').send({ redirectUrl }),
    ])

    expect(r1.body.state).not.toBe(r2.body.state)
  })

  it('embeds the state token in the returned authUrl', async () => {
    const res = await request(buildApp(userId))
      .post('/initiate')
      .send({ redirectUrl: `${ALLOWED_ORIGIN}/callback` })
      .expect(200)

    const authUrl = new URL(res.body.authUrl as string)
    expect(authUrl.searchParams.get('state')).toBe(res.body.state)
  })

  it('includes a future expiresAt timestamp (≈ 10 minutes)', async () => {
    const before = Date.now()
    const res = await request(buildApp(userId))
      .post('/initiate')
      .send({ redirectUrl: `${ALLOWED_ORIGIN}/callback` })
      .expect(200)
    const after = Date.now()

    const expiresAt = new Date(res.body.expiresAt as string).getTime()
    expect(expiresAt).toBeGreaterThan(before + 9 * 60 * 1_000)
    expect(expiresAt).toBeLessThanOrEqual(after + 10 * 60 * 1_000 + 1_000)
  })

  it('returns 503 when RAZORPAY_CLIENT_ID is not set', async () => {
    delete process.env.RAZORPAY_CLIENT_ID

    const res = await request(buildApp(userId))
      .post('/initiate')
      .send({ redirectUrl: `${ALLOWED_ORIGIN}/callback` })
      .expect(503)

    expect(res.body.error).toMatch(/not configured/i)
  })
})

// ═════════════════════════════════════════════════════════════════════════════
// 4. validateRazorpayState — structural rejection
// ═════════════════════════════════════════════════════════════════════════════

describe('validateRazorpayState — structural rejection (no store lookup)', () => {
  it('rejects undefined', () => {
    const result = validateRazorpayState(undefined)
    expect(result.valid).toBe(false)
    expect((result as any).reason).toMatch(/missing/i)
  })

  it('rejects null', () => {
    const result = validateRazorpayState(null)
    expect(result.valid).toBe(false)
  })

  it('rejects an empty string', () => {
    const result = validateRazorpayState('')
    expect(result.valid).toBe(false)
    expect((result as any).reason).toMatch(/missing/i)
  })

  it('rejects a numeric value', () => {
    const result = validateRazorpayState(12345)
    expect(result.valid).toBe(false)
  })

  it('rejects a string exceeding STATE_MAX_LENGTH (512 chars)', () => {
    const result = validateRazorpayState('a'.repeat(513))
    expect(result.valid).toBe(false)
    expect((result as any).reason).toMatch(/invalid or expired/i)
  })

  it('rejects a string with a null byte', () => {
    const result = validateRazorpayState('valid_prefix\x00suffix')
    expect(result.valid).toBe(false)
    expect((result as any).reason).toMatch(/invalid or expired/i)
  })

  it('rejects a string with a control character', () => {
    const result = validateRazorpayState('state\x1fvalue')
    expect(result.valid).toBe(false)
    expect((result as any).reason).toMatch(/invalid or expired/i)
  })

  it('rejects SQL injection payload', () => {
    const result = validateRazorpayState("' OR '1'='1'; --")
    expect(result.valid).toBe(false)
  })

  it('rejects XSS payload', () => {
    const result = validateRazorpayState("<script>alert('xss')</script>")
    expect(result.valid).toBe(false)
  })
})

// ═════════════════════════════════════════════════════════════════════════════
// 5. validateRazorpayState — store-level checks
// ═════════════════════════════════════════════════════════════════════════════

describe('validateRazorpayState — store-level checks', () => {
  const userId = 'user-validate-store'
  const redirectUrl = 'https://app.veritasor.com/callback'

  function seedValid(token: string, overrides?: Partial<Parameters<typeof _seedOAuthState>[1]>) {
    const now = Date.now()
    _seedOAuthState(token, {
      userId,
      redirectUrl,
      createdAt: now,
      expiresAt: now + 10 * 60 * 1_000,
      ...overrides,
    })
  }

  it('returns the stored entry for a valid, unexpired token', () => {
    const token = 'a'.repeat(64)
    seedValid(token)

    const result = validateRazorpayState(token)
    expect(result.valid).toBe(true)
    if (result.valid) {
      expect(result.entry.userId).toBe(userId)
      expect(result.entry.redirectUrl).toBe(redirectUrl)
    }
  })

  it('rejects a forged token not present in the store', () => {
    const result = validateRazorpayState('forged_state_' + 'x'.repeat(50))
    expect(result.valid).toBe(false)
    expect((result as any).reason).toMatch(/invalid or expired/i)
  })

  it('rejects a UUID-like forged token', () => {
    const result = validateRazorpayState('550e8400-e29b-41d4-a716-446655440000')
    expect(result.valid).toBe(false)
  })

  it('rejects an expired token (expiresAt in the past)', () => {
    const token = 'b'.repeat(64)
    seedValid(token, { expiresAt: Date.now() - 1_000 }) // 1 second ago

    const result = validateRazorpayState(token)
    expect(result.valid).toBe(false)
    expect((result as any).reason).toMatch(/invalid or expired/i)
  })

  it('deletes the token from the store even when it is expired', () => {
    const token = 'c'.repeat(64)
    seedValid(token, { expiresAt: Date.now() - 1_000 })

    validateRazorpayState(token)

    // Second call must not find it either
    const second = validateRazorpayState(token)
    expect(second.valid).toBe(false)
  })

  // ── Single-use guarantee (replay prevention) ───────────────────────────────

  it('is single-use: second call with same token returns invalid', () => {
    const token = 'd'.repeat(64)
    seedValid(token)

    const first = validateRazorpayState(token)
    const second = validateRazorpayState(token)

    expect(first.valid).toBe(true)
    expect(second.valid).toBe(false)
    expect((second as any).reason).toMatch(/invalid or expired/i)
  })

  it('does not allow the same token to be consumed twice under concurrent calls', async () => {
    const token = 'e'.repeat(64)
    seedValid(token)

    // Simulate two concurrent validation calls
    const [r1, r2] = await Promise.all([
      Promise.resolve(validateRazorpayState(token)),
      Promise.resolve(validateRazorpayState(token)),
    ])

    const successes = [r1, r2].filter((r) => r.valid)
    expect(successes).toHaveLength(1)
  })

  // ── Cross-user isolation ───────────────────────────────────────────────────

  it('returns only the entry belonging to the token — different user tokens are isolated', () => {
    const tokenA = 'a1'.repeat(32)
    const tokenB = 'b2'.repeat(32)

    _seedOAuthState(tokenA, {
      userId: 'user-A',
      redirectUrl,
      createdAt: Date.now(),
      expiresAt: Date.now() + 10 * 60 * 1_000,
    })
    _seedOAuthState(tokenB, {
      userId: 'user-B',
      redirectUrl,
      createdAt: Date.now(),
      expiresAt: Date.now() + 10 * 60 * 1_000,
    })

    const resultA = validateRazorpayState(tokenA)
    const resultB = validateRazorpayState(tokenB)

    expect(resultA.valid).toBe(true)
    expect(resultB.valid).toBe(true)

    if (resultA.valid && resultB.valid) {
      expect(resultA.entry.userId).toBe('user-A')
      expect(resultB.entry.userId).toBe('user-B')
    }
  })

  it("cannot use another user's token to obtain their entry", () => {
    const victimToken = 'v'.repeat(64)
    _seedOAuthState(victimToken, {
      userId: 'victim-user',
      redirectUrl,
      createdAt: Date.now(),
      expiresAt: Date.now() + 10 * 60 * 1_000,
    })

    // Attacker does not know the token, tries a guess
    const attackerGuess = 'a'.repeat(64)
    const result = validateRazorpayState(attackerGuess)
    expect(result.valid).toBe(false)

    // Victim's real token is still valid (attacker's guess didn't consume it)
    const victimResult = validateRazorpayState(victimToken)
    expect(victimResult.valid).toBe(true)
    if (victimResult.valid) {
      expect(victimResult.entry.userId).toBe('victim-user')
    }
  })
})

// ═════════════════════════════════════════════════════════════════════════════
// 6. End-to-end: initiate → validate round-trip
// ═════════════════════════════════════════════════════════════════════════════

describe('Razorpay connect: initiate → validate round-trip', () => {
  const userId = 'user-e2e-roundtrip'

  beforeEach(() => setEnv())

  it('a token produced by initiateRazorpayConnect is accepted by validateRazorpayState', async () => {
    const res = await request(buildApp(userId))
      .post('/initiate')
      .send({ redirectUrl: `${ALLOWED_ORIGIN}/callback` })
      .expect(200)

    const state = res.body.state as string
    const result = validateRazorpayState(state)

    expect(result.valid).toBe(true)
    if (result.valid) {
      expect(result.entry.userId).toBe(userId)
    }
  })

  it('the token from initiation is consumed and cannot be reused', async () => {
    const res = await request(buildApp(userId))
      .post('/initiate')
      .send({ redirectUrl: `${ALLOWED_ORIGIN}/callback` })
      .expect(200)

    const state = res.body.state as string

    validateRazorpayState(state) // first use — consume

    const replay = validateRazorpayState(state) // replay
    expect(replay.valid).toBe(false)
  })
})