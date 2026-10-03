/**
 * Unit tests for src/routes/webhooks-razorpay.ts — razorpayWebhookRouter
 *
 * Strategy: mount the router on an isolated Express app and mock the two
 * external seams the router depends on:
 *   - ../utils/secret-loader  (secretLoader.get)
 *   - ../services/webhooks/razorpayHandler  (verifyRazorpaySignatureWithRotation,
 *                                            parseRazorpayEvent, handleRazorpayEvent)
 *
 * This keeps the tests fast and deterministic — no real HMAC computation,
 * no idempotency state, no DB or Redis required.
 *
 * Covered branches in the route handler:
 *   ✓ Missing / empty x-razorpay-signature header → 400 missing_signature
 *   ✓ Secret not configured (SecretNotFoundError) → 500 secret_not_configured
 *   ✓ Non-buffer / empty body → 400 invalid_payload
 *   ✓ Signature verification fails → 401 invalid_signature
 *   ✓ Signature verifies via primary key → 200 + handler result
 *   ✓ Signature verifies via secondary key (rotation) → 200 + handler result
 *   ✓ parseRazorpayEvent throws RazorpayWebhookError → correct status + code
 *   ✓ handleRazorpayEvent returns ignored → 200 ignored
 *   ✓ handleRazorpayEvent throws unexpected error → 500 Internal Server Error
 *   ✓ SecretNotFoundError for secondary key treated as absent (no throw)
 *   ✓ Non-SecretNotFoundError from secondary key lookup is re-thrown → 500
 */
import { beforeEach, describe, expect, it, vi, type MockedFunction } from 'vitest'
import request from 'supertest'
import express from 'express'

// ── mocks ─────────────────────────────────────────────────────────────────────
// Must be hoisted above the import of the module under test so that the
// module receives the mocked versions at load time.

vi.mock('../utils/secret-loader.js', () => {
  const SecretNotFoundError = class SecretNotFoundError extends Error {
    public readonly key: string
    constructor(key: string) {
      super(`Secret not found: ${key}`)
      this.name = 'SecretNotFoundError'
      this.key = key
    }
  }
  return {
    SecretNotFoundError,
    secretLoader: { get: vi.fn() },
  }
})

vi.mock('../services/webhooks/razorpayHandler.js', () => {
  const RazorpayWebhookError = class RazorpayWebhookError extends Error {
    constructor(
      public readonly code: string,
      public readonly httpStatus: number,
      message: string,
    ) {
      super(message)
      this.name = 'RazorpayWebhookError'
    }
  }
  return {
    RazorpayWebhookError,
    verifyRazorpaySignatureWithRotation: vi.fn(),
    parseRazorpayEvent: vi.fn(),
    handleRazorpayEvent: vi.fn(),
  }
})

vi.mock('../utils/logger.js', () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
}))

// ── imports (after vi.mock hoisting) ──────────────────────────────────────────
import { razorpayWebhookRouter } from './webhooks-razorpay.js'
import { secretLoader, SecretNotFoundError } from '../utils/secret-loader.js'
import {
  verifyRazorpaySignatureWithRotation,
  parseRazorpayEvent,
  handleRazorpayEvent,
  RazorpayWebhookError,
} from '../services/webhooks/razorpayHandler.js'

// ── typed mock helpers ─────────────────────────────────────────────────────────
const mockSecretGet = secretLoader.get as MockedFunction<typeof secretLoader.get>
const mockVerify = verifyRazorpaySignatureWithRotation as MockedFunction<
  typeof verifyRazorpaySignatureWithRotation
>
const mockParse = parseRazorpayEvent as MockedFunction<typeof parseRazorpayEvent>
const mockHandle = handleRazorpayEvent as MockedFunction<typeof handleRazorpayEvent>

// ── test app ───────────────────────────────────────────────────────────────────
function buildApp() {
  const app = express()
  app.use('/webhook', razorpayWebhookRouter)
  return app
}

const ROUTE = '/webhook'
const VALID_SIG = 'a'.repeat(64) // placeholder — signature logic is mocked
const VALID_BODY = Buffer.from(JSON.stringify({ id: 'evt_1', event: 'payment.captured' }))

// Minimal parsed event returned by the mock
const PARSED_EVENT = {
  id: 'evt_1',
  event: 'payment.captured',
  payload: { payment: { entity: { id: 'pay_1', order_id: 'ord_1', status: 'captured', amount: 1000, currency: 'INR' } } },
}

// ── helpers ────────────────────────────────────────────────────────────────────
function postWebhook(app: ReturnType<typeof buildApp>, overrides: {
  sig?: string | null
  body?: Buffer | string
} = {}) {
  const { sig = VALID_SIG, body = VALID_BODY } = overrides
  const req = request(app)
    .post(ROUTE)
    .set('Content-Type', 'application/json')

  if (sig !== null) req.set('x-razorpay-signature', sig)
  return req.send(body instanceof Buffer ? body.toString('utf8') : body)
}

// ── tests ──────────────────────────────────────────────────────────────────────

describe('razorpayWebhookRouter — request validation', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('returns 400 missing_signature when x-razorpay-signature header is absent', async () => {
    const app = buildApp()
    const res = await postWebhook(app, { sig: null })

    expect(res.status).toBe(400)
    expect(res.body).toMatchObject({
      code: 'missing_signature',
      error: 'Missing Razorpay signature header',
    })
    // Secret and signature verification must NOT be reached
    expect(mockSecretGet).not.toHaveBeenCalled()
    expect(mockVerify).not.toHaveBeenCalled()
  })

  it('returns 400 missing_signature when x-razorpay-signature header is an empty string', async () => {
    const app = buildApp()
    const res = await postWebhook(app, { sig: '' })

    expect(res.status).toBe(400)
    expect(res.body.code).toBe('missing_signature')
  })

  it('returns 400 invalid_payload when the body is empty (zero bytes)', async () => {
    // Secret lookup must succeed so we reach the body check
    mockSecretGet.mockReturnValueOnce('primary_secret')  // primary
    mockSecretGet.mockImplementationOnce(() => {          // secondary
      throw new (SecretNotFoundError as any)('RAZORPAY_WEBHOOK_SECRET_NEXT')
    })
    mockVerify.mockReturnValueOnce({ valid: true, keyLabel: 'primary' })

    const app = buildApp()
    const res = await postWebhook(app, { body: Buffer.alloc(0) })

    expect(res.status).toBe(400)
    expect(res.body).toMatchObject({
      code: 'invalid_payload',
      error: 'Invalid webhook payload',
    })
  })
})

describe('razorpayWebhookRouter — secret loading', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('returns 500 secret_not_configured when primary secret is missing', async () => {
    mockSecretGet.mockImplementationOnce(() => {
      throw new (SecretNotFoundError as any)('RAZORPAY_WEBHOOK_SECRET')
    })

    const app = buildApp()
    const res = await postWebhook(app)

    expect(res.status).toBe(500)
    expect(res.body).toMatchObject({
      code: 'secret_not_configured',
      error: 'Webhook secret not configured',
    })
    expect(mockVerify).not.toHaveBeenCalled()
  })

  it('propagates unexpected errors from primary secret lookup as 500', async () => {
    mockSecretGet.mockImplementationOnce(() => {
      throw new Error('KMS unavailable')
    })

    const app = buildApp()
    const res = await postWebhook(app)

    expect(res.status).toBe(500)
    expect(res.body).toEqual({ error: 'Internal Server Error' })
  })

  it('treats SecretNotFoundError for the secondary key as absent (no secondary passed to verify)', async () => {
    mockSecretGet
      .mockReturnValueOnce('primary_secret') // primary succeeds
      .mockImplementationOnce(() => {         // secondary absent
        throw new (SecretNotFoundError as any)('RAZORPAY_WEBHOOK_SECRET_NEXT')
      })
    mockVerify.mockReturnValueOnce({ valid: true, keyLabel: 'primary' })
    mockParse.mockReturnValueOnce(PARSED_EVENT as any)
    mockHandle.mockResolvedValueOnce({ status: 'ok', message: 'captured' })

    const app = buildApp()
    await postWebhook(app).expect(200)

    // verifyRazorpaySignatureWithRotation called without a secondary
    expect(mockVerify).toHaveBeenCalledWith(
      expect.any(Buffer),
      VALID_SIG,
      'primary_secret',
      undefined,
    )
  })

  it('re-throws non-SecretNotFoundError from secondary key lookup, resulting in 500', async () => {
    mockSecretGet
      .mockReturnValueOnce('primary_secret')
      .mockImplementationOnce(() => {
        throw new Error('Vault timeout fetching secondary secret')
      })

    const app = buildApp()
    const res = await postWebhook(app)

    expect(res.status).toBe(500)
    expect(res.body).toEqual({ error: 'Internal Server Error' })
  })
})

describe('razorpayWebhookRouter — signature verification', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    // Default: both secrets present
    mockSecretGet
      .mockReturnValueOnce('primary_secret')
      .mockReturnValueOnce('secondary_secret')
  })

  it('returns 401 invalid_signature when verification returns valid:false', async () => {
    mockVerify.mockReturnValueOnce({ valid: false, keyLabel: null })

    const app = buildApp()
    const res = await postWebhook(app)

    expect(res.status).toBe(401)
    expect(res.body).toMatchObject({
      code: 'invalid_signature',
      error: 'Invalid signature',
    })
    expect(mockParse).not.toHaveBeenCalled()
  })

  it('passes both primary and secondary to verifyRazorpaySignatureWithRotation', async () => {
    mockVerify.mockReturnValueOnce({ valid: true, keyLabel: 'secondary' })
    mockParse.mockReturnValueOnce(PARSED_EVENT as any)
    mockHandle.mockResolvedValueOnce({ status: 'ok', message: 'captured' })

    const app = buildApp()
    await postWebhook(app).expect(200)

    expect(mockVerify).toHaveBeenCalledWith(
      expect.any(Buffer),
      VALID_SIG,
      'primary_secret',
      'secondary_secret',
    )
  })
})

describe('razorpayWebhookRouter — event processing', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    // Successful secret loading + verification by default
    mockSecretGet
      .mockReturnValueOnce('primary_secret')
      .mockReturnValueOnce('secondary_secret')
    mockVerify.mockReturnValueOnce({ valid: true, keyLabel: 'primary' })
  })

  it('returns 200 with handler result for a valid payment.captured event', async () => {
    mockParse.mockReturnValueOnce(PARSED_EVENT as any)
    mockHandle.mockResolvedValueOnce({ status: 'ok', message: 'Payment pay_1 captured successfully' })

    const app = buildApp()
    const res = await postWebhook(app)

    expect(res.status).toBe(200)
    expect(res.body).toEqual({ status: 'ok', message: 'Payment pay_1 captured successfully' })
  })

  it('returns 200 with status:ignored for unhandled event types', async () => {
    const ignoredEvent = { ...PARSED_EVENT, event: 'refund.created' }
    mockParse.mockReturnValueOnce(ignoredEvent as any)
    mockHandle.mockResolvedValueOnce({ status: 'ignored', message: 'Unhandled event type: refund.created' })

    const app = buildApp()
    const res = await postWebhook(app)

    expect(res.status).toBe(200)
    expect(res.body).toEqual({ status: 'ignored', message: 'Unhandled event type: refund.created' })
  })

  it('returns 400 with code from RazorpayWebhookError thrown by parseRazorpayEvent', async () => {
    mockParse.mockImplementationOnce(() => {
      throw new (RazorpayWebhookError as any)('invalid_event', 400, 'Invalid event structure')
    })

    const app = buildApp()
    const res = await postWebhook(app)

    expect(res.status).toBe(400)
    expect(res.body).toMatchObject({
      code: 'invalid_event',
      error: 'Invalid event structure',
    })
  })

  it('returns 400 invalid_timestamp when parseRazorpayEvent rejects a future timestamp', async () => {
    mockParse.mockImplementationOnce(() => {
      throw new (RazorpayWebhookError as any)('invalid_timestamp', 400, 'Invalid webhook timestamp')
    })

    const app = buildApp()
    const res = await postWebhook(app)

    expect(res.status).toBe(400)
    expect(res.body).toMatchObject({ code: 'invalid_timestamp' })
  })

  it('returns 500 Internal Server Error when handleRazorpayEvent throws an unexpected error', async () => {
    mockParse.mockReturnValueOnce(PARSED_EVENT as any)
    mockHandle.mockRejectedValueOnce(new Error('database unavailable'))

    const app = buildApp()
    const res = await postWebhook(app)

    expect(res.status).toBe(500)
    expect(res.body).toEqual({ error: 'Internal Server Error' })
  })

  it('returns JSON content-type on success', async () => {
    mockParse.mockReturnValueOnce(PARSED_EVENT as any)
    mockHandle.mockResolvedValueOnce({ status: 'ok', message: 'done' })

    const app = buildApp()
    const res = await postWebhook(app)

    expect(res.headers['content-type']).toMatch(/application\/json/)
  })

  it('returns JSON content-type on error responses', async () => {
    mockVerify.mockReset()
    mockVerify.mockReturnValueOnce({ valid: false, keyLabel: null })

    // Re-apply the secret mocks that were consumed in beforeEach, since we
    // reset mockVerify after beforeEach already applied the default secrets.
    mockSecretGet.mockReset()
    mockSecretGet
      .mockReturnValueOnce('primary_secret')
      .mockReturnValueOnce('secondary_secret')
    mockVerify.mockReturnValueOnce({ valid: false, keyLabel: null })

    const app = buildApp()
    const res = await postWebhook(app)

    expect(res.status).toBe(401)
    expect(res.headers['content-type']).toMatch(/application\/json/)
  })
})

describe('razorpayWebhookRouter — raw body handling', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('passes the raw Buffer to verifyRazorpaySignatureWithRotation (not a parsed object)', async () => {
    mockSecretGet
      .mockReturnValueOnce('primary_secret')
      .mockReturnValueOnce('secondary_secret')
    mockVerify.mockReturnValueOnce({ valid: true, keyLabel: 'primary' })
    mockParse.mockReturnValueOnce(PARSED_EVENT as any)
    mockHandle.mockResolvedValueOnce({ status: 'ok', message: 'captured' })

    const app = buildApp()
    await postWebhook(app, { body: VALID_BODY }).expect(200)

    const [rawBodyArg] = mockVerify.mock.calls[0]
    expect(Buffer.isBuffer(rawBodyArg)).toBe(true)
  })

  it('passes the same Buffer to parseRazorpayEvent that was verified', async () => {
    mockSecretGet
      .mockReturnValueOnce('primary_secret')
      .mockReturnValueOnce('secondary_secret')
    mockVerify.mockReturnValueOnce({ valid: true, keyLabel: 'primary' })
    mockParse.mockReturnValueOnce(PARSED_EVENT as any)
    mockHandle.mockResolvedValueOnce({ status: 'ok', message: 'captured' })

    const app = buildApp()
    await postWebhook(app, { body: VALID_BODY }).expect(200)

    const verifyBodyArg = mockVerify.mock.calls[0][0]
    const parseBodyArg = mockParse.mock.calls[0][0]
    // Both calls receive the identical Buffer reference
    expect(verifyBodyArg).toBe(parseBodyArg)
  })
})
