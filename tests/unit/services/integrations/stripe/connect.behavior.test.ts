import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { startConnect, type ConnectResult } from '../../../../../src/services/integrations/stripe/connect'
import * as store from '../../../../../src/services/integrations/stripe/store'

/**
 * Focused behaviour coverage for `connect.ts` (issue #993).
 *
 * `startConnect` is the entry point of the Stripe OAuth flow: it mints the CSRF
 * `state` token, registers it with the one-time-use store, and builds the
 * authorization URL the browser is redirected to. `connect.test.ts` covers the
 * happy path (URL parameters, default scope, two distinct tokens). This suite
 * pins the parts of the contract that were untested:
 *
 *  * the returned `ConnectResult` shape (`redirectUrl` + `state` only) and that
 *    the `state` in the URL is byte-identical to the returned token;
 *  * the token itself: exactly 64 lower-case hex characters (32 random bytes),
 *    high-volume uniqueness, and that it is a *real* CSRF token — registered
 *    with the store, valid exactly once, and bound to a 10-minute window whose
 *    boundary is asserted on both sides;
 *  * the expiry is derived from the call-time clock, not a fixed constant;
 *  * `redirect_uri` values containing a query string survive URL encoding;
 *  * an empty `STRIPE_SCOPES` falls back to the default (the `||` guard);
 *  * the unguarded failure path: with `STRIPE_CLIENT_ID` / `STRIPE_REDIRECT_URI`
 *    unset the OAuth URL is still returned and the missing values are
 *    serialised as the literal string `"undefined"`, because the module uses
 *    non-null assertions instead of validating configuration.
 */

const TEN_MINUTES_MS = 10 * 60 * 1000

const originalEnv = { ...process.env }

function loadEnv(overrides: Record<string, string | undefined> = {}) {
  process.env = {
    ...originalEnv,
    STRIPE_CLIENT_ID: 'test_client_id',
    STRIPE_REDIRECT_URI: 'http://localhost:3000/api/integrations/stripe/callback',
    STRIPE_SCOPES: 'read_write',
  }
  for (const [key, value] of Object.entries(overrides)) {
    if (value === undefined) delete process.env[key]
    else process.env[key] = value
  }
}

const paramsOf = (result: ConnectResult) => new URL(result.redirectUrl).searchParams

beforeEach(() => {
  vi.useFakeTimers()
  loadEnv()
  store.clearStripeIntegrationStore()
})

afterEach(() => {
  vi.useRealTimers()
  process.env = { ...originalEnv }
  vi.restoreAllMocks()
})

describe('startConnect — ConnectResult shape', () => {
  it('returns exactly the redirectUrl and state fields', () => {
    const result = startConnect()

    expect(Object.keys(result).sort()).toEqual(['redirectUrl', 'state'])
    expect(typeof result.redirectUrl).toBe('string')
    expect(typeof result.state).toBe('string')
  })

  it('points at the Stripe OAuth authorize endpoint over https with no fragment', () => {
    const url = new URL(startConnect().redirectUrl)

    expect(url.protocol).toBe('https:')
    expect(url.host).toBe('connect.stripe.com')
    expect(url.pathname).toBe('/oauth/authorize')
    expect(url.hash).toBe('')
  })

  it('embeds exactly the token it returns', () => {
    const result = startConnect()

    expect(paramsOf(result).get('state')).toBe(result.state)
  })

  it('sends no unexpected OAuth parameters', () => {
    const keys = Array.from(paramsOf(startConnect()).keys()).sort()

    expect(keys).toEqual(['client_id', 'redirect_uri', 'response_type', 'scope', 'state'])
  })
})

describe('startConnect — state token', () => {
  it('is 32 random bytes rendered as 64 lower-case hex characters', () => {
    const { state } = startConnect()

    expect(state).toHaveLength(64)
    expect(state).toMatch(/^[0-9a-f]{64}$/)
  })

  it('does not repeat across many consecutive calls', () => {
    const seen = new Set<string>()

    for (let i = 0; i < 200; i += 1) {
      seen.add(startConnect().state)
    }

    expect(seen.size).toBe(200)
  })

  it('draws genuine entropy rather than a counter', () => {
    // A counter or timestamp-derived token would share long prefixes; random
    // 32-byte tokens should not.
    const tokens = Array.from({ length: 20 }, () => startConnect().state)
    const prefixes = new Set(tokens.map((t) => t.slice(0, 8)))

    expect(prefixes.size).toBe(20)
  })
})

describe('startConnect — CSRF state registration', () => {
  it('registers the token with the one-time-use store', () => {
    const { state } = startConnect()

    expect(store.consumeOAuthState(state)).toBe(true)
  })

  it('cannot replay the same state token', () => {
    const { state } = startConnect()

    expect(store.consumeOAuthState(state)).toBe(true)
    expect(store.consumeOAuthState(state)).toBe(false)
  })

  it('rejects a state token it never issued', () => {
    startConnect()

    expect(store.consumeOAuthState('0'.repeat(64))).toBe(false)
  })

  it('expires the token ten minutes after it was issued', () => {
    const issuedAt = Date.now()
    vi.setSystemTime(issuedAt)
    const { state } = startConnect()

    vi.setSystemTime(issuedAt + TEN_MINUTES_MS - 1)
    expect(store.consumeOAuthState(state)).toBe(true)
  })

  it('treats the expiry as exclusive: one millisecond late is invalid', () => {
    const issuedAt = Date.now()
    vi.setSystemTime(issuedAt)
    const { state } = startConnect()

    vi.setSystemTime(issuedAt + TEN_MINUTES_MS + 1)
    expect(store.consumeOAuthState(state)).toBe(false)
  })

  it('is still valid at the exact expiry instant', () => {
    const issuedAt = Date.now()
    vi.setSystemTime(issuedAt)
    const { state } = startConnect()

    // The store compares with a strict `<`, so the boundary instant is valid.
    vi.setSystemTime(issuedAt + TEN_MINUTES_MS)
    expect(store.consumeOAuthState(state)).toBe(true)
  })

  it('derives the window from the call-time clock, not a module constant', () => {
    const setSpy = vi.spyOn(store, 'setOAuthState')
    vi.setSystemTime(1_000_000)
    startConnect()
    vi.setSystemTime(5_000_000)
    startConnect()

    expect(setSpy).toHaveBeenNthCalledWith(1, expect.any(String), 1_000_000 + TEN_MINUTES_MS)
    expect(setSpy).toHaveBeenNthCalledWith(2, expect.any(String), 5_000_000 + TEN_MINUTES_MS)
  })
})

describe('startConnect — configuration handling', () => {
  it('percent-encodes a redirect URI that already carries a query string', () => {
    const redirectUri = 'https://app.example.com/oauth/cb?tenant=acme&env=prod'
    loadEnv({ STRIPE_REDIRECT_URI: redirectUri })

    const result = startConnect()

    expect(paramsOf(result).get('redirect_uri')).toBe(redirectUri)
    expect(result.redirectUrl).not.toContain('tenant=acme&env=prod&')
  })

  it('falls back to the default scope when STRIPE_SCOPES is empty', () => {
    loadEnv({ STRIPE_SCOPES: '' })

    expect(paramsOf(startConnect()).get('scope')).toBe('read_write')
  })

  it('passes a comma-separated scope list through untouched', () => {
    loadEnv({ STRIPE_SCOPES: 'read_write,account:read' })

    expect(paramsOf(startConnect()).get('scope')).toBe('read_write,account:read')
  })

  it('serialises a missing client id as the literal string "undefined"', () => {
    // The module uses non-null assertions (`clientId!`) instead of validating
    // configuration, so an unconfigured deployment hands Stripe a URL with
    // `client_id=undefined` rather than failing fast. Pinned so the behaviour is
    // visible; a future guard (throw or explicit error result) must update this
    // test deliberately.
    loadEnv({ STRIPE_CLIENT_ID: undefined })

    const result = startConnect()

    expect(paramsOf(result).get('client_id')).toBe('undefined')
    expect(result.state).toHaveLength(64)
  })

  it('serialises a missing redirect uri as the literal string "undefined"', () => {
    loadEnv({ STRIPE_REDIRECT_URI: undefined })

    const result = startConnect()

    expect(paramsOf(result).get('redirect_uri')).toBe('undefined')
  })

  it('still returns a usable state token when configuration is absent', () => {
    loadEnv({ STRIPE_CLIENT_ID: undefined, STRIPE_REDIRECT_URI: undefined })

    const { state } = startConnect()

    // The CSRF token is issued even on the broken-config path, which is why the
    // store — not the URL — is the authoritative check for this flow.
    expect(store.consumeOAuthState(state)).toBe(true)
  })
})
