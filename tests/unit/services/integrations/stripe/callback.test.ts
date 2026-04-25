import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import crypto from 'crypto'
import {
  handleCallback,
  verifyStripeWebhook,
  parseStripeSignatureHeader,
  computeStripeSignature,
  isValidStripeOAuthState,
  SeenEventStore,
  seenEventStore,
  STRIPE_WEBHOOK_TOLERANCE_SECONDS,
} from '../../../../../src/services/integrations/stripe/callback.js'
import * as store from '../../../../../src/services/integrations/stripe/store.js'
import * as IntegrationRepository from '../../../../../src/repositories/integration.js'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const VALID_SECRET = 'whsec_test_secret_1234567890abcdef'
const NOW_SECS = 1_700_000_000

function buildSigHeader(
  rawBody: string,
  secret: string,
  nowSecs: number,
  extra: string[] = [],
): string {
  const sig = computeStripeSignature(nowSecs, rawBody, secret)
  return ['t=' + nowSecs, 'v1=' + sig, ...extra.map((s) => 'v1=' + s)].join(',')
}

function makePayload(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    id: 'evt_' + crypto.randomBytes(8).toString('hex'),
    type: 'account.updated',
    created: NOW_SECS,
    data: { object: {} },
    ...overrides,
  })
}

// ---------------------------------------------------------------------------
// SeenEventStore
// ---------------------------------------------------------------------------

describe('SeenEventStore', () => {
  let evtStore: SeenEventStore

  beforeEach(() => {
    evtStore = new SeenEventStore(STRIPE_WEBHOOK_TOLERANCE_SECONDS * 2 * 1000)
  })

  it('returns false for a new event ID and marks it as seen', () => {
    expect(evtStore.checkAndMark('evt_new')).toBe(false)
    expect(evtStore.size()).toBe(1)
  })

  it('returns true for a duplicate event ID', () => {
    evtStore.checkAndMark('evt_dup')
    expect(evtStore.checkAndMark('evt_dup')).toBe(true)
  })

  it('different event IDs are tracked independently', () => {
    expect(evtStore.checkAndMark('evt_a')).toBe(false)
    expect(evtStore.checkAndMark('evt_b')).toBe(false)
    expect(evtStore.size()).toBe(2)
  })

  it('evicts entries older than TTL', () => {
    vi.useFakeTimers()
    const shortStore = new SeenEventStore(100)
    shortStore.checkAndMark('evt_old')
    expect(shortStore.size()).toBe(1)
    vi.advanceTimersByTime(200)
    shortStore.checkAndMark('evt_trigger_evict')
    expect(shortStore.size()).toBe(1)
    vi.useRealTimers()
  })

  it('does not evict entries within TTL', () => {
    vi.useFakeTimers()
    const shortStore = new SeenEventStore(1000)
    shortStore.checkAndMark('evt_fresh')
    vi.advanceTimersByTime(500)
    shortStore.checkAndMark('evt_trigger')
    expect(shortStore.size()).toBe(2)
    vi.useRealTimers()
  })

  it('clear() empties the store', () => {
    evtStore.checkAndMark('evt_1')
    evtStore.checkAndMark('evt_2')
    evtStore.clear()
    expect(evtStore.size()).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// isValidStripeOAuthState
// ---------------------------------------------------------------------------

describe('isValidStripeOAuthState', () => {
  it('accepts a valid 64-char lowercase hex string', () => {
    const state = crypto.randomBytes(32).toString('hex')
    expect(isValidStripeOAuthState(state)).toBe(true)
  })

  it('rejects a string that is too short', () => {
    expect(isValidStripeOAuthState('abc123')).toBe(false)
  })

  it('rejects a string that is too long', () => {
    expect(isValidStripeOAuthState('a'.repeat(65))).toBe(false)
  })

  it('rejects uppercase hex characters', () => {
    const upper = crypto.randomBytes(32).toString('hex').toUpperCase()
    expect(isValidStripeOAuthState(upper)).toBe(false)
  })

  it('rejects non-hex characters', () => {
    const bad = 'g'.repeat(64)
    expect(isValidStripeOAuthState(bad)).toBe(false)
  })

  it('rejects an empty string', () => {
    expect(isValidStripeOAuthState('')).toBe(false)
  })

  it('rejects strings with whitespace padding', () => {
    const state = ' ' + crypto.randomBytes(31).toString('hex') + ' '
    expect(isValidStripeOAuthState(state)).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// parseStripeSignatureHeader
// ---------------------------------------------------------------------------

describe('parseStripeSignatureHeader', () => {
  it('parses a well-formed header', () => {
    const sig = 'a'.repeat(64)
    const result = parseStripeSignatureHeader('t=1700000000,v1=' + sig)
    expect(result).not.toBeNull()
    expect(result!.timestamp).toBe(1700000000)
    expect(result!.v1Signatures).toEqual([sig])
  })

  it('parses a header with multiple v1 signatures', () => {
    const sig1 = 'a'.repeat(64)
    const sig2 = 'b'.repeat(64)
    const result = parseStripeSignatureHeader('t=1700000000,v1=' + sig1 + ',v1=' + sig2)
    expect(result!.v1Signatures).toHaveLength(2)
    expect(result!.v1Signatures).toContain(sig1)
    expect(result!.v1Signatures).toContain(sig2)
  })

  it('returns null for undefined input', () => {
    expect(parseStripeSignatureHeader(undefined)).toBeNull()
  })

  it('returns null for an empty string', () => {
    expect(parseStripeSignatureHeader('')).toBeNull()
  })

  it('returns null when timestamp is missing', () => {
    expect(parseStripeSignatureHeader('v1=' + 'a'.repeat(64))).toBeNull()
  })

  it('returns null when v1 signature is missing', () => {
    expect(parseStripeSignatureHeader('t=1700000000')).toBeNull()
  })

  it('returns null for a non-integer timestamp', () => {
    expect(parseStripeSignatureHeader('t=abc,v1=' + 'a'.repeat(64))).toBeNull()
  })

  it('returns null for a zero timestamp', () => {
    expect(parseStripeSignatureHeader('t=0,v1=' + 'a'.repeat(64))).toBeNull()
  })

  it('returns null for a negative timestamp', () => {
    expect(parseStripeSignatureHeader('t=-1,v1=' + 'a'.repeat(64))).toBeNull()
  })

  it('silently ignores v1 signatures that are not 64 hex chars', () => {
    const result = parseStripeSignatureHeader('t=1700000000,v1=tooshort')
    expect(result).toBeNull()
  })

  it('ignores unknown keys without failing', () => {
    const sig = 'a'.repeat(64)
    const result = parseStripeSignatureHeader('t=1700000000,v0=ignored,v1=' + sig)
    expect(result).not.toBeNull()
    expect(result!.v1Signatures).toEqual([sig])
  })
})

// ---------------------------------------------------------------------------
// computeStripeSignature
// ---------------------------------------------------------------------------

describe('computeStripeSignature', () => {
  it('produces a 64-char lowercase hex string', () => {
    const sig = computeStripeSignature(NOW_SECS, 'body', VALID_SECRET)
    expect(sig).toMatch(/^[a-f0-9]{64}$/)
  })

  it('is deterministic for the same inputs', () => {
    const a = computeStripeSignature(NOW_SECS, 'body', VALID_SECRET)
    const b = computeStripeSignature(NOW_SECS, 'body', VALID_SECRET)
    expect(a).toBe(b)
  })

  it('changes when the timestamp changes', () => {
    const a = computeStripeSignature(NOW_SECS, 'body', VALID_SECRET)
    const b = computeStripeSignature(NOW_SECS + 1, 'body', VALID_SECRET)
    expect(a).not.toBe(b)
  })

  it('changes when the body changes', () => {
    const a = computeStripeSignature(NOW_SECS, 'body_a', VALID_SECRET)
    const b = computeStripeSignature(NOW_SECS, 'body_b', VALID_SECRET)
    expect(a).not.toBe(b)
  })

  it('changes when the secret changes', () => {
    const a = computeStripeSignature(NOW_SECS, 'body', VALID_SECRET)
    const b = computeStripeSignature(NOW_SECS, 'body', 'different_secret')
    expect(a).not.toBe(b)
  })
})

// ---------------------------------------------------------------------------
// verifyStripeWebhook  replay resistance, deduplication, signature checks
// ---------------------------------------------------------------------------

describe('verifyStripeWebhook', () => {
  let freshStore: SeenEventStore

  beforeEach(() => {
    freshStore = new SeenEventStore()
  })

  //  Happy path 
  it('accepts a valid webhook event', () => {
    const body = makePayload()
    const sig = buildSigHeader(body, VALID_SECRET, NOW_SECS)
    const result = verifyStripeWebhook(body, sig, VALID_SECRET, NOW_SECS, freshStore)
    expect(result.success).toBe(true)
    expect(result.event).toBeDefined()
    expect(result.event!.type).toBe('account.updated')
    expect(result.reason).toBeUndefined()
  })

  it('accepts an event at the exact tolerance boundary (age = tolerance)', () => {
    const body = makePayload()
    const eventTs = NOW_SECS - STRIPE_WEBHOOK_TOLERANCE_SECONDS
    const sig = buildSigHeader(body, VALID_SECRET, eventTs)
    const result = verifyStripeWebhook(body, sig, VALID_SECRET, NOW_SECS, freshStore)
    expect(result.success).toBe(true)
  })

  it('accepts an event with multiple v1 signatures when one matches', () => {
    const body = makePayload()
    const sig = buildSigHeader(body, VALID_SECRET, NOW_SECS, ['f'.repeat(64)])
    const result = verifyStripeWebhook(body, sig, VALID_SECRET, NOW_SECS, freshStore)
    expect(result.success).toBe(true)
  })

  //  Missing / malformed signature 
  it('rejects when Stripe-Signature header is absent', () => {
    const body = makePayload()
    const result = verifyStripeWebhook(body, undefined, VALID_SECRET, NOW_SECS, freshStore)
    expect(result.success).toBe(false)
    expect(result.reason).toBe('missing_signature')
  })

  it('rejects when Stripe-Signature header is an empty string', () => {
    const body = makePayload()
    const result = verifyStripeWebhook(body, '', VALID_SECRET, NOW_SECS, freshStore)
    expect(result.success).toBe(false)
    expect(result.reason).toBe('missing_signature')
  })

  it('rejects a header with no v1 component', () => {
    const body = makePayload()
    const result = verifyStripeWebhook(body, 't=' + NOW_SECS, VALID_SECRET, NOW_SECS, freshStore)
    expect(result.success).toBe(false)
    expect(result.reason).toBe('missing_signature')
  })

  it('rejects a header with no timestamp component', () => {
    const body = makePayload()
    const result = verifyStripeWebhook(body, 'v1=' + 'a'.repeat(64), VALID_SECRET, NOW_SECS, freshStore)
    expect(result.success).toBe(false)
    expect(result.reason).toBe('missing_signature')
  })

  //  Wrong signing secret 
  it('rejects when signed with a different secret', () => {
    const body = makePayload()
    const sig = buildSigHeader(body, 'wrong_secret', NOW_SECS)
    const result = verifyStripeWebhook(body, sig, VALID_SECRET, NOW_SECS, freshStore)
    expect(result.success).toBe(false)
    expect(result.reason).toBe('signature_mismatch')
  })

  it('rejects when the body has been tampered after signing', () => {
    const body = makePayload()
    const sig = buildSigHeader(body, VALID_SECRET, NOW_SECS)
    const tamperedBody = body + ' '
    const result = verifyStripeWebhook(tamperedBody, sig, VALID_SECRET, NOW_SECS, freshStore)
    expect(result.success).toBe(false)
    expect(result.reason).toBe('signature_mismatch')
  })

  it('rejects a signature of all-zeros (forged)', () => {
    const body = makePayload()
    const forgedSig = 't=' + NOW_SECS + ',v1=' + '0'.repeat(64)
    const result = verifyStripeWebhook(body, forgedSig, VALID_SECRET, NOW_SECS, freshStore)
    expect(result.success).toBe(false)
    expect(result.reason).toBe('signature_mismatch')
  })

  //  Timestamp tolerance  replay resistance 
  it('rejects an event older than the tolerance window (replay)', () => {
    const body = makePayload()
    const staleTs = NOW_SECS - STRIPE_WEBHOOK_TOLERANCE_SECONDS - 1
    const sig = buildSigHeader(body, VALID_SECRET, staleTs)
    const result = verifyStripeWebhook(body, sig, VALID_SECRET, NOW_SECS, freshStore)
    expect(result.success).toBe(false)
    expect(result.reason).toBe('timestamp_too_old')
  })

  it('rejects an event 1 hour in the past (obvious replay)', () => {
    const body = makePayload()
    const oldTs = NOW_SECS - 3600
    const sig = buildSigHeader(body, VALID_SECRET, oldTs)
    const result = verifyStripeWebhook(body, sig, VALID_SECRET, NOW_SECS, freshStore)
    expect(result.success).toBe(false)
    expect(result.reason).toBe('timestamp_too_old')
  })

  it('rejects an event with a timestamp far in the future (clock skew guard)', () => {
    const body = makePayload()
    const futureTs = NOW_SECS + STRIPE_WEBHOOK_TOLERANCE_SECONDS + 1
    const sig = buildSigHeader(body, VALID_SECRET, futureTs)
    const result = verifyStripeWebhook(body, sig, VALID_SECRET, NOW_SECS, freshStore)
    expect(result.success).toBe(false)
    expect(result.reason).toBe('timestamp_in_future')
  })

  it('accepts an event 1 second before the tolerance boundary', () => {
    const body = makePayload()
    const ts = NOW_SECS - STRIPE_WEBHOOK_TOLERANCE_SECONDS + 1
    const sig = buildSigHeader(body, VALID_SECRET, ts)
    const result = verifyStripeWebhook(body, sig, VALID_SECRET, NOW_SECS, freshStore)
    expect(result.success).toBe(true)
  })

  //  Duplicate event IDs 
  it('rejects a duplicate event ID on second delivery', () => {
    const body = makePayload({ id: 'evt_dedup_test' })
    const sig = buildSigHeader(body, VALID_SECRET, NOW_SECS)
    const first = verifyStripeWebhook(body, sig, VALID_SECRET, NOW_SECS, freshStore)
    expect(first.success).toBe(true)
    const second = verifyStripeWebhook(body, sig, VALID_SECRET, NOW_SECS, freshStore)
    expect(second.success).toBe(false)
    expect(second.reason).toBe('duplicate_event')
  })

  it('accepts the same event type with a different event ID (not a duplicate)', () => {
    const body1 = makePayload({ id: 'evt_unique_1' })
    const body2 = makePayload({ id: 'evt_unique_2' })
    const sig1 = buildSigHeader(body1, VALID_SECRET, NOW_SECS)
    const sig2 = buildSigHeader(body2, VALID_SECRET, NOW_SECS)
    expect(verifyStripeWebhook(body1, sig1, VALID_SECRET, NOW_SECS, freshStore).success).toBe(true)
    expect(verifyStripeWebhook(body2, sig2, VALID_SECRET, NOW_SECS, freshStore).success).toBe(true)
  })

  it('rejects a duplicate even when delivered with a fresh timestamp', () => {
    const body = makePayload({ id: 'evt_replay_fresh_ts' })
    const sig1 = buildSigHeader(body, VALID_SECRET, NOW_SECS)
    verifyStripeWebhook(body, sig1, VALID_SECRET, NOW_SECS, freshStore)
    // Attacker re-signs with a fresh timestamp but same event body/id
    const sig2 = buildSigHeader(body, VALID_SECRET, NOW_SECS + 10)
    const result = verifyStripeWebhook(body, sig2, VALID_SECRET, NOW_SECS + 10, freshStore)
    expect(result.success).toBe(false)
    expect(result.reason).toBe('duplicate_event')
  })

  //  Out-of-order delivery 
  it('accepts out-of-order events as long as they are within the tolerance window', () => {
    const body1 = makePayload({ id: 'evt_order_1', created: NOW_SECS - 10 })
    const body2 = makePayload({ id: 'evt_order_2', created: NOW_SECS })
    const sig2 = buildSigHeader(body2, VALID_SECRET, NOW_SECS)
    const sig1 = buildSigHeader(body1, VALID_SECRET, NOW_SECS - 10)
    // Deliver event 2 first, then event 1
    expect(verifyStripeWebhook(body2, sig2, VALID_SECRET, NOW_SECS, freshStore).success).toBe(true)
    expect(verifyStripeWebhook(body1, sig1, VALID_SECRET, NOW_SECS, freshStore).success).toBe(true)
  })

  //  Invalid payload 
  it('rejects a payload that is not valid JSON', () => {
    const body = 'not-json'
    const sig = buildSigHeader(body, VALID_SECRET, NOW_SECS)
    const result = verifyStripeWebhook(body, sig, VALID_SECRET, NOW_SECS, freshStore)
    expect(result.success).toBe(false)
    expect(result.reason).toBe('invalid_payload')
  })

  it('rejects a payload missing the event id field', () => {
    const body = JSON.stringify({ type: 'account.updated', created: NOW_SECS, data: { object: {} } })
    const sig = buildSigHeader(body, VALID_SECRET, NOW_SECS)
    const result = verifyStripeWebhook(body, sig, VALID_SECRET, NOW_SECS, freshStore)
    expect(result.success).toBe(false)
    expect(result.reason).toBe('invalid_payload')
  })

  it('rejects a payload missing the event type field', () => {
    const body = JSON.stringify({ id: 'evt_no_type', created: NOW_SECS, data: { object: {} } })
    const sig = buildSigHeader(body, VALID_SECRET, NOW_SECS)
    const result = verifyStripeWebhook(body, sig, VALID_SECRET, NOW_SECS, freshStore)
    expect(result.success).toBe(false)
    expect(result.reason).toBe('invalid_payload')
  })

  it('rejects an empty JSON object payload', () => {
    const body = '{}'
    const sig = buildSigHeader(body, VALID_SECRET, NOW_SECS)
    const result = verifyStripeWebhook(body, sig, VALID_SECRET, NOW_SECS, freshStore)
    expect(result.success).toBe(false)
    expect(result.reason).toBe('invalid_payload')
  })

  //  Security: no secret or payload leakage in rejection results 
  it('does not include the signing secret in any rejection result', () => {
    const body = makePayload()
    const sig = buildSigHeader(body, 'wrong_secret', NOW_SECS)
    const result = verifyStripeWebhook(body, sig, VALID_SECRET, NOW_SECS, freshStore)
    expect(JSON.stringify(result)).not.toContain(VALID_SECRET)
    expect(JSON.stringify(result)).not.toContain('wrong_secret')
  })

  it('does not echo the raw body in any rejection result', () => {
    const body = makePayload({ sensitiveField: 'secret_value_xyz' })
    const result = verifyStripeWebhook(body, undefined, VALID_SECRET, NOW_SECS, freshStore)
    expect(JSON.stringify(result)).not.toContain('secret_value_xyz')
  })

})

// ---------------------------------------------------------------------------
// handleCallback  OAuth flow
// ---------------------------------------------------------------------------

describe('handleCallback', () => {
  const VALID_STATE = 'a'.repeat(64)
  const USER_ID = 'user_test_123'
  const STRIPE_ACCOUNT_ID = 'acct_test_abc'

  const originalEnv = { ...process.env }

  beforeEach(() => {
    process.env.STRIPE_CLIENT_ID = 'ca_test_client'
    process.env.STRIPE_CLIENT_SECRET = 'sk_test_secret'
    vi.spyOn(store, 'consumeOAuthState').mockReturnValue(true)
    vi.spyOn(IntegrationRepository, 'listByUserId').mockResolvedValue([])
    vi.spyOn(IntegrationRepository, 'create').mockResolvedValue({
      id: 'int_1', userId: USER_ID, provider: 'stripe',
      externalId: STRIPE_ACCOUNT_ID, token: {}, metadata: {},
      createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
    })
    vi.spyOn(IntegrationRepository, 'update').mockResolvedValue(null)
  })

  afterEach(() => {
    vi.restoreAllMocks()
    process.env = { ...originalEnv }
  })

  function mockFetchSuccess(stripeUserId = STRIPE_ACCOUNT_ID) {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        access_token: 'sk_test_access',
        refresh_token: 'rt_test_refresh',
        stripe_user_id: stripeUserId,
        scope: 'read_write',
        token_type: 'bearer',
      }),
    }))
  }

  //  Missing / invalid params 
  it('returns error when code is missing', async () => {
    const result = await handleCallback({ code: '', state: VALID_STATE }, USER_ID)
    expect(result.success).toBe(false)
    expect(result.error).toMatch(/missing/i)
  })

  it('returns error when state is missing', async () => {
    const result = await handleCallback({ code: 'auth_code', state: '' }, USER_ID)
    expect(result.success).toBe(false)
    expect(result.error).toMatch(/missing/i)
  })

  it('returns error for a malformed state token (too short)', async () => {
    const result = await handleCallback({ code: 'auth_code', state: 'abc' }, USER_ID)
    expect(result.success).toBe(false)
    expect(result.error).toMatch(/invalid oauth state format/i)
  })

  it('returns error for a state token with uppercase hex', async () => {
    const badState = 'A'.repeat(64)
    const result = await handleCallback({ code: 'auth_code', state: badState }, USER_ID)
    expect(result.success).toBe(false)
    expect(result.error).toMatch(/invalid oauth state format/i)
  })

  it('returns error for a state token with non-hex characters', async () => {
    const badState = 'z'.repeat(64)
    const result = await handleCallback({ code: 'auth_code', state: badState }, USER_ID)
    expect(result.success).toBe(false)
    expect(result.error).toMatch(/invalid oauth state format/i)
  })

  //  CSRF / state validation 
  it('returns error when state token is not in the store (CSRF)', async () => {
    vi.spyOn(store, 'consumeOAuthState').mockReturnValue(false)
    const result = await handleCallback({ code: 'auth_code', state: VALID_STATE }, USER_ID)
    expect(result.success).toBe(false)
    expect(result.error).toMatch(/invalid or expired state/i)
  })

  it('returns error when state token has expired', async () => {
    vi.spyOn(store, 'consumeOAuthState').mockReturnValue(false)
    const result = await handleCallback({ code: 'auth_code', state: VALID_STATE }, USER_ID)
    expect(result.success).toBe(false)
    expect(result.error).toMatch(/invalid or expired state/i)
  })

  it('consumes the state token exactly once (one-time use)', async () => {
    const consumeSpy = vi.spyOn(store, 'consumeOAuthState').mockReturnValue(false)
    await handleCallback({ code: 'auth_code', state: VALID_STATE }, USER_ID)
    expect(consumeSpy).toHaveBeenCalledTimes(1)
    expect(consumeSpy).toHaveBeenCalledWith(VALID_STATE)
  })

  //  Network / Stripe API errors 
  it('returns network error when fetch throws', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('ECONNREFUSED')))
    const result = await handleCallback({ code: 'auth_code', state: VALID_STATE }, USER_ID)
    expect(result.success).toBe(false)
    expect(result.error).toBe('Failed to reach Stripe API')
  })

  it('returns token exchange error when Stripe returns non-2xx', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, status: 401, json: async () => ({}) }))
    const result = await handleCallback({ code: 'auth_code', state: VALID_STATE }, USER_ID)
    expect(result.success).toBe(false)
    expect(result.error).toMatch(/token exchange failed/i)
  })

  it('returns error when access_token is absent from Stripe response', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true, status: 200,
      json: async () => ({ stripe_user_id: STRIPE_ACCOUNT_ID }),
    }))
    const result = await handleCallback({ code: 'auth_code', state: VALID_STATE }, USER_ID)
    expect(result.success).toBe(false)
    expect(result.error).toMatch(/no access token/i)
  })

  it('returns error when stripe_user_id is absent from Stripe response', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true, status: 200,
      json: async () => ({ access_token: 'sk_test_access' }),
    }))
    const result = await handleCallback({ code: 'auth_code', state: VALID_STATE }, USER_ID)
    expect(result.success).toBe(false)
    expect(result.error).toMatch(/no stripe account id/i)
  })

  //  Happy path 
  it('creates a new integration on first connect', async () => {
    mockFetchSuccess()
    const createSpy = vi.spyOn(IntegrationRepository, 'create')
    const result = await handleCallback({ code: 'auth_code', state: VALID_STATE }, USER_ID)
    expect(result.success).toBe(true)
    expect(result.stripeAccountId).toBe(STRIPE_ACCOUNT_ID)
    expect(createSpy).toHaveBeenCalledTimes(1)
    expect(createSpy).toHaveBeenCalledWith(expect.objectContaining({
      userId: USER_ID,
      provider: 'stripe',
      externalId: STRIPE_ACCOUNT_ID,
    }))
  })

  it('updates an existing integration on reconnect (idempotent upsert)', async () => {
    const existingIntegration = {
      id: 'int_existing', userId: USER_ID, provider: 'stripe',
      externalId: STRIPE_ACCOUNT_ID, token: { accessToken: 'old_token' }, metadata: {},
      createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
    }
    vi.spyOn(IntegrationRepository, 'listByUserId').mockResolvedValue([existingIntegration])
    const updateSpy = vi.spyOn(IntegrationRepository, 'update').mockResolvedValue(existingIntegration)
    const createSpy = vi.spyOn(IntegrationRepository, 'create')
    mockFetchSuccess()
    const result = await handleCallback({ code: 'auth_code', state: VALID_STATE }, USER_ID)
    expect(result.success).toBe(true)
    expect(updateSpy).toHaveBeenCalledTimes(1)
    expect(updateSpy).toHaveBeenCalledWith(USER_ID, 'int_existing', expect.objectContaining({
      token: expect.objectContaining({ accessToken: 'sk_test_access' }),
    }))
    expect(createSpy).not.toHaveBeenCalled()
  })

  //  Security: no token leakage 
  it('does not include access_token in the success result', async () => {
    mockFetchSuccess()
    const result = await handleCallback({ code: 'auth_code', state: VALID_STATE }, USER_ID)
    expect(JSON.stringify(result)).not.toContain('sk_test_access')
    expect(JSON.stringify(result)).not.toContain('rt_test_refresh')
  })

  it('does not include STRIPE_CLIENT_SECRET in any error result', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('fail')))
    const result = await handleCallback({ code: 'auth_code', state: VALID_STATE }, USER_ID)
    expect(JSON.stringify(result)).not.toContain('sk_test_secret')
  })

  it('trims whitespace from code and state before processing', async () => {
    mockFetchSuccess()
    const consumeSpy = vi.spyOn(store, 'consumeOAuthState').mockReturnValue(true)
    await handleCallback({ code: '  auth_code  ', state: '  ' + VALID_STATE + '  ' }, USER_ID)
    expect(consumeSpy).toHaveBeenCalledWith(VALID_STATE)
  })

})
