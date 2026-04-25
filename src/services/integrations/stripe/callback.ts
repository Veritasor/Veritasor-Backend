/**
 * Stripe OAuth callback service
 *
 * Handles the OAuth redirect from Stripe:
 *   1. Validates the `state` token shape (early rejection of malformed input)
 *   2. Consumes the one-time-use state token (CSRF protection)
 *   3. Exchanges the authorization `code` for an access token
 *   4. Idempotently persists the Stripe integration for the user
 *
 * Stripe webhook event handler:
 *   1. Verifies the `Stripe-Signature` header using HMAC-SHA256 (replay resistance)
 *   2. Enforces a timestamp tolerance window to reject stale/replayed events
 *   3. Deduplicates events by `id` using an in-process seen-event store
 *   4. Dispatches to per-event-type handlers with structured logging
 *
 * Security properties:
 *   - Constant-time signature comparison (prevents timing attacks)
 *   - Timestamp tolerance window (default 5 min) rejects replayed events
 *   - In-process event-ID deduplication rejects duplicate deliveries
 *   - No secrets or raw payloads are reflected in error responses
 *   - All security-relevant decisions are emitted as structured log entries
 */

import crypto from 'crypto'
import { consumeOAuthState } from './store.js'
import * as IntegrationRepository from '../../../repositories/integration.js'
import { logger } from '../../../utils/logger.js'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const STRIPE_STATE_LENGTH = 64
const STRIPE_STATE_PATTERN = /^[a-f0-9]+$/

/**
 * Maximum age (in seconds) of a Stripe webhook event timestamp before it is
 * rejected as potentially replayed.  Stripe's own SDK uses 300 s (5 min).
 */
export const STRIPE_WEBHOOK_TOLERANCE_SECONDS = 300

// ---------------------------------------------------------------------------
// OAuth callback types
// ---------------------------------------------------------------------------

export interface CallbackParams {
  code: string
  state: string
}

export interface CallbackResult {
  success: boolean
  stripeAccountId?: string
  error?: string
}

// ---------------------------------------------------------------------------
// Webhook types
// ---------------------------------------------------------------------------

export interface StripeWebhookEvent {
  id: string
  type: string
  created: number
  data: {
    object: Record<string, unknown>
  }
  [key: string]: unknown
}

export interface WebhookVerifyResult {
  success: boolean
  event?: StripeWebhookEvent
  /** Machine-readable rejection reason (never echoed to callers verbatim) */
  reason?: WebhookRejectionReason
}

export type WebhookRejectionReason =
  | 'missing_signature'
  | 'invalid_signature_format'
  | 'timestamp_too_old'
  | 'timestamp_in_future'
  | 'signature_mismatch'
  | 'duplicate_event'
  | 'invalid_payload'

// ---------------------------------------------------------------------------
// In-process event deduplication store
// ---------------------------------------------------------------------------

/**
 * Bounded in-process store for seen Stripe event IDs.
 *
 * Design notes:
 *   - Keyed by event ID; value is the Unix timestamp (ms) when the event was
 *     first accepted so we can expire old entries.
 *   - TTL is set to 2× the webhook tolerance window so that any event that
 *     could still arrive within the tolerance window is guaranteed to be in
 *     the store.
 *   - Cleanup runs on every insert to keep memory bounded without a timer.
 *   - For multi-instance deployments, replace this with a shared Redis SET
 *     with an appropriate TTL.
 *
 * @internal
 */
export class SeenEventStore {
  private readonly store = new Map<string, number>()
  /** How long (ms) to keep an event ID in the store */
  private readonly ttlMs: number

  constructor(ttlMs = STRIPE_WEBHOOK_TOLERANCE_SECONDS * 2 * 1000) {
    this.ttlMs = ttlMs
  }

  /**
   * Returns `true` if the event ID has already been seen (duplicate).
   * Registers the event ID if it is new.
   */
  checkAndMark(eventId: string): boolean {
    this._evict()
    if (this.store.has(eventId)) {
      return true // duplicate
    }
    this.store.set(eventId, Date.now())
    return false
  }

  /** Remove entries older than TTL */
  private _evict(): void {
    const cutoff = Date.now() - this.ttlMs
    for (const [id, seenAt] of this.store) {
      if (seenAt < cutoff) {
        this.store.delete(id)
      }
    }
  }

  /** Exposed for testing only */
  clear(): void {
    this.store.clear()
  }

  /** Exposed for testing only */
  size(): number {
    return this.store.size
  }
}

/** Module-level singleton; replace with a Redis-backed store in production. */
export const seenEventStore = new SeenEventStore()

// ---------------------------------------------------------------------------
// OAuth state validation
// ---------------------------------------------------------------------------

/**
 * Validates the Stripe OAuth `state` token shape before store lookup.
 *
 * State must be a 64-char lowercase hex string (32 random bytes encoded in
 * hex).  This rejects malformed input early and avoids reflecting
 * attacker-controlled values into the store lookup path.
 */
export function isValidStripeOAuthState(state: string): boolean {
  if (typeof state !== 'string') return false
  if (state.length !== STRIPE_STATE_LENGTH) return false
  return STRIPE_STATE_PATTERN.test(state)
}

// ---------------------------------------------------------------------------
// OAuth callback handler
// ---------------------------------------------------------------------------

/**
 * Handle Stripe OAuth callback.
 *
 * Validates state, exchanges authorization code for tokens, and creates or
 * updates the integration record idempotently.
 */
export async function handleCallback(
  params: CallbackParams,
  userId: string,
): Promise<CallbackResult> {
  const code = params.code?.trim()
  const state = params.state?.trim()

  if (!code || !state) {
    return { success: false, error: 'Missing code, or state' }
  }

  // Security guard: reject malformed OAuth state tokens before consuming store entries.
  if (!isValidStripeOAuthState(state)) {
    logger.warn(
      JSON.stringify({
        event: 'stripe_oauth_state_invalid_format',
        userId,
      }),
    )
    return { success: false, error: 'Invalid OAuth state format' }
  }

  // Consume and validate state token (one-time use — CSRF protection)
  const isValidState = consumeOAuthState(state)
  if (!isValidState) {
    logger.warn(
      JSON.stringify({
        event: 'stripe_oauth_state_invalid_or_expired',
        userId,
      }),
    )
    return { success: false, error: 'Invalid or expired state' }
  }

  // Exchange authorization code for tokens
  const clientId = process.env.STRIPE_CLIENT_ID
  const clientSecret = process.env.STRIPE_CLIENT_SECRET

  const tokenRequestBody = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    client_id: clientId!,
    client_secret: clientSecret!,
  })

  let response: Response
  try {
    response = await fetch('https://connect.stripe.com/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: tokenRequestBody.toString(),
    })
  } catch {
    logger.error(
      JSON.stringify({
        event: 'stripe_oauth_token_exchange_network_error',
        userId,
      }),
    )
    return { success: false, error: 'Failed to reach Stripe API' }
  }

  if (!response.ok) {
    logger.warn(
      JSON.stringify({
        event: 'stripe_oauth_token_exchange_failed',
        userId,
        httpStatus: response.status,
      }),
    )
    return { success: false, error: 'Token exchange failed' }
  }

  const tokenData = await response.json()

  if (!tokenData.access_token) {
    return { success: false, error: 'No access token in response' }
  }

  const stripeUserId: unknown = tokenData.stripe_user_id
  if (!stripeUserId || typeof stripeUserId !== 'string') {
    return { success: false, error: 'No Stripe account ID in response' }
  }

  const integrationData = {
    userId,
    provider: 'stripe',
    externalId: stripeUserId,
    token: {
      accessToken: tokenData.access_token as string,
      refreshToken: tokenData.refresh_token as string | undefined,
      scope: tokenData.scope as string | undefined,
      tokenType: tokenData.token_type as string | undefined,
    },
    metadata: {},
  }

  const existingIntegrations = await IntegrationRepository.listByUserId(userId)
  const existingStripeIntegration = existingIntegrations.find(
    (i) => i.provider === 'stripe' && i.externalId === stripeUserId,
  )

  if (existingStripeIntegration) {
    await IntegrationRepository.update(userId, existingStripeIntegration.id, {
      token: integrationData.token,
      metadata: integrationData.metadata,
    })
    logger.info(
      JSON.stringify({
        event: 'stripe_oauth_integration_updated',
        userId,
        stripeAccountId: stripeUserId,
      }),
    )
  } else {
    await IntegrationRepository.create(integrationData)
    logger.info(
      JSON.stringify({
        event: 'stripe_oauth_integration_created',
        userId,
        stripeAccountId: stripeUserId,
      }),
    )
  }

  return { success: true, stripeAccountId: stripeUserId }
}

// ---------------------------------------------------------------------------
// Webhook signature verification
// ---------------------------------------------------------------------------

/**
 * Parse and validate the `Stripe-Signature` header.
 *
 * The header has the form:
 *   `t=<unix_timestamp>,v1=<hmac_hex>[,v1=<hmac_hex>...]`
 *
 * Returns `null` if the header is absent, empty, or structurally invalid.
 */
export function parseStripeSignatureHeader(
  header: string | undefined,
): { timestamp: number; v1Signatures: string[] } | null {
  if (!header || typeof header !== 'string' || header.trim() === '') {
    return null
  }

  let timestamp: number | undefined
  const v1Signatures: string[] = []

  for (const part of header.split(',')) {
    const eqIdx = part.indexOf('=')
    if (eqIdx === -1) continue
    const key = part.slice(0, eqIdx).trim()
    const value = part.slice(eqIdx + 1).trim()

    if (key === 't') {
      const parsed = Number(value)
      if (!Number.isInteger(parsed) || parsed <= 0) return null
      timestamp = parsed
    } else if (key === 'v1') {
      if (/^[a-f0-9]{64}$/.test(value)) {
        v1Signatures.push(value)
      }
    }
  }

  if (timestamp === undefined || v1Signatures.length === 0) {
    return null
  }

  return { timestamp, v1Signatures }
}

/**
 * Compute the expected HMAC-SHA256 signature for a Stripe webhook payload.
 *
 * Stripe's signed payload format: `<timestamp>.<rawBody>`
 */
export function computeStripeSignature(
  timestamp: number,
  rawBody: string,
  secret: string,
): string {
  const signedPayload = `${timestamp}.${rawBody}`
  return crypto.createHmac('sha256', secret).update(signedPayload, 'utf8').digest('hex')
}

/**
 * Verify a Stripe webhook request and return the parsed event.
 *
 * Security checks (in order):
 *   1. `Stripe-Signature` header is present and well-formed
 *   2. Timestamp is within the tolerance window (rejects replayed events)
 *   3. At least one `v1` signature matches (constant-time comparison)
 *   4. Event ID has not been seen before (deduplication)
 *   5. Payload is valid JSON with required fields
 *
 * @param rawBody   - The raw (unparsed) request body string
 * @param signature - The value of the `Stripe-Signature` header
 * @param secret    - The webhook endpoint signing secret (`whsec_...`)
 * @param nowSeconds - Current Unix time in seconds (injectable for testing)
 * @param store     - Event deduplication store (injectable for testing)
 */
export function verifyStripeWebhook(
  rawBody: string,
  signature: string | undefined,
  secret: string,
  nowSeconds: number = Math.floor(Date.now() / 1000),
  store: SeenEventStore = seenEventStore,
): WebhookVerifyResult {
  // 1. Parse signature header
  const parsed = parseStripeSignatureHeader(signature)
  if (!parsed) {
    logger.warn(
      JSON.stringify({
        event: 'stripe_webhook_rejected',
        reason: 'missing_signature',
      }),
    )
    return { success: false, reason: 'missing_signature' }
  }

  const { timestamp, v1Signatures } = parsed

  // 2. Timestamp tolerance — reject events older than the tolerance window
  //    and events with timestamps suspiciously far in the future (clock skew guard)
  const ageSecs = nowSeconds - timestamp
  if (ageSecs > STRIPE_WEBHOOK_TOLERANCE_SECONDS) {
    logger.warn(
      JSON.stringify({
        event: 'stripe_webhook_rejected',
        reason: 'timestamp_too_old',
        ageSecs,
        toleranceSecs: STRIPE_WEBHOOK_TOLERANCE_SECONDS,
      }),
    )
    return { success: false, reason: 'timestamp_too_old' }
  }
  if (ageSecs < -STRIPE_WEBHOOK_TOLERANCE_SECONDS) {
    logger.warn(
      JSON.stringify({
        event: 'stripe_webhook_rejected',
        reason: 'timestamp_in_future',
        ageSecs,
      }),
    )
    return { success: false, reason: 'timestamp_in_future' }
  }

  // 3. Signature verification — constant-time comparison against all v1 sigs
  const expected = computeStripeSignature(timestamp, rawBody, secret)
  const expectedBuf = Buffer.from(expected, 'hex')

  const signatureMatches = v1Signatures.some((sig) => {
    const sigBuf = Buffer.from(sig, 'hex')
    // Buffers must be the same length for timingSafeEqual
    if (sigBuf.length !== expectedBuf.length) return false
    return crypto.timingSafeEqual(expectedBuf, sigBuf)
  })

  if (!signatureMatches) {
    logger.warn(
      JSON.stringify({
        event: 'stripe_webhook_rejected',
        reason: 'signature_mismatch',
      }),
    )
    return { success: false, reason: 'signature_mismatch' }
  }

  // 4. Parse payload (signature is valid, so we can trust the body)
  let event: StripeWebhookEvent
  try {
    event = JSON.parse(rawBody) as StripeWebhookEvent
    if (!event.id || typeof event.id !== 'string') {
      throw new Error('missing event id')
    }
    if (!event.type || typeof event.type !== 'string') {
      throw new Error('missing event type')
    }
  } catch {
    logger.error(
      JSON.stringify({
        event: 'stripe_webhook_rejected',
        reason: 'invalid_payload',
      }),
    )
    return { success: false, reason: 'invalid_payload' }
  }

  // 5. Deduplication — reject events we have already processed
  const isDuplicate = store.checkAndMark(event.id)
  if (isDuplicate) {
    logger.warn(
      JSON.stringify({
        event: 'stripe_webhook_rejected',
        reason: 'duplicate_event',
        stripeEventId: event.id,
        stripeEventType: event.type,
      }),
    )
    return { success: false, reason: 'duplicate_event' }
  }

  logger.info(
    JSON.stringify({
      event: 'stripe_webhook_accepted',
      stripeEventId: event.id,
      stripeEventType: event.type,
    }),
  )

  return { success: true, event }
}
