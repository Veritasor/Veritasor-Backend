import { createHash, randomBytes } from 'node:crypto'
import { Request, Response } from 'express'
import { z } from 'zod'
import { integrationRepository } from '../../../repositories/integrations.js'

const RAZORPAY_VERIFY_URL = 'https://api.razorpay.com/v1/payments'
const RAZORPAY_OAUTH_URL = 'https://auth.razorpay.com/authorize'
const MAX_CREDENTIAL_LENGTH = 256
const CREDENTIAL_TIMEOUT_MS = 10_000

/**
 * CSRF state tokens expire after 10 minutes.
 * Short enough to limit replay windows; long enough for normal OAuth flows.
 */
const STATE_TTL_MS = 10 * 60 * 1_000

/**
 * Maximum permitted byte-length for a state token.
 * Anything longer than this is structurally invalid and rejected before store lookup.
 */
const STATE_MAX_LENGTH = 512

/**
 * Allowlist of redirect URL origins that Razorpay may redirect back to.
 * Populated from RAZORPAY_ALLOWED_REDIRECT_ORIGINS (comma-separated) at boot time.
 * An empty allowlist means ALL redirects are blocked (fail-closed).
 *
 * Example env var:
 *   RAZORPAY_ALLOWED_REDIRECT_ORIGINS=https://app.veritasor.com,https://staging.veritasor.com
 */
const ALLOWED_REDIRECT_ORIGINS: ReadonlySet<string> = (() => {
  const raw = process.env.RAZORPAY_ALLOWED_REDIRECT_ORIGINS ?? ''
  const origins = raw
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
  return new Set(origins)
})()

// ─── In-memory OAuth state store ─────────────────────────────────────────────
// Replace with Redis / DB in production for multi-instance deployments.

type OAuthStateEntry = {
  userId: string
  redirectUrl: string
  createdAt: number
  expiresAt: number
}

const oauthStateStore = new Map<string, OAuthStateEntry>()

/** Exposed for tests only — clears all state entries. */
export function _clearOAuthStateStore(): void {
  oauthStateStore.clear()
}

/** Exposed for tests only — directly inserts an entry (e.g. to seed expired states). */
export function _seedOAuthState(token: string, entry: OAuthStateEntry): void {
  oauthStateStore.set(token, entry)
}

// ─── Types ────────────────────────────────────────────────────────────────────

type RazorpayVerificationPayload = {
  entity: 'collection'
  items: unknown[]
}

// ─── Zod schemas ──────────────────────────────────────────────────────────────

const ConnectInitiateSchema = z.object({
  redirectUrl: z
    .string({ required_error: 'redirectUrl is required' })
    .url('redirectUrl must be a valid URL'),
})

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Validate and return a Razorpay credential value without mutating it.
 * Rejecting padded or control-character input helps preserve credential integrity.
 */
function parseCredential(value: unknown): string | null {
  if (typeof value !== 'string') return null
  if (value.length === 0 || value.length > MAX_CREDENTIAL_LENGTH) return null
  if (value.trim() !== value) return null
  if (/[\u0000-\u001f\u007f]/.test(value)) return null
  return value
}

function isRazorpayVerificationPayload(value: unknown): value is RazorpayVerificationPayload {
  if (!value || typeof value !== 'object') return false
  const payload = value as Partial<RazorpayVerificationPayload>
  return payload.entity === 'collection' && Array.isArray(payload.items)
}

function fingerprintCredentials(apiKeyId: string, apiKeySecret: string): string {
  return createHash('sha256').update(`${apiKeyId}:${apiKeySecret}`).digest('hex')
}

/**
 * Generate a cryptographically random, URL-safe state token.
 * 32 bytes → 64 hex chars; statistically unique, not guessable.
 */
function generateStateToken(): string {
  return randomBytes(32).toString('hex')
}

/**
 * Validate that a redirect URL belongs to an explicitly allowed origin.
 *
 * Security properties:
 * - Parsed via the WHATWG URL API — rejects malformed URLs before origin comparison.
 * - Only the origin (scheme + host + port) is compared; paths/query-strings are ignored.
 * - Non-https origins are always rejected unless the allowlist explicitly contains them
 *   (e.g. http://localhost for local development).
 * - An empty allowlist causes all redirects to be rejected (fail-closed).
 * - Open-redirect vectors (e.g. `//evil.com`, `javascript:`, `data:`) are blocked
 *   because the URL constructor either throws or normalises them to a non-matching origin.
 */
function validateRedirectUrl(rawUrl: string): { valid: true; url: URL } | { valid: false; reason: string } {
  let parsed: URL
  try {
    parsed = new URL(rawUrl)
  } catch {
    return { valid: false, reason: 'redirectUrl is not a valid absolute URL' }
  }

  // Reject non-https in production; allow http only when explicitly allow-listed.
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    return { valid: false, reason: 'redirectUrl scheme must be https (or http for local dev)' }
  }

  const origin = parsed.origin // e.g. "https://app.veritasor.com"

  if (!ALLOWED_REDIRECT_ORIGINS.has(origin)) {
    return {
      valid: false,
      reason: `redirectUrl origin "${origin}" is not in the allowed list`,
    }
  }

  return { valid: true, url: parsed }
}

/**
 * Consume a state token exactly once.
 * Returns the stored entry if the token is valid and unexpired; null otherwise.
 * The token is removed from the store regardless of outcome (prevents replay).
 */
function consumeStateToken(token: string): OAuthStateEntry | null {
  const entry = oauthStateStore.get(token)
  oauthStateStore.delete(token) // delete first — even if expired, don't keep it

  if (!entry) return null
  if (Date.now() > entry.expiresAt) return null

  return entry
}

// ─── Route handlers ───────────────────────────────────────────────────────────

/**
 * POST /api/integrations/razorpay/initiate
 *
 * Initiates a Razorpay OAuth connect flow by:
 *   1. Validating the caller-supplied redirectUrl against the origin allowlist
 *      (prevents open-redirect attacks).
 *   2. Generating a cryptographically random, single-use CSRF state token
 *      (prevents cross-site request forgery during the OAuth callback).
 *   3. Storing the state token server-side with a 10-minute TTL
 *      (prevents replay attacks after expiry).
 *   4. Returning the Razorpay authorization URL that the client should redirect
 *      the merchant browser to.
 *
 * The caller MUST redirect the user's browser to `authUrl`.  On return, the
 * Razorpay platform will redirect to `redirectUrl?code=...&state=<token>`.
 * The callback handler MUST call `validateRazorpayState` to verify the state
 * before exchanging the authorization code.
 *
 * Security notes:
 * - State tokens are 32 random bytes (256-bit entropy) — not guessable.
 * - Tokens are single-use: consumed and deleted on first validation attempt.
 * - Expired tokens are rejected even if the token itself is cryptographically valid.
 * - The redirectUrl origin is checked against an explicit server-side allowlist;
 *   no client-supplied URL can bypass this check.
 */
export async function initiateRazorpayConnect(req: Request, res: Response) {
  const userId = req.user?.userId
  if (!userId) {
    return res.status(401).json({ error: 'Unauthorized' })
  }

  // ── 1. Validate request body ───────────────────────────────────────────────
  const parsed = ConnectInitiateSchema.safeParse(req.body)
  if (!parsed.success) {
    return res.status(400).json({
      error: 'Validation error',
      details: parsed.error.flatten().fieldErrors,
    })
  }

  const { redirectUrl: rawRedirectUrl } = parsed.data

  // ── 2. Validate redirect URL against allowlist ─────────────────────────────
  const redirectValidation = validateRedirectUrl(rawRedirectUrl)
  if (!redirectValidation.valid) {
    return res.status(400).json({ error: redirectValidation.reason })
  }

  // ── 3. Prevent duplicate in-flight initiations (optional guard) ────────────
  // We intentionally do NOT block duplicate initiations here — a user may
  // legitimately open the flow in two tabs.  Each gets an independent token.

  // ── 4. Generate CSRF-safe state token ─────────────────────────────────────
  const stateToken = generateStateToken()
  const now = Date.now()

  oauthStateStore.set(stateToken, {
    userId,
    redirectUrl: redirectValidation.url.toString(),
    createdAt: now,
    expiresAt: now + STATE_TTL_MS,
  })

  // ── 5. Build Razorpay authorization URL ───────────────────────────────────
  const clientId = process.env.RAZORPAY_CLIENT_ID
  if (!clientId) {
    // State token was stored — clean it up to avoid orphaned entries.
    oauthStateStore.delete(stateToken)
    console.error('[razorpay] RAZORPAY_CLIENT_ID env var is not set')
    return res.status(503).json({ error: 'Razorpay OAuth is not configured' })
  }

  const authUrl = new URL(RAZORPAY_OAUTH_URL)
  authUrl.searchParams.set('response_type', 'code')
  authUrl.searchParams.set('client_id', clientId)
  authUrl.searchParams.set('redirect_uri', redirectValidation.url.toString())
  authUrl.searchParams.set('state', stateToken)
  authUrl.searchParams.set('scope', 'read_write')

  console.info({
    event: 'razorpay_oauth_initiate',
    userId,
    stateToken: stateToken.slice(0, 8) + '…', // log only prefix — not the full token
    redirectOrigin: redirectValidation.url.origin,
    expiresAt: new Date(now + STATE_TTL_MS).toISOString(),
  })

  return res.status(200).json({
    authUrl: authUrl.toString(),
    state: stateToken,
    expiresAt: new Date(now + STATE_TTL_MS).toISOString(),
  })
}

/**
 * Validate a Razorpay OAuth callback state token.
 *
 * Called by the callback route handler before exchanging the authorization code.
 * Returns the stored entry (userId + redirectUrl) on success.
 *
 * Failure modes (all return null + a human-readable reason string):
 * - Token is missing or non-string
 * - Token exceeds MAX_LENGTH (structural rejection before store lookup)
 * - Token contains control characters or null bytes
 * - Token not found in store (forged, already consumed, or never issued)
 * - Token found but expired
 *
 * The token is always deleted from the store on first call (single-use guarantee).
 */
export function validateRazorpayState(
  rawState: unknown,
): { valid: true; entry: OAuthStateEntry } | { valid: false; reason: string } {
  // ── Structural checks (before store lookup) ────────────────────────────────
  if (typeof rawState !== 'string' || rawState.length === 0) {
    return { valid: false, reason: 'Missing state parameter' }
  }

  if (rawState.length > STATE_MAX_LENGTH) {
    return { valid: false, reason: 'Invalid or expired state' }
  }

  if (/[\u0000-\u001f\u007f]/.test(rawState)) {
    return { valid: false, reason: 'Invalid or expired state' }
  }

  // ── Store lookup + consume ─────────────────────────────────────────────────
  const entry = consumeStateToken(rawState)
  if (!entry) {
    return { valid: false, reason: 'Invalid or expired state' }
  }

  return { valid: true, entry }
}

// ─── Existing API-key connect handler (unchanged) ─────────────────────────────

/**
 * Connect Razorpay account using API key pair.
 * Expects { apiKeyId, apiKeySecret } in the JSON body.
 * Verifies credentials by calling a lightweight Razorpay endpoint before storing.
 *
 * Security notes:
 * - Rejects malformed or padded credentials instead of normalizing them silently.
 * - Refuses duplicate provider connections for the same user.
 * - Never returns upstream Razorpay response bodies or secrets to the client.
 */
export async function connectRazorpay(req: Request, res: Response) {
  const userId = req.user?.userId
  if (!userId) return res.status(401).json({ error: 'Unauthorized' })

  const apiKeyId = parseCredential(req.body?.apiKeyId)
  const apiKeySecret = parseCredential(req.body?.apiKeySecret)

  if (!apiKeyId || !apiKeySecret) {
    return res.status(400).json({
      error: 'apiKeyId and apiKeySecret must be non-empty strings without surrounding whitespace',
    })
  }

  const existingIntegration = integrationRepository.findByUserAndProvider(userId, 'razorpay')
  if (existingIntegration) {
    return res.status(409).json({ error: 'Razorpay integration already connected' })
  }

  const auth = Buffer.from(`${apiKeyId}:${apiKeySecret}`).toString('base64')
  const url = new URL(RAZORPAY_VERIFY_URL)
  url.searchParams.set('count', '1')

  try {
    const resp = await fetch(url.toString(), {
      headers: { Authorization: `Basic ${auth}`, Accept: 'application/json' },
      signal: AbortSignal.timeout(CREDENTIAL_TIMEOUT_MS),
    })

    if (!resp.ok) {
      if (resp.status === 401 || resp.status === 403) {
        return res.status(400).json({ error: 'Invalid Razorpay credentials' })
      }
      return res.status(502).json({ error: 'Razorpay credential verification failed' })
    }

    const responseBody = await resp.json().catch(() => null)
    if (!isRazorpayVerificationPayload(responseBody)) {
      return res.status(502).json({ error: 'Unexpected Razorpay verification response' })
    }
  } catch {
    return res.status(502).json({ error: 'Failed to reach Razorpay API' })
  }

  const record = integrationRepository.create({
    provider: 'razorpay',
    userId,
    meta: {
      apiKeyId,
      apiKeySecret,
      credentialFingerprint: fingerprintCredentials(apiKeyId, apiKeySecret),
      verifiedAt: new Date().toISOString(),
    },
  })

  const safe = {
    ...record,
    meta: {
      apiKeyId: record.meta.apiKeyId,
      apiKeySecret: '*****',
      credentialFingerprint: record.meta.credentialFingerprint,
      verifiedAt: record.meta.verifiedAt,
    },
  }

  return res.status(201).json(safe)
}

export default connectRazorpay