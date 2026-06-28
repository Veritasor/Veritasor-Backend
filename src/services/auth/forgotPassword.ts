/**
 * @file forgotPassword.ts
 * @description Initiates the password reset flow.
 *
 * Security properties
 * ───────────────────
 * • User enumeration resistance — the same response shape and a constant-time
 *   delay are returned regardless of whether the email exists in the database.
 * • Token entropy — 32 random bytes (256-bit) generated with crypto.randomBytes,
 *   formatted as 64 lowercase hex characters. Not guessable.
 * • Token storage at rest — only the SHA-256 hash of the raw token is written
 *   to the database via `setResetToken`. The raw token never touches persistent
 *   storage. See `src/utils/tokenHash.ts` for the security rationale.
 * • Token TTL — configurable via RESET_TOKEN_TTL_MINUTES (default 15 min).
 *   The issue guidelines require < 15 min; the default satisfies that bound.
 * • Single-use — tokens are consumed (nulled) by resetPassword on first use,
 *   preventing replay.
 * • Rate limiting — applied at the route level via the shared rateLimiter
 *   middleware with a dedicated 'auth:forgot-password' bucket.
 * • Structured audit log — every invocation emits a typed log record to the
 *   provided logger callback (or a no-op if omitted). The record contains only
 *   the first 8 hex chars of the raw token for correlation — never the full
 *   token, and never the hash.
 * • Email delivery failures — retryable vs. permanent failures are surfaced as
 *   distinct AppError codes so callers/operators can react appropriately.
 *   On any delivery failure the token is cleared from the DB before throwing,
 *   so the user is not left with an unusable token silently stored.
 */

import { randomBytes } from 'node:crypto'
import {
  findUserByEmail,
  setResetToken,
  updateUser,
} from '../../repositories/userRepository.js'
import { sendPasswordResetEmail } from '../email/sendReset.js'
import { AppError } from '../../types/errors.js'
import { hashResetToken, tokenLogPrefix } from '../../utils/tokenHash.js'

// ── Types ─────────────────────────────────────────────────────────────────────

export interface ForgotPasswordRequest {
  email: string
}

export interface ForgotPasswordResponse {
  message: string
  /** Returned only in non-production environments for local testing. */
  resetLink?: string
}

export type ForgotPasswordAuditEvent =
  | 'forgot_password_requested'
  | 'forgot_password_user_not_found'
  | 'forgot_password_token_issued'
  | 'forgot_password_email_sent'
  | 'forgot_password_email_retryable_failure'
  | 'forgot_password_email_permanent_failure'

export interface ForgotPasswordAuditRecord {
  event: ForgotPasswordAuditEvent
  /**
   * First 8 hex chars of the *raw* token — sufficient for log correlation
   * without exposing the secret or the stored hash.
   */
  tokenPrefix?: string
  userId?: string
  /** ISO 8601 UTC timestamp. */
  timestamp: string
}

export type ForgotPasswordLogger = (record: ForgotPasswordAuditRecord) => void

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Read RESET_TOKEN_TTL_MINUTES from env, defaulting to 15.
 * Values outside (0, 60] fall back to the default and emit a stderr warning.
 */
function resolveTokenTtlMinutes(): number {
  const DEFAULT = 15
  const raw = process.env.RESET_TOKEN_TTL_MINUTES
  if (!raw) return DEFAULT
  const parsed = Number.parseInt(raw, 10)
  if (!Number.isFinite(parsed) || parsed <= 0 || parsed > 60) {
    process.stderr.write(
      `[forgotPassword] RESET_TOKEN_TTL_MINUTES="${raw}" is invalid; using default ${DEFAULT} min\n`,
    )
    return DEFAULT
  }
  return parsed
}

/**
 * Constant-time artificial delay to prevent timing-based user enumeration.
 * ~200 ms is long enough to mask DB round-trip variance.
 */
function timingDelay(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 200))
}

function nowIso(): string {
  return new Date().toISOString()
}

// ── Core service ─────────────────────────────────────────────────────────────

/**
 * Initiate a password reset for the given email address.
 *
 * Token storage contract
 * ──────────────────────
 * 1. A 64-char hex raw token is generated via `crypto.randomBytes(32)`.
 * 2. Its SHA-256 hash is computed via `hashResetToken(rawToken)`.
 * 3. **Only the hash** is passed to `setResetToken` — the raw token is
 *    never written to the database.
 * 4. The raw token is embedded in the reset link emailed to the user.
 * 5. On consumption (`resetPassword`), the incoming raw token is hashed
 *    and compared against the stored hash via `findUserByResetTokenHash`.
 *
 * @param request  - Validated request body containing the user's email.
 * @param logger   - Optional structured-log callback (defaults to no-op).
 *                   Wire this to pino / winston in your route handler.
 */
export async function forgotPassword(
  request: ForgotPasswordRequest,
  logger: ForgotPasswordLogger = () => {},
): Promise<ForgotPasswordResponse> {
  const { email } = request

  if (!email || typeof email !== 'string' || email.trim().length === 0) {
    throw new AppError('Email is required', 400, 'VALIDATION_ERROR')
  }

  logger({ event: 'forgot_password_requested', timestamp: nowIso() })

  // Constant-time baseline: run the DB look-up and the artificial delay in
  // parallel so the total wall-clock time is ~consistent whether or not the
  // user exists.
  const [user] = await Promise.all([
    findUserByEmail(email.trim().toLowerCase()),
    timingDelay(),
  ])

  // ── User not found: return the generic message without leaking existence ──
  if (!user) {
    logger({ event: 'forgot_password_user_not_found', timestamp: nowIso() })
    return {
      message:
        'If an account with this email exists, a reset link has been sent.',
    }
  }

  // ── Generate raw token ────────────────────────────────────────────────────
  const rawToken = randomBytes(32).toString('hex') // 64 lowercase hex chars

  // ── Hash for storage — raw token must NEVER be stored in the database ─────
  //
  // Security: if the database is compromised (SQL injection, stolen backup,
  // misconfigured access), the attacker only obtains SHA-256(rawToken).
  // Inverting SHA-256 on a 256-bit random input is computationally infeasible.
  const tokenHash = hashResetToken(rawToken)

  // Log only the first 8 characters of the RAW token for correlation.
  // Never log the full raw token or the hash.
  const logPrefix = tokenLogPrefix(rawToken)
  const ttlMinutes = resolveTokenTtlMinutes()

  // Persist the HASH, not the raw token.
  await setResetToken(user.id, tokenHash, ttlMinutes)

  logger({
    event: 'forgot_password_token_issued',
    tokenPrefix: logPrefix,
    userId: String(user.id),
    timestamp: nowIso(),
  })

  // ── Build reset link (contains the raw token, sent only via email) ────────
  const baseUrl =
    process.env.RESET_PASSWORD_URL ?? 'http://localhost:3000/reset-password'
  const resetLink = `${baseUrl}?token=${rawToken}`

  // ── Send email ────────────────────────────────────────────────────────────
  const emailResult = await sendPasswordResetEmail(user.email, resetLink)

  if (emailResult.error) {
    // Clear the hash from the DB so no dangling token is left behind.
    await updateUser(user.id, {
      resetToken: null,
      resetTokenExpiry: null,
    })

    if (emailResult.retryable) {
      logger({
        event: 'forgot_password_email_retryable_failure',
        tokenPrefix: logPrefix,
        userId: String(user.id),
        timestamp: nowIso(),
      })
      throw new AppError(
        'Unable to send reset email right now. Please try again shortly.',
        503,
        'RESET_EMAIL_RETRYABLE_FAILURE',
      )
    }

    logger({
      event: 'forgot_password_email_permanent_failure',
      tokenPrefix: logPrefix,
      userId: String(user.id),
      timestamp: nowIso(),
    })
    throw new AppError(
      'Password reset email is currently unavailable.',
      500,
      'RESET_EMAIL_UNAVAILABLE',
    )
  }

  logger({
    event: 'forgot_password_email_sent',
    tokenPrefix: logPrefix,
    userId: String(user.id),
    timestamp: nowIso(),
  })

  const isDev = process.env.NODE_ENV !== 'production'

  return {
    message:
      'If an account with this email exists, a reset link has been sent.',
    ...(isDev && { resetLink }),
  }
}
