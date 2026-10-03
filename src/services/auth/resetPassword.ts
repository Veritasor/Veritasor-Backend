/**
 * @file resetPassword.ts
 * @description Completes the password reset flow.
 *
 * Security properties
 * ───────────────────
 * • Token hash lookup — the incoming raw token is hashed with SHA-256 before
 *   querying the database.  The database never sees the raw token, and only
 *   stores the hash (written by forgotPassword).  See `src/utils/tokenHash.ts`
 *   for the full security rationale.
 * • Token single-use — `updateUserPassword` clears `resetToken` +
 *   `resetTokenExpiry` atomically with the password update, so a captured or
 *   replayed token cannot be used twice.
 * • Token expiry — `findUserByResetTokenHash` rejects tokens whose
 *   `resetTokenExpiry` is in the past (enforced at the repository layer).
 * • Minimum password entropy — rejects passwords shorter than 8 characters.
 *   Operators can raise the floor via RESET_MIN_PASSWORD_LENGTH.
 * • Structured audit log — emits typed records to the provided logger callback.
 *   Only the first 8 chars of the raw token are logged, never the hash.
 * • No silent failures — every error path throws a typed AppError.
 * • Generic error message — "Invalid or expired reset token" is returned for
 *   all token failures (wrong, expired, reused) to avoid oracle attacks.
 */

import {
  findUserByResetTokenHash,
  updateUserPassword,
} from '../../repositories/userRepository.js'
import { hashPassword } from '../../utils/password.js'
import { AppError } from '../../types/errors.js'
import { hashResetToken, tokenLogPrefix } from '../../utils/tokenHash.js'

// ── Types ─────────────────────────────────────────────────────────────────────

export interface ResetPasswordRequest {
  token: string
  newPassword: string
}

export interface ResetPasswordResponse {
  message: string
}

export type ResetPasswordAuditEvent =
  | 'reset_password_attempted'
  | 'reset_password_invalid_token'
  | 'reset_password_success'

export interface ResetPasswordAuditRecord {
  event: ResetPasswordAuditEvent
  /**
   * First 8 hex chars of the *raw* token — for log correlation only.
   * Never log the full raw token or the computed hash.
   */
  tokenPrefix?: string
  userId?: string
  timestamp: string
}

export type ResetPasswordLogger = (record: ResetPasswordAuditRecord) => void

// ── Helpers ───────────────────────────────────────────────────────────────────

function resolveMinPasswordLength(): number {
  const DEFAULT = 8
  const raw = process.env.RESET_MIN_PASSWORD_LENGTH
  if (!raw) return DEFAULT
  const parsed = Number.parseInt(raw, 10)
  if (!Number.isFinite(parsed) || parsed < 8) {
    process.stderr.write(
      `[resetPassword] RESET_MIN_PASSWORD_LENGTH="${raw}" is invalid or below minimum 8; using ${DEFAULT}\n`,
    )
    return DEFAULT
  }
  return parsed
}

function nowIso(): string {
  return new Date().toISOString()
}

// ── Core service ─────────────────────────────────────────────────────────────

/**
 * Complete a password reset given a valid, unexpired, single-use token.
 *
 * Token consumption contract
 * ──────────────────────────
 * 1. The caller supplies the raw token from the URL query parameter.
 * 2. This service hashes it: `tokenHash = SHA-256(rawToken)`.
 * 3. `findUserByResetTokenHash(tokenHash)` performs the DB lookup using the
 *    hash — the raw token is never sent to the database.
 * 4. If a matching, unexpired record is found, the password is updated and the
 *    token fields are atomically cleared (single-use enforcement).
 *
 * @param request - Validated request body containing the token and new password.
 * @param logger  - Optional structured-log callback (defaults to no-op).
 */
export async function resetPassword(
  request: ResetPasswordRequest,
  logger: ResetPasswordLogger = () => {},
): Promise<ResetPasswordResponse> {
  const { token, newPassword } = request

  // ── Input validation ───────────────────────────────────────────────────────
  if (!token || typeof token !== 'string' || token.trim().length === 0) {
    throw new AppError('Token is required', 400, 'VALIDATION_ERROR')
  }

  if (
    !newPassword ||
    typeof newPassword !== 'string' ||
    newPassword.trim().length === 0
  ) {
    throw new AppError('New password is required', 400, 'VALIDATION_ERROR')
  }

  const minLength = resolveMinPasswordLength()
  if (newPassword.length < minLength) {
    throw new AppError(
      `Password must be at least ${minLength} characters`,
      400,
      'VALIDATION_ERROR',
    )
  }

  // Log only the short prefix of the RAW token — never the hash, never the
  // full raw token.
  const logPrefix = tokenLogPrefix(token)

  logger({
    event: 'reset_password_attempted',
    tokenPrefix: logPrefix,
    timestamp: nowIso(),
  })

  // ── Hash the incoming raw token before touching the database ───────────────
  //
  // Security: the database stores SHA-256(rawToken), not the token itself.
  // We must hash the incoming value to produce the correct lookup key.
  // This means the raw token is only ever in memory during this request and
  // in the reset-link URL — it never reaches persistent storage.
  const tokenHash = hashResetToken(token)

  // ── Lookup by hash — covers: wrong token, expired token, reused token ─────
  //
  // `findUserByResetTokenHash` must:
  //   1. Perform an exact-match query on the stored hash column.
  //   2. Return null if no record matches (wrong/reused token).
  //   3. Return null if `resetTokenExpiry` is in the past (expired token).
  const user = await findUserByResetTokenHash(tokenHash)

  if (!user) {
    logger({
      event: 'reset_password_invalid_token',
      tokenPrefix: logPrefix,
      timestamp: nowIso(),
    })
    // Use a generic message for ALL token failure modes (wrong / expired /
    // reused) to prevent oracle attacks that distinguish between them.
    throw new AppError('Invalid or expired reset token', 400, 'INVALID_RESET_TOKEN')
  }

  const passwordHash = await hashPassword(newPassword)

  // ── Atomically update password and clear the token (single-use) ───────────
  //
  // `updateUserPassword` sets the new password hash AND nulls out `resetToken`
  // + `resetTokenExpiry` in a single operation so there is no window where a
  // concurrent request could consume the same token.
  await updateUserPassword(user.id, passwordHash)

  logger({
    event: 'reset_password_success',
    tokenPrefix: logPrefix,
    userId: String(user.id),
    timestamp: nowIso(),
  })

  return {
    message: 'Password has been reset successfully.',
  }
}
