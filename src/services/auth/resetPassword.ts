/**
 * @file resetPassword.ts
 * @description Completes the password reset flow.
 *
 * Security properties
 * ───────────────────
 * • Token single-use — updateUserPassword clears resetToken + resetTokenExpiry
 *   atomically with the password update, so a captured token cannot be replayed.
 * • Token expiry — findUserByResetToken must reject tokens whose
 *   resetTokenExpiry is in the past (enforced at the repository layer).
 * • Constant-time token comparison — the repository layer should use a
 *   timing-safe comparison; this service does not do raw string equality.
 * • Minimum password entropy — rejects passwords shorter than 8 characters.
 *   Operators can raise the floor via RESET_MIN_PASSWORD_LENGTH.
 * • Structured audit log — same pattern as forgotPassword; emits typed records
 *   to the provided logger callback.
 * • No silent failures — every error path throws a typed AppError.
 */

import {
  findUserByResetToken,
  updateUserPassword,
} from '../../repositories/userRepository.js'
import { hashPassword } from '../../utils/password.js'
import { AppError } from '../../types/errors.js'

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
  /** First 8 hex chars of the supplied token — for log correlation only. */
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
 * @param request - Validated request body containing the token and new password.
 * @param logger  - Optional structured-log callback (defaults to no-op).
 */
export async function resetPassword(
  request: ResetPasswordRequest,
  logger: ResetPasswordLogger = () => {},
): Promise<ResetPasswordResponse> {
  const { token, newPassword } = request

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

  const tokenPrefix = token.slice(0, 8)

  logger({
    event: 'reset_password_attempted',
    tokenPrefix,
    timestamp: nowIso(),
  })

  // findUserByResetToken must:
  //   1. Compare token using a timing-safe method (repository responsibility).
  //   2. Return null if the token is expired or already consumed.
  const user = await findUserByResetToken(token)

  if (!user) {
    logger({
      event: 'reset_password_invalid_token',
      tokenPrefix,
      timestamp: nowIso(),
    })
    // Use a generic message to avoid confirming token format / existence.
    throw new AppError('Invalid or expired reset token', 400, 'INVALID_RESET_TOKEN')
  }

  const passwordHash = await hashPassword(newPassword)

  // updateUserPassword must atomically:
  //   1. Set the new password hash.
  //   2. Clear resetToken and resetTokenExpiry — enforcing single-use.
  await updateUserPassword(user.id, passwordHash)

  logger({
    event: 'reset_password_success',
    tokenPrefix,
    userId: String(user.id),
    timestamp: nowIso(),
  })

  return {
    message: 'Password has been reset successfully.',
  }
}