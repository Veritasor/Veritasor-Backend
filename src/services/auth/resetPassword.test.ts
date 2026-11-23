/**
 * Unit tests for src/services/auth/resetPassword.ts (issue #1330).
 *
 * Covers the post-reset security properties:
 *   - Pre-reset refresh tokens are rejected after a successful password reset
 *   - Another user's refresh tokens remain unaffected
 *   - The reset token is strictly single-use (replay rejected, DB lookup null)
 *   - Response body is unchanged: { message: 'Password has been reset successfully.' }
 *   - The revocation is recorded in the structured audit log (no raw tokens)
 *
 * These are integration-style tests against the REAL in-memory userRepository
 * and the REAL rotation-aware JWT machinery in src/utils/jwt.ts — only the
 * surrounding route layer is not involved.
 */

import { randomBytes } from 'node:crypto'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { resetPassword } from './resetPassword.js'
import type {
  ResetPasswordAuditRecord,
  ResetPasswordLogger,
} from './resetPassword.js'
import {
  createUser,
  deleteUser,
  findUserByResetTokenHash,
  setResetToken,
} from '../../repositories/userRepository.js'
import { hashPassword } from '../../utils/password.js'
import { hashResetToken } from '../../utils/tokenHash.js'
import {
  generateTokenPair,
  getTokenFamily,
  isTokenBlacklisted,
  verifyAccessToken,
  verifyRefreshTokenRotationAware,
} from '../../utils/jwt.js'
import { JWTError } from '../../utils/jwt.js'

// ---------------------------------------------------------------------------
// Fixtures / helpers
// ---------------------------------------------------------------------------

function makeRawResetToken(): string {
  return randomBytes(32).toString('hex')
}

const createdUsers: string[] = []

async function createTestUser(email: string) {
  const user = await createUser(email, await hashPassword('InitialPass123!'))
  createdUsers.push(user.id)
  return user
}

function auditEvents(
  logger: { mock: { calls: Array<[ResetPasswordAuditRecord]> } },
): string[] {
  return logger.mock.calls.map(([record]) => record.event)
}

// ---------------------------------------------------------------------------
// Setup / teardown
// ---------------------------------------------------------------------------

afterEach(async () => {
  for (const userId of createdUsers.splice(0)) {
    await deleteUser(userId)
  }
})

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('resetPassword — refresh-token invalidation on reset (issue #1330)', () => {
  it('rejects pre-reset refresh tokens after a successful password reset', async () => {
    const user = await createTestUser('reset-revoke@example.com')
    const { accessToken, refreshToken, familyId } = generateTokenPair({
      userId: user.id,
      email: user.email,
    })

    // Precondition: the refresh token is valid before the reset.
    const decodedRefresh = verifyRefreshTokenRotationAware(refreshToken)
    expect(decodedRefresh.userId).toBe(user.id)

    // Plant an unexpired reset token for the user.
    const rawResetToken = makeRawResetToken()
    await setResetToken(user.id, hashResetToken(rawResetToken), 5)

    const logger = vi.fn<ResetPasswordLogger>()
    const result = await resetPassword(
      { token: rawResetToken, newPassword: 'NewPass123!' },
      logger,
    )

    // Response body unchanged.
    expect(result).toEqual({
      message: 'Password has been reset successfully.',
    })

    // The pre-reset refresh token is now rejected: its JTI is blacklisted and
    // its token family entry was deleted by revokeAllUserTokenFamilies.
    expect(() => verifyRefreshTokenRotationAware(refreshToken)).toThrow(JWTError)
    expect(isTokenBlacklisted(decodedRefresh.jti)).toBe(true)
    expect(getTokenFamily(familyId)).toBeUndefined()

    // The access token minted with the same family is revoked too.
    expect(() => verifyAccessToken(accessToken)).toThrow(JWTError)

    // Audit event for the revocation is emitted (userId + family count).
    const events = auditEvents(logger)
    expect(events).toContain('reset_password_success')
    expect(events).toContain('reset_password_revoked_token_families')
    const revocation = logger.mock.calls
      .map(([record]) => record)
      .find((record) => record.event === 'reset_password_revoked_token_families')
    expect(revocation).toMatchObject({ userId: user.id, revokedFamilyCount: 1 })

    // No raw token or its hash leaks into the audit records.
    expect(JSON.stringify(logger.mock.calls)).not.toContain(rawResetToken)
    expect(JSON.stringify(logger.mock.calls)).not.toContain(
      hashResetToken(rawResetToken),
    )
  })

  it('revokes every family of the user (multiple families → count matches)', async () => {
    const user = await createTestUser('reset-multi@example.com')
    const pairA = generateTokenPair({ userId: user.id, email: user.email })
    const pairB = generateTokenPair({ userId: user.id, email: user.email })

    const rawResetToken = makeRawResetToken()
    await setResetToken(user.id, hashResetToken(rawResetToken), 5)

    const logger = vi.fn<ResetPasswordLogger>()
    await resetPassword(
      { token: rawResetToken, newPassword: 'NewPass123!' },
      logger,
    )

    expect(() => verifyRefreshTokenRotationAware(pairA.refreshToken)).toThrow(
      JWTError,
    )
    expect(() => verifyRefreshTokenRotationAware(pairB.refreshToken)).toThrow(
      JWTError,
    )
    expect(getTokenFamily(pairA.familyId)).toBeUndefined()
    expect(getTokenFamily(pairB.familyId)).toBeUndefined()

    const revocation = logger.mock.calls
      .map(([record]) => record)
      .find((record) => record.event === 'reset_password_revoked_token_families')
    expect(revocation).toMatchObject({ revokedFamilyCount: 2 })
  })

  it('leaves other users refresh tokens unaffected', async () => {
    const userA = await createTestUser('reset-other-a@example.com')
    const userB = await createTestUser('reset-other-b@example.com')
    const pairB = generateTokenPair({ userId: userB.id, email: userB.email })
    const jtiB = verifyRefreshTokenRotationAware(pairB.refreshToken).jti

    const rawResetToken = makeRawResetToken()
    await setResetToken(userA.id, hashResetToken(rawResetToken), 5)
    await resetPassword({ token: rawResetToken, newPassword: 'NewPass123!' })

    // userB's token still verifies and its family entry survives.
    expect(verifyRefreshTokenRotationAware(pairB.refreshToken).userId).toBe(
      userB.id,
    )
    expect(isTokenBlacklisted(jtiB)).toBe(false)
    expect(getTokenFamily(pairB.familyId)).toBeDefined()
  })

  it('rejects a second submission of the same reset token (single-use)', async () => {
    const user = await createTestUser('reset-single@example.com')
    const rawResetToken = makeRawResetToken()
    await setResetToken(user.id, hashResetToken(rawResetToken), 5)

    const first = await resetPassword({
      token: rawResetToken,
      newPassword: 'NewPass123!',
    })
    expect(first).toEqual({
      message: 'Password has been reset successfully.',
    })

    // Replay: the same token is rejected with the generic INVALID_RESET_TOKEN error.
    await expect(
      resetPassword({ token: rawResetToken, newPassword: 'OtherPass123!' }),
    ).rejects.toMatchObject({
      name: 'AppError',
      message: 'Invalid or expired reset token',
      status: 400,
    })

    // The stored reset-token hash is cleared, so the lookup cannot match again.
    expect(await findUserByResetTokenHash(hashResetToken(rawResetToken))).toBeNull()
  })
})
