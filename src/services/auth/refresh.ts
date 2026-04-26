import { findUserById } from '../../repositories/userRepository.js'
import {
  generateToken,
  generateRefreshToken,
  verifyRefreshToken,
} from '../../utils/jwt.js'
import { AuthenticationError } from '../../types/errors.js'

// Simple in-memory store for used tokens (rotation protection)
const usedRefreshTokens = new Set<string>()

export interface RefreshRequest {
  refreshToken: string
}

export interface RefreshResponse {
  accessToken: string
  refreshToken: string
}

/**
 * Clear all used refresh tokens.
 * @internal For testing only — resets rotation-protection state between test runs.
 */
export function clearUsedRefreshTokens(): void {
  usedRefreshTokens.clear()
}

/**
 * Unified Auth Session Rotation Policy:
 * - validates refresh token
 * - prevents reuse
 * - rotates tokens
 */
export async function refresh(
  request: RefreshRequest
): Promise<RefreshResponse> {
  const { refreshToken } = request

  if (!refreshToken) {
    throw new AuthenticationError('Refresh token is required')
  }

  // 🚨 prevent reuse (IMPORTANT for rotation)
  if (usedRefreshTokens.has(refreshToken)) {
    throw new AuthenticationError('Invalid refresh token')
  }

  const payload = verifyRefreshToken(refreshToken)
  if (!payload) {
    throw new AuthenticationError('Invalid or expired refresh token')
  }

  const user = await findUserById(payload.userId)
  if (!user) {
    throw new AuthenticationError('User not found')
  }

  // mark old token as used
  usedRefreshTokens.add(refreshToken)

  const accessToken = generateToken({
    userId: user.id,
    email: user.email,
  })

  const newRefreshToken = generateRefreshToken({
    userId: user.id,
    email: user.email,
  })

  return {
    accessToken,
    refreshToken: newRefreshToken,
  }
}
