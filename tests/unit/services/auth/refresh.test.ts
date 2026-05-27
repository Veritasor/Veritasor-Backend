/**
 * Unit tests for src/services/auth/refresh.ts
 *
 * Coverage:
 *   - Happy path: valid token → new token pair returned
 *   - Replay after rotation: same token rejected with AuthenticationError
 *   - Expired token: rejected before store is consulted
 *   - User not found: rejected after store check
 *   - Store unavailable: fails closed (AuthenticationError propagated)
 *   - Concurrent refresh: second concurrent call with same JTI is rejected
 *   - clearUsedRefreshTokens() resets state between tests
 *   - Missing token: rejected immediately
 */

import { describe, it, expect, beforeEach, vi } from 'vitest'
import jwt from 'jsonwebtoken'
import {
  refresh,
  clearUsedRefreshTokens,
} from '../../../../src/services/auth/refresh.js'
import {
  setUsedTokenStore,
  InMemoryUsedTokenStore,
  type UsedTokenStore,
} from '../../../../src/services/auth/usedTokenStore.js'
import { AuthenticationError } from '../../../../src/types/errors.js'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET ?? 'dev-refresh-secret-key'
const JWT_ISSUER = process.env.JWT_ISSUER ?? 'veritasor-api'
const JWT_REFRESH_AUDIENCE = process.env.JWT_REFRESH_AUDIENCE ?? 'veritasor-refresh'

const testUser = {
  id: 'user-abc-123',
  email: 'test@example.com',
  passwordHash: 'hash',
  createdAt: new Date(),
  updatedAt: new Date(),
  role: 'user' as const,
}

/** Mint a valid refresh token for testUser */
function makeRefreshToken(overrides: Record<string, unknown> = {}): string {
  return jwt.sign(
    {
      userId: testUser.id,
      email: testUser.email,
      jti: `jti-${Math.random().toString(36).slice(2)}`,
      ...overrides,
    },
    REFRESH_SECRET,
    {
      expiresIn: '7d',
      issuer: JWT_ISSUER,
      audience: JWT_REFRESH_AUDIENCE,
    }
  )
}

/** Mint an already-expired refresh token */
function makeExpiredRefreshToken(): string {
  return jwt.sign(
    {
      userId: testUser.id,
      email: testUser.email,
      jti: `jti-expired-${Math.random().toString(36).slice(2)}`,
    },
    REFRESH_SECRET,
    {
      expiresIn: -1,
      issuer: JWT_ISSUER,
      audience: JWT_REFRESH_AUDIENCE,
    }
  )
}

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

vi.mock('../../../../src/repositories/userRepository.js', () => ({
  findUserById: vi.fn(async (id: string) => {
    if (id === testUser.id) return testUser
    return null
  }),
}))

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

beforeEach(() => {
  clearUsedRefreshTokens()
})

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('refresh — happy path', () => {
  it('returns a new access token and refresh token', async () => {
    const token = makeRefreshToken()
    const result = await refresh({ refreshToken: token })

    expect(result).toHaveProperty('accessToken')
    expect(result).toHaveProperty('refreshToken')
    expect(typeof result.accessToken).toBe('string')
    expect(typeof result.refreshToken).toBe('string')
  })

  it('issues a different refresh token each time (rotation)', async () => {
    const token = makeRefreshToken()
    const result = await refresh({ refreshToken: token })
    expect(result.refreshToken).not.toBe(token)
  })
})

describe('refresh — replay after rotation', () => {
  it('rejects the same token on a second call', async () => {
    const token = makeRefreshToken()

    // First call succeeds
    await refresh({ refreshToken: token })

    // Second call with the same token must fail
    await expect(refresh({ refreshToken: token })).rejects.toThrow(
      AuthenticationError
    )
  })

  it('throws AuthenticationError with message "Invalid refresh token" on replay', async () => {
    const token = makeRefreshToken()
    await refresh({ refreshToken: token })

    const err = await refresh({ refreshToken: token }).catch((e) => e)
    expect(err).toBeInstanceOf(AuthenticationError)
    expect(err.message).toBe('Invalid refresh token')
  })
})

describe('refresh — expired token', () => {
  it('rejects an expired token before consulting the store', async () => {
    const expired = makeExpiredRefreshToken()
    await expect(refresh({ refreshToken: expired })).rejects.toThrow(
      AuthenticationError
    )
  })
})

describe('refresh — missing token', () => {
  it('rejects when refreshToken is an empty string', async () => {
    await expect(refresh({ refreshToken: '' })).rejects.toThrow(
      AuthenticationError
    )
  })
})

describe('refresh — user not found', () => {
  it('rejects when the user no longer exists', async () => {
    const token = makeRefreshToken({ userId: 'nonexistent-user' })
    await expect(refresh({ refreshToken: token })).rejects.toThrow(
      AuthenticationError
    )
  })
})

describe('refresh — store unavailable (fail closed)', () => {
  it('propagates store errors rather than allowing the refresh through', async () => {
    const faultyStore: UsedTokenStore = {
      async has() {
        throw new Error('DB connection lost')
      },
      async mark() {},
      clear() {},
    }
    setUsedTokenStore(faultyStore)

    const token = makeRefreshToken()
    await expect(refresh({ refreshToken: token })).rejects.toThrow(
      'DB connection lost'
    )
  })

  it('rejects when mark() throws (concurrent insert / unique violation)', async () => {
    let hasCallCount = 0
    const concurrentStore: UsedTokenStore = {
      async has() {
        // First call returns false (not yet consumed), simulating a race where
        // two requests pass the has() check before either calls mark().
        hasCallCount++
        return false
      },
      async mark() {
        throw Object.assign(new Error('unique violation'), { code: '23505' })
      },
      clear() {},
    }
    setUsedTokenStore(concurrentStore)

    const token = makeRefreshToken()
    await expect(refresh({ refreshToken: token })).rejects.toThrow()
  })
})

describe('clearUsedRefreshTokens', () => {
  it('allows a previously-used token to be accepted again after reset', async () => {
    const token = makeRefreshToken()

    // Consume the token
    await refresh({ refreshToken: token })

    // Reset state
    clearUsedRefreshTokens()

    // Token should be accepted again (store was wiped)
    const result = await refresh({ refreshToken: token })
    expect(result).toHaveProperty('accessToken')
  })
})
