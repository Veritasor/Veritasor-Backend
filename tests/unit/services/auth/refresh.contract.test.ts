/**
 * Contract coverage for src/services/auth/refresh.ts.
 *
 * Complements `refresh.test.ts` (happy path, replay, expiry) by pinning the
 * parts of the public contract that were still implicit:
 *   - the exact `RefreshResponse` shape and the rotation of the refresh `jti`
 *   - the `extractJtiAndExp` claim-validation branch
 *   - the message/taxonomy contract of every rejection
 *   - the order and arguments of the used-token store calls
 *   - `clearUsedRefreshTokens()` replacing the active store
 */

import { describe, it, expect, beforeEach, vi } from 'vitest'
import jwt from 'jsonwebtoken'
import { refresh, clearUsedRefreshTokens } from '../../../../src/services/auth/refresh.js'
import {
  setUsedTokenStore,
  getUsedTokenStore,
  InMemoryUsedTokenStore,
  type UsedTokenStore,
} from '../../../../src/services/auth/usedTokenStore.js'
import { AuthenticationError } from '../../../../src/types/errors.js'

const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET ?? 'dev-refresh-secret-key'
const JWT_ISSUER = process.env.JWT_ISSUER ?? 'veritasor-api'
const JWT_REFRESH_AUDIENCE = process.env.JWT_REFRESH_AUDIENCE ?? 'veritasor-refresh'

const testUser = {
  id: 'user-contract-1',
  email: 'contract@example.com',
  passwordHash: 'hash',
  createdAt: new Date(),
  updatedAt: new Date(),
  role: 'user' as const,
}

vi.mock('../../../../src/repositories/userRepository.js', () => ({
  findUserById: vi.fn(async (id: string) => (id === testUser.id ? testUser : null)),
}))

const { findUserById } = await import('../../../../src/repositories/userRepository.js')
const findUserByIdMock = vi.mocked(findUserById)

/** Mint a signed refresh token with full control over the claims. */
function signRefresh(claims: Record<string, unknown>, options: jwt.SignOptions = {}): string {
  const merged: jwt.SignOptions = {
    expiresIn: '7d',
    issuer: JWT_ISSUER,
    audience: JWT_REFRESH_AUDIENCE,
    ...options,
  }
  // Allow callers to drop a default (e.g. mint a token with no `exp` claim).
  for (const key of Object.keys(merged) as (keyof jwt.SignOptions)[]) {
    if (merged[key] === undefined) delete merged[key]
  }
  return jwt.sign(claims, REFRESH_SECRET, merged)
}

function makeRefreshToken(overrides: Record<string, unknown> = {}, options: jwt.SignOptions = {}): string {
  return signRefresh(
    {
      userId: testUser.id,
      email: testUser.email,
      jti: `jti-${Math.random().toString(36).slice(2)}`,
      ...overrides,
    },
    options,
  )
}

function claimsOf(token: string): { jti?: string; exp?: number; aud?: string; userId?: string; email?: string } {
  return jwt.decode(token) as { jti?: string; exp?: number; aud?: string; userId?: string; email?: string }
}

/** A store that records every call, for ordering and argument assertions. */
function recordingStore(): { store: UsedTokenStore; calls: string[]; has: ReturnType<typeof vi.fn>; mark: ReturnType<typeof vi.fn> } {
  const calls: string[] = []
  const has = vi.fn(async (_jti: string) => {
    calls.push('has')
    return false
  })
  const mark = vi.fn(async (_jti: string, _userId: string, _expiresAt: Date) => {
    calls.push('mark')
  })
  return {
    store: { has, mark, clear: () => {} } as UsedTokenStore,
    calls,
    has,
    mark,
  }
}

async function rejection(promise: Promise<unknown>): Promise<AuthenticationError> {
  const err = await promise.then(
    () => {
      throw new Error('expected refresh() to reject')
    },
    (e) => e,
  )
  return err as AuthenticationError
}

beforeEach(() => {
  clearUsedRefreshTokens()
  findUserByIdMock.mockClear()
})

describe('refresh — RefreshResponse contract', () => {
  it('returns exactly an accessToken and a refreshToken, both non-empty strings', async () => {
    const result = await refresh({ refreshToken: makeRefreshToken() })

    expect(Object.keys(result).sort()).toEqual(['accessToken', 'refreshToken'])
    expect(typeof result.accessToken).toBe('string')
    expect(typeof result.refreshToken).toBe('string')
    expect(result.accessToken.length).toBeGreaterThan(0)
    expect(result.refreshToken.length).toBeGreaterThan(0)
  })

  it('rotates the refresh jti while preserving the identity claims', async () => {
    const presented = makeRefreshToken()
    const before = claimsOf(presented)

    const result = await refresh({ refreshToken: presented })
    const after = claimsOf(result.refreshToken)

    expect(after.jti).toBeTruthy()
    expect(after.jti).not.toBe(before.jti)
    expect(after.userId).toBe(testUser.id)
    expect(after.email).toBe(testUser.email)
    expect(after.aud).toBe(JWT_REFRESH_AUDIENCE)
    expect(after.exp).toBeGreaterThan(Math.floor(Date.now() / 1000))
  })

  it('does not leak the presented token into the response', async () => {
    const presented = makeRefreshToken()
    const result = await refresh({ refreshToken: presented })
    expect(result.refreshToken).not.toBe(presented)
  })
})

describe('refresh — rejected input contract', () => {
  it('rejects a missing token with "Refresh token is required"', async () => {
    const err = await rejection(refresh({ refreshToken: undefined as unknown as string }))
    expect(err).toBeInstanceOf(AuthenticationError)
    expect(err.message).toBe('Refresh token is required')
  })

  it('rejects whitespace-only input as invalid rather than missing', async () => {
    const err = await rejection(refresh({ refreshToken: '   ' }))
    expect(err.message).toBe('Invalid or expired refresh token')
  })

  it('rejects a token signed with the wrong secret', async () => {
    const token = jwt.sign({ userId: testUser.id, email: testUser.email, jti: 'x' }, 'wrong-secret', {
      expiresIn: '7d',
      issuer: JWT_ISSUER,
      audience: JWT_REFRESH_AUDIENCE,
    })
    const err = await rejection(refresh({ refreshToken: token }))
    expect(err.message).toBe('Invalid or expired refresh token')
  })

  it('rejects a token minted for a different audience', async () => {
    const token = makeRefreshToken({}, { audience: 'veritasor-client' })
    const err = await rejection(refresh({ refreshToken: token }))
    expect(err.message).toBe('Invalid or expired refresh token')
  })

  it('rejects a token minted by a different issuer', async () => {
    const token = makeRefreshToken({}, { issuer: 'some-other-issuer' })
    const err = await rejection(refresh({ refreshToken: token }))
    expect(err.message).toBe('Invalid or expired refresh token')
  })

  it('rejects a signed token that carries no jti claim', async () => {
    const token = makeRefreshToken({ jti: undefined })
    const err = await rejection(refresh({ refreshToken: token }))
    expect(err).toBeInstanceOf(AuthenticationError)
    expect(err.message).toBe('Refresh token is missing required claims')
  })

  it('rejects a signed token that carries no exp claim', async () => {
    const token = signRefresh(
      { userId: testUser.id, email: testUser.email, jti: 'no-exp' },
      { expiresIn: undefined },
    )
    expect(claimsOf(token).exp).toBeUndefined()
    const err = await rejection(refresh({ refreshToken: token }))
    expect(err.message).toBe('Refresh token is missing required claims')
  })

  it('rejects a deleted user with "User not found"', async () => {
    const token = makeRefreshToken({ userId: 'deleted-user' })
    const err = await rejection(refresh({ refreshToken: token }))
    expect(err.message).toBe('User not found')
  })

  it('reports every rejection through the AuthenticationError taxonomy', async () => {
    const err = await rejection(refresh({ refreshToken: makeRefreshToken({ userId: 'deleted-user' }) }))
    expect(err.name).toBe('AuthenticationError')
    expect(err.status).toBe(401)
    expect(err.vrtCode).toBe('VRT-0001')
  })
})

describe('refresh — used-token store contract', () => {
  it('checks the presented jti before consuming it, then marks the exact expiry', async () => {
    const rec = recordingStore()
    setUsedTokenStore(rec.store)

    const presented = makeRefreshToken()
    const expectedJti = claimsOf(presented).jti as string
    const expectedExp = claimsOf(presented).exp as number

    await refresh({ refreshToken: presented })

    expect(rec.has).toHaveBeenCalledTimes(1)
    expect(rec.has).toHaveBeenCalledWith(expectedJti)
    expect(rec.calls).toEqual(['has', 'mark'])

    expect(rec.mark).toHaveBeenCalledTimes(1)
    const [markedJti, markedUser, markedExpiry] = rec.mark.mock.calls[0] as [string, string, Date]
    expect(markedJti).toBe(expectedJti)
    expect(markedUser).toBe(testUser.id)
    expect(markedExpiry).toBeInstanceOf(Date)
    expect(markedExpiry.getTime()).toBe(expectedExp * 1000)
  })

  it('does not look up the user again when the jti was already consumed', async () => {
    const rec = recordingStore()
    rec.has.mockResolvedValue(true)
    setUsedTokenStore(rec.store)

    const err = await rejection(refresh({ refreshToken: makeRefreshToken() }))

    expect(err.message).toBe('Invalid refresh token')
    expect(rec.mark).not.toHaveBeenCalled()
    expect(findUserByIdMock).not.toHaveBeenCalled()
  })

  it('rejects when the store reports a consumed jti even if the token is otherwise valid', async () => {
    const store: UsedTokenStore = {
      has: async () => true,
      mark: vi.fn(async () => {}),
      clear: () => {},
    }
    setUsedTokenStore(store)
    await expect(refresh({ refreshToken: makeRefreshToken() })).rejects.toBeInstanceOf(AuthenticationError)
  })
})

describe('clearUsedRefreshTokens', () => {
  it('installs a fresh in-memory store', () => {
    const before = getUsedTokenStore()
    clearUsedRefreshTokens()
    const after = getUsedTokenStore()
    expect(after).toBeInstanceOf(InMemoryUsedTokenStore)
    expect(after).not.toBe(before)
  })

  it('forgets the consumption of a jti so the same token is accepted again', async () => {
    const token = makeRefreshToken()
    await refresh({ refreshToken: token })

    clearUsedRefreshTokens()

    const result = await refresh({ refreshToken: token })
    expect(typeof result.refreshToken).toBe('string')
  })
})
