/**
 * Unit tests for src/services/auth/me.ts
 *
 * The response returned by `me()` is consumed by the frontend immediately
 * after login, so its shape is a security-sensitive contract: it must expose
 * exactly `id`, `email`, `createdAt`, and `updatedAt` — never credential
 * fields such as `passwordHash`.
 *
 * Coverage:
 *   - Returns only the four public user fields (explicitly no passwordHash)
 *   - Empty ids (including whitespace-only) throw AuthenticationError
 *   - An unknown user throws NotFoundError
 *   - Repository errors propagate unchanged
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { me } from '../../../../src/services/auth/me.js'
import {
  AuthenticationError,
  NotFoundError,
} from '../../../../src/types/errors.js'
import * as userRepository from '../../../../src/repositories/userRepository.js'
import type { User } from '../../../../src/repositories/userRepository.js'

const createdAt = new Date('2026-02-18T09:00:00.000Z')
const updatedAt = new Date('2026-11-20T15:30:00.000Z')

function makeUser(overrides: Partial<User> = {}): User {
  return {
    id: 'user-abc123',
    email: 'alice@example.com',
    passwordHash: '$2b$12$super-secret-bcrypt-hash',
    createdAt,
    updatedAt,
    role: 'user',
    ...overrides,
  }
}

let findUserById: ReturnType<typeof vi.spyOn>

beforeEach(() => {
  findUserById = vi.spyOn(userRepository, 'findUserById')
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('me()', () => {
  it('returns only id, email, createdAt, and updatedAt for a known user', async () => {
    const user = makeUser()
    findUserById.mockResolvedValueOnce(user)

    const result = await me(user.id)

    expect(findUserById).toHaveBeenCalledWith(user.id)
    expect(result).toEqual({
      user: {
        id: user.id,
        email: user.email,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
      },
    })
  })

  it('never exposes passwordHash or other credential fields', async () => {
    const user = makeUser({
      resetToken: 'hashed-reset-token',
      resetTokenExpiry: new Date('2026-12-01T00:00:00.000Z'),
    })
    findUserById.mockResolvedValueOnce(user)

    const result = await me(user.id)

    expect(result.user).not.toHaveProperty('passwordHash')
    expect(result.user).not.toHaveProperty('resetToken')
    expect(result.user).not.toHaveProperty('resetTokenExpiry')
    expect(Object.keys(result.user).sort()).toEqual([
      'createdAt',
      'email',
      'id',
      'updatedAt',
    ])
    expect(JSON.stringify(result)).not.toContain(user.passwordHash)
  })

  it.each([
    ['an empty string', ''],
    ['a whitespace-only string', '   '],
    ['tabs and newlines only', '\t\n'],
  ])('throws AuthenticationError for %s', async (_label, userId) => {
    await expect(me(userId)).rejects.toBeInstanceOf(AuthenticationError)
    expect(findUserById).not.toHaveBeenCalled()
  })

  it('throws NotFoundError when the user does not exist', async () => {
    findUserById.mockResolvedValueOnce(null)

    await expect(me('missing-user')).rejects.toBeInstanceOf(NotFoundError)
    expect(findUserById).toHaveBeenCalledWith('missing-user')
  })

  it('propagates repository errors unchanged', async () => {
    const repositoryError = new Error('connection refused')
    findUserById.mockRejectedValueOnce(repositoryError)

    await expect(me('user-abc123')).rejects.toBe(repositoryError)
  })
})
