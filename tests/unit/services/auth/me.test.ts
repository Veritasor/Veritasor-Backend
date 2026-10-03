import { beforeEach, describe, expect, it, vi } from 'vitest'
import { AuthenticationError, NotFoundError } from '../../../../src/types/errors.js'
import type { User } from '../../../../src/repositories/userRepository.js'

const findUserById = vi.hoisted(() => vi.fn())

vi.mock('../../../../src/repositories/userRepository.js', () => ({
  findUserById,
}))

import { me, type MeResponse } from '../../../../src/services/auth/me.js'

const user: User = {
  id: 'user-123',
  email: 'person@example.com',
  passwordHash: 'must-not-be-returned',
  createdAt: new Date('2024-01-02T03:04:05.000Z'),
  updatedAt: new Date('2024-02-03T04:05:06.000Z'),
  role: 'user',
}

beforeEach(() => {
  findUserById.mockReset()
})

describe('me', () => {
  it('returns the public user profile with the MeResponse shape', async () => {
    findUserById.mockResolvedValue(user)

    const result: MeResponse = await me(user.id)

    expect(result).toEqual({
      user: {
        id: user.id,
        email: user.email,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
      },
    })
    expect(Object.keys(result.user).sort()).toEqual(['createdAt', 'email', 'id', 'updatedAt'])
    expect(result.user.createdAt).toBe(user.createdAt)
    expect(result.user.updatedAt).toBe(user.updatedAt)
    expect(result.user).not.toHaveProperty('passwordHash')
    expect(findUserById).toHaveBeenCalledExactlyOnceWith(user.id)
  })

  it.each([
    ['an empty string', ''],
    ['an undefined ID', undefined],
    ['a null ID', null],
  ])('rejects %s before querying the repository', async (_description, userId) => {
    await expect(me(userId as string)).rejects.toMatchObject({
      name: 'AuthenticationError',
      message: 'User ID is required',
      status: 401,
    })

    expect(findUserById).not.toHaveBeenCalled()
  })

  it('looks up a whitespace-only ID and reports it as an unknown user', async () => {
    findUserById.mockResolvedValue(null)

    await expect(me('   ')).rejects.toBeInstanceOf(NotFoundError)
    expect(findUserById).toHaveBeenCalledExactlyOnceWith('   ')
  })

  it('reports a missing user without changing the response contract', async () => {
    findUserById.mockResolvedValue(null)

    await expect(me('missing-user')).rejects.toMatchObject({
      name: 'NotFoundError',
      message: 'User not found',
      status: 404,
    })
    expect(findUserById).toHaveBeenCalledExactlyOnceWith('missing-user')
  })

  it('propagates repository failures unchanged', async () => {
    const failure = new Error('repository unavailable')
    findUserById.mockRejectedValue(failure)

    await expect(me(user.id)).rejects.toBe(failure)
  })

  it('moves from not-found to a profile response when the user becomes available', async () => {
    findUserById.mockResolvedValueOnce(null).mockResolvedValueOnce(user)

    await expect(me(user.id)).rejects.toBeInstanceOf(NotFoundError)
    await expect(me(user.id)).resolves.toMatchObject({ user: { id: user.id, email: user.email } })
    expect(findUserById).toHaveBeenCalledTimes(2)
  })
})
