import { beforeEach, describe, expect, it } from 'vitest'
import {
  clearAllUsers,
  createUser,
  findUserById,
  promoteUserToBusinessAdmin,
  updateUser,
} from '../../../src/repositories/userRepository.js'

describe('userRepository role promotion', () => {
  beforeEach(() => {
    clearAllUsers()
  })

  it('promotes a regular user to business_admin', async () => {
    const user = await createUser('user@test.com', 'hash')

    const result = await promoteUserToBusinessAdmin(user.id)
    const stored = await findUserById(user.id)

    expect(result.outcome).toBe('promoted')
    expect(result.previousRole).toBe('user')
    expect(result.newRole).toBe('business_admin')
    expect(result.user?.role).toBe('business_admin')
    expect(stored?.role).toBe('business_admin')
  })

  it('is idempotent for duplicate retry after promotion', async () => {
    const user = await createUser('user@test.com', 'hash')

    const first = await promoteUserToBusinessAdmin(user.id)
    const retry = await promoteUserToBusinessAdmin(user.id)

    expect(first.outcome).toBe('promoted')
    expect(retry.outcome).toBe('already_business_admin')
    expect(retry.user?.role).toBe('business_admin')
  })

  it('keeps concurrent duplicate promotion attempts to one stored role transition', async () => {
    const user = await createUser('user@test.com', 'hash')

    const results = await Promise.all([
      promoteUserToBusinessAdmin(user.id),
      promoteUserToBusinessAdmin(user.id),
    ])
    const stored = await findUserById(user.id)

    expect(results.map(result => result.outcome).sort()).toEqual([
      'already_business_admin',
      'promoted',
    ])
    expect(stored?.role).toBe('business_admin')
  })

  it('does not overwrite admin users during promotion', async () => {
    const user = await createUser('admin@test.com', 'hash')
    await updateUser(user.id, { role: 'admin' })

    const result = await promoteUserToBusinessAdmin(user.id)
    const stored = await findUserById(user.id)

    expect(result.outcome).toBe('invalid_current_role')
    expect(result.previousRole).toBe('admin')
    expect(stored?.role).toBe('admin')
  })

  it('returns not_found for missing users', async () => {
    const result = await promoteUserToBusinessAdmin('missing')

    expect(result).toEqual({
      outcome: 'not_found',
      user: null,
      previousRole: null,
      newRole: 'business_admin',
    })
  })
})
