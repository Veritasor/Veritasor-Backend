import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { UpdateUserData, User, UserRole } from './userRepository.js'
import {
  clearAllUsers,
  createUser,
  deleteUser,
  findUserByEmail,
  findUserById,
  findUserByResetTokenHash,
  findUsersByIds,
  getAllUsers,
  promoteUserToBusinessAdmin,
  setResetToken,
  updateUser,
  updateUserPassword,
} from './userRepository.js'

describe('userRepository user lifecycle', () => {
  beforeEach(() => {
    clearAllUsers()
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-01-01T12:00:00.000Z'))
  })

  afterEach(() => {
    clearAllUsers()
    vi.useRealTimers()
  })

  it('creates a User with the default role and returns isolated date values', async () => {
    const user: User = await createUser('first@example.com', 'hash-1')
    const second = await createUser('second@example.com', 'hash-2')

    expect(user).toMatchObject({ email: 'first@example.com', passwordHash: 'hash-1', role: 'user' })
    expect(user.id).toMatch(/^[0-9a-f]{32}$/)
    expect(second.id).not.toBe(user.id)
    expect(user.createdAt).toEqual(new Date('2026-01-01T12:00:00.000Z'))
    expect(user.updatedAt).toEqual(user.createdAt)

    user.createdAt.setUTCFullYear(2000)
    user.email = 'tampered@example.com'
    const stored = await findUserById(user.id)
    expect(stored?.createdAt.getUTCFullYear()).toBe(2026)
    expect(stored?.email).toBe('first@example.com')
    expect(await findUserByEmail('tampered@example.com')).toBeNull()
    expect(await getAllUsers()).toHaveLength(2)
  })

  it('applies UpdateUserData partially, reindexes email, and preserves immutable fields', async () => {
    const original = await createUser('old@example.com', 'hash-1')
    vi.setSystemTime(new Date('2026-01-01T12:01:00.000Z'))
    const role: UserRole = 'admin'
    const updates: UpdateUserData = { email: 'new@example.com', role }
    const updated = await updateUser(original.id, updates)

    expect(updated).toMatchObject({
      id: original.id,
      email: 'new@example.com',
      passwordHash: 'hash-1',
      role: 'admin',
    })
    expect(updated?.createdAt).toEqual(original.createdAt)
    expect(updated?.updatedAt).toEqual(new Date('2026-01-01T12:01:00.000Z'))
    expect(await findUserByEmail('old@example.com')).toBeNull()
    expect((await findUserByEmail('new@example.com'))?.id).toBe(original.id)
    expect((await updateUser(original.id, {}))?.role).toBe('admin')
  })

  it('returns null for missing users without creating a record', async () => {
    expect(await findUserById('missing')).toBeNull()
    expect(await findUserByEmail('missing@example.com')).toBeNull()
    expect(await updateUser('missing', { role: 'admin' })).toBeNull()
    expect(await setResetToken('missing', 'hash')).toBeNull()
    expect(await updateUserPassword('missing', 'new-hash')).toBeNull()
    expect(await getAllUsers()).toEqual([])
  })

  it('finds a reset token only before expiry and clears it when password changes', async () => {
    const user = await createUser('reset@example.com', 'old-hash')
    const tokenUser = await setResetToken(user.id, 'token-hash', 1)
    expect(tokenUser?.resetTokenExpiry).toEqual(new Date('2026-01-01T12:01:00.000Z'))
    expect(await findUserByResetTokenHash('wrong-hash')).toBeNull()

    vi.setSystemTime(new Date('2026-01-01T12:00:59.999Z'))
    expect((await findUserByResetTokenHash('token-hash'))?.id).toBe(user.id)
    vi.setSystemTime(new Date('2026-01-01T12:01:00.000Z'))
    expect(await findUserByResetTokenHash('token-hash')).toBeNull()

    const changed = await updateUserPassword(user.id, 'new-hash')
    expect(changed).toMatchObject({ passwordHash: 'new-hash' })
    expect(changed?.resetToken).toBeUndefined()
    expect(changed?.resetTokenExpiry).toBeUndefined()
    expect(await findUserByResetTokenHash('token-hash')).toBeNull()
  })

  it('promotes a regular user once and refuses to overwrite an admin role', async () => {
    const regular = await createUser('regular@example.com', 'hash')
    const admin = await createUser('admin@example.com', 'hash')
    await updateUser(admin.id, { role: 'admin' })

    expect((await promoteUserToBusinessAdmin(regular.id)).outcome).toBe('promoted')
    expect((await promoteUserToBusinessAdmin(regular.id)).outcome).toBe('already_business_admin')
    expect(await promoteUserToBusinessAdmin(admin.id)).toMatchObject({
      outcome: 'invalid_current_role', previousRole: 'admin', newRole: 'business_admin',
    })
    expect((await findUserById(admin.id))?.role).toBe('admin')
    expect((await promoteUserToBusinessAdmin('missing')).outcome).toBe('not_found')
  })

  it('deletes a user and reports missing IDs without affecting other users', async () => {
    const first = await createUser('first@example.com', 'hash')
    const second = await createUser('second@example.com', 'hash')

    expect(await deleteUser(first.id)).toBe(true)
    expect(await deleteUser(first.id)).toBe(false)
    expect(await findUserByEmail(first.email)).toBeNull()
    const results = await findUsersByIds([first.id, second.id])
    expect(results[0]).toEqual(new Error(`User not found: ${first.id}`))
    expect(results[1]).toMatchObject({ id: second.id, role: 'user' })
    expect(await getAllUsers()).toHaveLength(1)
  })
})
