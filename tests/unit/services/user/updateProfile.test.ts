import { describe, it, expect, vi } from 'vitest'
import {
  updateProfile,
  ProfileUpdateError,
  MAX_NAME_LENGTH,
  type ProfileStore,
  type User,
} from '../../../../src/services/user/updateProfile'

const base: User = { id: 'u1', email: 'a@b.com', name: 'Old', profile: { bio: 'x' } }

function makeStore(user: User | null = base) {
  return {
    findById: vi.fn(async () => (user ? { ...user } : null)),
    save: vi.fn(async (u: User) => u),
  } satisfies ProfileStore
}

async function codeOf(p: Promise<unknown>) {
  try {
    await p
  } catch (e) {
    expect(e).toBeInstanceOf(ProfileUpdateError)
    expect(e).toBeInstanceOf(Error)
    return { code: (e as ProfileUpdateError).code, message: (e as Error).message }
  }
  throw new Error('expected rejection')
}

describe('updateProfile - success', () => {
  it('updates name and profile and persists via the store', async () => {
    const store = makeStore()
    const res = await updateProfile('u1', { name: 'New', profile: { bio: 'y' } }, store)
    expect(res).toEqual({ id: 'u1', email: 'a@b.com', name: 'New', profile: { bio: 'y' } })
    expect(store.save).toHaveBeenCalledTimes(1)
  })

  it('trims the name', async () => {
    const res = await updateProfile('u1', { name: '  Ada  ' }, makeStore())
    expect(res.name).toBe('Ada')
  })

  it('accepts a name of exactly MAX_NAME_LENGTH', async () => {
    const name = 'a'.repeat(MAX_NAME_LENGTH)
    expect((await updateProfile('u1', { name }, makeStore())).name).toBe(name)
  })

  it('empty updates return the existing user unchanged', async () => {
    expect(await updateProfile('u1', {}, makeStore())).toEqual(base)
  })

  it('skips undefined values instead of erasing fields', async () => {
    const res = await updateProfile('u1', { name: undefined, profile: undefined }, makeStore())
    expect(res.name).toBe('Old')
    expect(res.profile).toEqual({ bio: 'x' })
  })

  it('ignores unknown fields and never changes id or email', async () => {
    const res = await updateProfile(
      'u1',
      { id: 'evil', email: 'evil@x.com', role: 'admin' } as any,
      makeStore(),
    )
    expect(res.id).toBe('u1')
    expect(res.email).toBe('a@b.com')
    expect(res).not.toHaveProperty('role')
  })

  it('does not alias the caller profile object', async () => {
    const profile = { bio: 'y' }
    const res = await updateProfile('u1', { profile }, makeStore())
    expect(res.profile).not.toBe(profile)
  })

  it('works with the default stub store (existing behaviour)', async () => {
    const res = await updateProfile('u9', { name: 'Z' })
    expect(res).toEqual({ id: 'u9', email: 'user@example.com', name: 'Z', profile: {} })
  })
})

describe('updateProfile - rejections', () => {
  it.each([[''], ['   '], [undefined], [null], [123]])('rejects userId %j', async (id) => {
    expect(await codeOf(updateProfile(id as any, {}, makeStore()))).toEqual({
      code: 'USER_ID_REQUIRED',
      message: 'userId required',
    })
  })

  it.each([[null], [undefined], ['str'], [[]], [5]])('rejects updates %j', async (u) => {
    expect((await codeOf(updateProfile('u1', u as any, makeStore()))).code).toBe('INVALID_UPDATES')
  })

  it.each([[123], [true], [{}], [['a']], [null]])('rejects non-string name %j', async (name) => {
    expect(await codeOf(updateProfile('u1', { name } as any, makeStore()))).toEqual({
      code: 'INVALID_NAME',
      message: 'name must be a string',
    })
  })

  it.each([[''], ['   ']])('rejects empty name %j', async (name) => {
    expect((await codeOf(updateProfile('u1', { name }, makeStore()))).code).toBe('NAME_EMPTY')
  })

  it('rejects a name of MAX_NAME_LENGTH + 1', async () => {
    const name = 'a'.repeat(MAX_NAME_LENGTH + 1)
    expect((await codeOf(updateProfile('u1', { name }, makeStore()))).code).toBe('NAME_TOO_LONG')
  })

  it.each([['str'], [5], [null], [[]], [true]])('rejects invalid profile %j', async (profile) => {
    expect(await codeOf(updateProfile('u1', { profile } as any, makeStore()))).toEqual({
      code: 'INVALID_PROFILE',
      message: 'profile must be an object',
    })
  })

  it('rejects when the user does not exist', async () => {
    expect((await codeOf(updateProfile('nope', { name: 'A' }, makeStore(null)))).code).toBe(
      'USER_NOT_FOUND',
    )
  })

  it('validation failures never touch the store', async () => {
    const store = makeStore()
    await codeOf(updateProfile('u1', { name: 5 } as any, store))
    expect(store.findById).not.toHaveBeenCalled()
    expect(store.save).not.toHaveBeenCalled()
  })

  it('not-found does not call save', async () => {
    const store = makeStore(null)
    await codeOf(updateProfile('u1', { name: 'A' }, store))
    expect(store.save).not.toHaveBeenCalled()
  })

  it('checks in a fixed order: name error wins over profile error', async () => {
    const r = await codeOf(updateProfile('u1', { name: 5, profile: 'x' } as any, makeStore()))
    expect(r.code).toBe('INVALID_NAME')
  })
})