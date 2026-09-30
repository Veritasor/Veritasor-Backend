export type User = {
  id: string
  email: string
  name?: string
  profile?: Record<string, any>
}

export const MAX_NAME_LENGTH = 100

export type ProfileUpdateErrorCode =
  | 'USER_ID_REQUIRED'
  | 'INVALID_UPDATES'
  | 'INVALID_NAME'
  | 'NAME_EMPTY'
  | 'NAME_TOO_LONG'
  | 'INVALID_PROFILE'
  | 'USER_NOT_FOUND'

/** Extends Error, so existing `catch (e) { e.message }` callers keep working. */
export class ProfileUpdateError extends Error {
  readonly code: ProfileUpdateErrorCode
  constructor(code: ProfileUpdateErrorCode, message: string) {
    super(message)
    this.name = 'ProfileUpdateError'
    this.code = code
  }
}

/** Persistence seam. Defaults to the in-memory stub below. */
export interface ProfileStore {
  findById(userId: string): Promise<User | null>
  save(user: User): Promise<User>
}

const stubStore: ProfileStore = {
  async findById(userId) {
    return { id: userId, email: 'user@example.com', name: 'Existing User', profile: {} }
  },
  async save(user) {
    return user
  },
}

function isPlainObject(v: unknown): v is Record<string, any> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

/**
 * Update a user's profile.
 *
 * Success: resolves to the full updated User (id and email are never changed).
 * Only `name` and `profile` are updatable; other keys are ignored.
 * `undefined` values are skipped. `profile` replaces the old profile (shallow copy).
 *
 * Failure: rejects with ProfileUpdateError. Checks run in a fixed order and
 * always before any store access:
 * userId -> updates -> name -> profile -> user lookup.
 */
export async function updateProfile(
  userId: string,
  updates: Partial<User>,
  store: ProfileStore = stubStore,
): Promise<User> {
  if (typeof userId !== 'string' || userId.trim() === '') {
    throw new ProfileUpdateError('USER_ID_REQUIRED', 'userId required')
  }
  if (!isPlainObject(updates)) {
    throw new ProfileUpdateError('INVALID_UPDATES', 'updates must be an object')
  }

  const payload: Partial<Pick<User, 'name' | 'profile'>> = {}

  if (Object.prototype.hasOwnProperty.call(updates, 'name') && updates.name !== undefined) {
    if (typeof updates.name !== 'string') {
      throw new ProfileUpdateError('INVALID_NAME', 'name must be a string')
    }
    const name = updates.name.trim()
    if (name.length === 0) {
      throw new ProfileUpdateError('NAME_EMPTY', 'name must not be empty')
    }
    if (name.length > MAX_NAME_LENGTH) {
      throw new ProfileUpdateError(
        'NAME_TOO_LONG',
        `name must be at most ${MAX_NAME_LENGTH} characters`,
      )
    }
    payload.name = name
  }

  if (Object.prototype.hasOwnProperty.call(updates, 'profile') && updates.profile !== undefined) {
    if (!isPlainObject(updates.profile)) {
      throw new ProfileUpdateError('INVALID_PROFILE', 'profile must be an object')
    }
    payload.profile = { ...updates.profile }
  }

  const existing = await store.findById(userId)
  if (!existing) {
    throw new ProfileUpdateError('USER_NOT_FOUND', 'user not found')
  }

  return store.save({ ...existing, ...payload, id: existing.id, email: existing.email })
}

export default updateProfile