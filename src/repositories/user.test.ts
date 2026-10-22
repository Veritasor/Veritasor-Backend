import { describe, it, expect, vi, beforeEach } from 'vitest'

import { AppError } from '../types/errors.js'

// The repository talks to the database through the shared lazy singleton
// `db` proxy. Mock the module so every query is intercepted and the
// repository's SQL construction + error mapping can be asserted in isolation.
const { query } = vi.hoisted(() => ({ query: vi.fn() }))

vi.mock('../db/client.js', () => ({
  db: { query },
}))

import { getById, create, update } from './user.js'

const now = new Date('2026-01-01T00:00:00.000Z')

function row(overrides: Record<string, unknown> = {}) {
  return {
    id: 'user-1',
    email: 'ada@example.com',
    name: 'Ada',
    createdAt: now,
    updatedAt: now,
    ...overrides,
  }
}

beforeEach(() => {
  query.mockReset()
})

describe('user repository — getById', () => {
  it('returns the row when a matching user exists', async () => {
    const expected = row()
    query.mockResolvedValueOnce({ rows: [expected] })

    await expect(getById('user-1')).resolves.toEqual(expected)
    expect(query).toHaveBeenCalledTimes(1)
    const [sql, params] = query.mock.calls[0]
    expect(String(sql)).toContain('FROM users WHERE id = $1')
    expect(params).toEqual(['user-1'])
  })

  it('returns null (not an error) when no user matches', async () => {
    query.mockResolvedValueOnce({ rows: [] })
    await expect(getById('missing')).resolves.toBeNull()
  })

  it('maps a database failure to a 500 AppError with DB_ERROR code', async () => {
    query.mockRejectedValueOnce(new Error('connection reset'))
    const err = await getById('user-1').catch((e) => e)

    expect(err).toBeInstanceOf(AppError)
    expect(err.message).toBe('Failed to fetch user')
    expect(err.status).toBe(500)
    expect((err as AppError).vrtCode).toBe('DB_ERROR')
  })
})

describe('user repository — create', () => {
  it('inserts the user and returns the created row', async () => {
    const expected = row({ id: 'new-1', email: 'new@example.com', name: 'New' })
    query.mockResolvedValueOnce({ rows: [expected] })

    await expect(
      create({ email: 'new@example.com', passwordHash: 'hash', name: 'New' }),
    ).resolves.toEqual(expected)

    const [sql, params] = query.mock.calls[0]
    expect(String(sql)).toContain('INSERT INTO users')
    expect(params).toEqual(['new@example.com', 'hash', 'New'])
  })

  it('defaults a missing name to the empty string', async () => {
    query.mockResolvedValueOnce({ rows: [row({ name: '' })] })

    await create({ email: 'noname@example.com', passwordHash: 'hash' })

    const [, params] = query.mock.calls[0]
    expect(params).toEqual(['noname@example.com', 'hash', ''])
  })

  it('maps a unique-violation (23505) to a 400 USER_ALREADY_EXISTS error', async () => {
    const unique = Object.assign(new Error('duplicate key value'), { code: '23505' })
    query.mockRejectedValueOnce(unique)

    const err = await create({ email: 'dup@example.com', passwordHash: 'hash' }).catch((e) => e)

    expect(err).toBeInstanceOf(AppError)
    expect(err.message).toBe('Email already exists')
    expect(err.status).toBe(400)
    expect((err as AppError).vrtCode).toBe('USER_ALREADY_EXISTS')
  })

  it('maps any other database failure to a generic 500 DB_ERROR', async () => {
    const boom = Object.assign(new Error('disk full'), { code: '53100' })
    query.mockRejectedValueOnce(boom)

    const err = await create({ email: 'x@example.com', passwordHash: 'hash' }).catch((e) => e)

    expect(err).toBeInstanceOf(AppError)
    expect(err.message).toBe('Failed to create user')
    expect(err.status).toBe(500)
    expect((err as AppError).vrtCode).toBe('DB_ERROR')
  })
})

describe('user repository — update', () => {
  it('with no mutable fields delegates to getById and never issues an UPDATE', async () => {
    const existing = row()
    query.mockResolvedValueOnce({ rows: [existing] })

    await expect(update('user-1', {})).resolves.toEqual(existing)

    expect(query).toHaveBeenCalledTimes(1)
    expect(String(query.mock.calls[0][0])).toContain('SELECT')
    expect(String(query.mock.calls[0][0])).not.toContain('UPDATE')
  })

  it('with no fields and no matching user throws 404 USER_NOT_FOUND', async () => {
    query.mockResolvedValueOnce({ rows: [] })

    const err = await update('ghost', {}).catch((e) => e)

    expect(err).toBeInstanceOf(AppError)
    expect(err.message).toBe('User not found')
    expect(err.status).toBe(404)
    expect((err as AppError).vrtCode).toBe('USER_NOT_FOUND')
  })

  it('builds positional placeholders for a single field and always bumps updated_at', async () => {
    const updated = row({ email: 'changed@example.com' })
    query.mockResolvedValueOnce({ rows: [updated] })

    await expect(update('user-1', { email: 'changed@example.com' })).resolves.toEqual(updated)

    const [sql, params] = query.mock.calls[0]
    expect(String(sql)).toContain('email = $1')
    expect(String(sql)).toContain('updated_at = now()')
    expect(String(sql)).toContain('WHERE id = $2')
    expect(params).toEqual(['changed@example.com', 'user-1'])
  })

  it('numbers placeholders correctly when both fields are present', async () => {
    const updated = row({ email: 'both@example.com', name: 'Both' })
    query.mockResolvedValueOnce({ rows: [updated] })

    await update('user-7', { email: 'both@example.com', name: 'Both' })

    const [sql, params] = query.mock.calls[0]
    expect(String(sql)).toContain('email = $1')
    expect(String(sql)).toContain('name = $2')
    expect(String(sql)).toContain('WHERE id = $3')
    expect(params).toEqual(['both@example.com', 'Both', 'user-7'])
  })

  it('throws 404 when the target id does not exist (zero rows updated)', async () => {
    query.mockResolvedValueOnce({ rows: [] })

    const err = await update('ghost', { name: 'Nobody' }).catch((e) => e)

    expect(err).toBeInstanceOf(AppError)
    expect(err.status).toBe(404)
    expect((err as AppError).vrtCode).toBe('USER_NOT_FOUND')
  })

  it('maps a unique-violation on update to 400 USER_ALREADY_EXISTS', async () => {
    const unique = Object.assign(new Error('duplicate key value'), { code: '23505' })
    query.mockRejectedValueOnce(unique)

    const err = await update('user-1', { email: 'taken@example.com' }).catch((e) => e)

    expect(err).toBeInstanceOf(AppError)
    expect(err.message).toBe('Email already exists')
    expect(err.status).toBe(400)
    expect((err as AppError).vrtCode).toBe('USER_ALREADY_EXISTS')
  })

  it('maps other update failures to 500 DB_ERROR', async () => {
    query.mockRejectedValueOnce(new Error('deadlock detected'))

    const err = await update('user-1', { name: 'X' }).catch((e) => e)

    expect(err).toBeInstanceOf(AppError)
    expect(err.message).toBe('Failed to update user')
    expect(err.status).toBe(500)
    expect((err as AppError).vrtCode).toBe('DB_ERROR')
  })
})
