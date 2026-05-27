/**
 * Unit tests for src/services/auth/usedTokenStore.ts
 *
 * Coverage:
 *   InMemoryUsedTokenStore:
 *     - has() returns false for unknown JTI
 *     - has() returns true after mark()
 *     - mark() is idempotent (no error on duplicate)
 *     - clear() resets all entries
 *
 *   DbUsedTokenStore:
 *     - has() returns false when DB returns no rows
 *     - has() returns true when DB returns a row
 *     - mark() executes INSERT with correct params
 *     - mark() re-throws on unique violation (23505)
 *     - mark() re-throws on other DB errors
 *
 *   Singleton helpers:
 *     - getUsedTokenStore() returns the active store
 *     - setUsedTokenStore() replaces the active store
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import {
  InMemoryUsedTokenStore,
  DbUsedTokenStore,
  getUsedTokenStore,
  setUsedTokenStore,
} from '../../../../src/services/auth/usedTokenStore.js'

// ---------------------------------------------------------------------------
// InMemoryUsedTokenStore
// ---------------------------------------------------------------------------

describe('InMemoryUsedTokenStore', () => {
  let store: InMemoryUsedTokenStore

  beforeEach(() => {
    store = new InMemoryUsedTokenStore()
  })

  it('has() returns false for an unknown JTI', async () => {
    expect(await store.has('unknown-jti')).toBe(false)
  })

  it('has() returns true after mark()', async () => {
    await store.mark('jti-1', 'user-1', new Date(Date.now() + 7 * 86400_000))
    expect(await store.has('jti-1')).toBe(true)
  })

  it('mark() is idempotent — no error on duplicate', async () => {
    const exp = new Date(Date.now() + 7 * 86400_000)
    await store.mark('jti-dup', 'user-1', exp)
    await expect(store.mark('jti-dup', 'user-1', exp)).resolves.toBeUndefined()
  })

  it('clear() removes all entries', async () => {
    await store.mark('jti-a', 'user-1', new Date())
    await store.mark('jti-b', 'user-2', new Date())
    store.clear()
    expect(await store.has('jti-a')).toBe(false)
    expect(await store.has('jti-b')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// DbUsedTokenStore
// ---------------------------------------------------------------------------

vi.mock('../../../../src/db/client.js', () => ({
  db: {
    query: vi.fn(),
  },
}))

import { db } from '../../../../src/db/client.js'

describe('DbUsedTokenStore', () => {
  let store: DbUsedTokenStore
  const mockQuery = vi.mocked(db.query)

  beforeEach(() => {
    store = new DbUsedTokenStore()
    mockQuery.mockReset()
  })

  describe('has()', () => {
    it('returns false when DB returns no rows', async () => {
      mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 0 } as any)
      expect(await store.has('jti-x')).toBe(false)
    })

    it('returns true when DB returns a row', async () => {
      mockQuery.mockResolvedValueOnce({ rows: [{ 1: 1 }], rowCount: 1 } as any)
      expect(await store.has('jti-x')).toBe(true)
    })

    it('passes the JTI as a query parameter', async () => {
      mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 0 } as any)
      await store.has('my-jti')
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('used_refresh_tokens'),
        ['my-jti']
      )
    })
  })

  describe('mark()', () => {
    it('executes an INSERT with jti, userId, and expiresAt', async () => {
      mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 1 } as any)
      const exp = new Date('2033-01-01T00:00:00Z')
      await store.mark('jti-y', 'user-42', exp)

      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO used_refresh_tokens'),
        ['jti-y', 'user-42', exp]
      )
    })

    it('re-throws on unique violation (23505) — concurrent replay', async () => {
      const uniqueViolation = Object.assign(new Error('duplicate key'), {
        code: '23505',
      })
      mockQuery.mockRejectedValueOnce(uniqueViolation)

      await expect(
        store.mark('jti-dup', 'user-1', new Date())
      ).rejects.toMatchObject({ code: '23505' })
    })

    it('re-throws on other DB errors', async () => {
      mockQuery.mockRejectedValueOnce(new Error('connection refused'))
      await expect(
        store.mark('jti-z', 'user-1', new Date())
      ).rejects.toThrow('connection refused')
    })
  })
})

// ---------------------------------------------------------------------------
// Singleton helpers
// ---------------------------------------------------------------------------

describe('getUsedTokenStore / setUsedTokenStore', () => {
  it('getUsedTokenStore returns the active store', () => {
    const store = new InMemoryUsedTokenStore()
    setUsedTokenStore(store)
    expect(getUsedTokenStore()).toBe(store)
  })

  it('setUsedTokenStore replaces the active store', () => {
    const storeA = new InMemoryUsedTokenStore()
    const storeB = new InMemoryUsedTokenStore()
    setUsedTokenStore(storeA)
    setUsedTokenStore(storeB)
    expect(getUsedTokenStore()).toBe(storeB)
  })
})
