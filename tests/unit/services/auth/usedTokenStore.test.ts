/**
 * Unit tests for src/services/auth/usedTokenStore.ts
 *
 * This module is the replay-protection primitive behind refresh-token rotation:
 * refresh() asks the active store whether a JTI was already consumed and marks
 * it as consumed before handing out a new token pair. The store contract is
 * therefore security-relevant, so this fixture pins it down directly.
 *
 * Coverage:
 *   UsedTokenStore (interface contract, exercised against BOTH implementations):
 *     - has() false → mark() → has() true (primary state transition)
 *     - mark() is idempotent for the same JTI
 *     - a second JTI does not affect the first
 *     - clear() returns the store to its empty state and the store stays usable
 *     - clear() may be sync (void) or async (Promise<void>) — awaiting works
 *     - expiresAt is never applied by the store (JWT expiry / DB cleanup owns it)
 *     - has() always resolves to a boolean primitive
 *
 *   InMemoryUsedTokenStore:
 *     - has() returns false for an unknown JTI
 *     - has() returns true after mark()
 *     - mark() is idempotent (no error on duplicate)
 *     - clear() resets all entries
 *     - clear() is synchronous — it returns undefined, not a promise
 *     - concurrent mark() calls for the same JTI converge without error
 *     - instances are isolated from each other
 *     - representative invalid inputs (empty, whitespace, unicode, 4 KB and
 *       non-string JTIs) are handled deterministically by the Set backing store
 *
 *   DbUsedTokenStore:
 *     - has() returns false when the DB returns no rows
 *     - has() returns true when the DB returns a row
 *     - has() treats a nullish rowCount as "no rows"
 *     - has() propagates DB errors (callers fail closed)
 *     - mark() issues INSERT ... ON CONFLICT (jti) DO NOTHING with all params
 *     - mark() resolves only after the INSERT settles
 *     - mark() re-throws a 23505 unique violation without logging (replay path)
 *     - mark() logs and re-throws other DB errors
 *     - mark() logs and re-throws non-Error rejections
 *     - clear() issues DELETE FROM used_refresh_tokens
 *     - clear() propagates DB errors
 *
 *   Singleton helpers:
 *     - a fresh module instance exposes an InMemoryUsedTokenStore by default
 *     - getUsedTokenStore() returns the active store
 *     - setUsedTokenStore() swaps the active store by reference
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import {
  InMemoryUsedTokenStore,
  DbUsedTokenStore,
  getUsedTokenStore,
  setUsedTokenStore,
  type UsedTokenStore,
} from '../../../../src/services/auth/usedTokenStore.js'

vi.mock('../../../../src/db/client.js', () => ({
  db: {
    query: vi.fn(),
  },
}))

vi.mock('../../../../src/utils/logger.js', () => ({
  logger: {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}))

import { db } from '../../../../src/db/client.js'
import { logger } from '../../../../src/utils/logger.js'

const mockQuery = vi.mocked(db.query)
const mockLoggerError = vi.mocked(logger.error)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Shape of what the store consumes from a `pg` query result. */
type QueryResultLike = Awaited<ReturnType<typeof db.query>>

/** Build a query result without reaching into pg's internals. */
function queryResult(rowCount: number | null, rows: unknown[] = []): QueryResultLike {
  return { rows, rowCount } as unknown as QueryResultLike
}

/**
 * Install a tiny in-process stand-in for the `used_refresh_tokens` table so the
 * PostgreSQL implementation can be exercised through its public interface.
 * Mirrors the real statements: SELECT 1 / INSERT ... ON CONFLICT DO NOTHING /
 * DELETE. Returns the backing table so assertions can inspect what was stored.
 */
function installFakeDatabase(): Map<string, { userId: string; expiresAt: Date }> {
  const table = new Map<string, { userId: string; expiresAt: Date }>()

  const implementation = (async (
    sql: string,
    params?: unknown[]
  ): Promise<QueryResultLike> => {
    if (sql.includes('DELETE FROM used_refresh_tokens')) {
      const deleted = table.size
      table.clear()
      return queryResult(deleted)
    }

    if (sql.includes('SELECT 1 FROM used_refresh_tokens')) {
      const jti = String(params?.[0])
      return table.has(jti) ? queryResult(1, [{ '?column?': 1 }]) : queryResult(0)
    }

    const [jti, userId, expiresAt] = params as [string, string, Date]
    const inserted = !table.has(jti)
    table.set(jti, { userId, expiresAt })
    return queryResult(inserted ? 1 : 0)
  }) as unknown as typeof db.query

  mockQuery.mockImplementation(implementation)
  return table
}

const SECOND_USER = 'user-2'
const TTL = new Date('2033-01-01T00:00:00Z')

/**
 * Implementations that must satisfy the shared UsedTokenStore contract.
 * DbUsedTokenStore is wired to the fake table above, so both implementations
 * are driven through exactly the same assertions.
 */
const IMPLEMENTATIONS: Array<{ name: string; create: () => UsedTokenStore }> = [
  {
    name: 'InMemoryUsedTokenStore',
    create: () => new InMemoryUsedTokenStore(),
  },
  {
    name: 'DbUsedTokenStore',
    create: () => {
      installFakeDatabase()
      return new DbUsedTokenStore()
    },
  },
]

// ---------------------------------------------------------------------------
// Shared UsedTokenStore contract — both implementations
// ---------------------------------------------------------------------------

for (const implementation of IMPLEMENTATIONS) {
  describe(`UsedTokenStore contract — ${implementation.name}`, () => {
    let store: UsedTokenStore

    beforeEach(() => {
      mockQuery.mockReset()
      store = implementation.create()
    })

    it('reports an unseen JTI as not consumed', async () => {
      expect(await store.has('jti-unseen')).toBe(false)
    })

    it('transitions to consumed after mark() and stays consumed', async () => {
      await store.mark('jti-1', 'user-1', TTL)

      expect(await store.has('jti-1')).toBe(true)
      expect(await store.has('jti-1')).toBe(true)
    })

    it('mark() is idempotent — re-marking the same JTI never throws', async () => {
      await store.mark('jti-dup', 'user-1', TTL)

      await expect(store.mark('jti-dup', 'user-1', TTL)).resolves.toBeUndefined()
      await expect(store.mark('jti-dup', SECOND_USER, TTL)).resolves.toBeUndefined()
      expect(await store.has('jti-dup')).toBe(true)
    })

    it('tracks JTIs independently', async () => {
      await store.mark('jti-a', 'user-1', TTL)

      expect(await store.has('jti-a')).toBe(true)
      expect(await store.has('jti-b')).toBe(false)

      await store.mark('jti-b', SECOND_USER, TTL)

      expect(await store.has('jti-a')).toBe(true)
      expect(await store.has('jti-b')).toBe(true)
    })

    it('clear() empties the store and leaves it usable', async () => {
      await store.mark('jti-a', 'user-1', TTL)
      await store.mark('jti-b', SECOND_USER, TTL)

      // Awaiting works for both the sync (InMemory) and async (Db) contract.
      await store.clear()

      expect(await store.has('jti-a')).toBe(false)
      expect(await store.has('jti-b')).toBe(false)

      await store.mark('jti-a', 'user-1', TTL)
      expect(await store.has('jti-a')).toBe(true)
    })

    it('ignores expiresAt — expiry is enforced before the store is consulted', async () => {
      const alreadyExpired = new Date(Date.now() - 60_000)

      await store.mark('jti-expired', 'user-1', alreadyExpired)

      // The store records consumption, not validity: an expired JTI that was
      // consumed must still be reported as consumed.
      expect(await store.has('jti-expired')).toBe(true)
    })

    it('has() resolves to a boolean primitive', async () => {
      expect(typeof (await store.has('jti-missing'))).toBe('boolean')

      await store.mark('jti-1', 'user-1', TTL)
      expect(typeof (await store.has('jti-1'))).toBe('boolean')
    })
  })
}

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
    await store.mark('jti-b', SECOND_USER, new Date())
    store.clear()
    expect(await store.has('jti-a')).toBe(false)
    expect(await store.has('jti-b')).toBe(false)
  })

  it('clear() is synchronous — it returns undefined, not a promise', () => {
    expect(store.clear()).toBeUndefined()
  })

  it('clear() on an empty store is a no-op', async () => {
    store.clear()
    expect(await store.has('jti-a')).toBe(false)
  })

  it('converges when the same JTI is marked concurrently', async () => {
    await Promise.all(
      Array.from({ length: 16 }, () => store.mark('jti-race', 'user-1', TTL))
    )

    expect(await store.has('jti-race')).toBe(true)
  })

  it('keeps separate instances isolated', async () => {
    const other = new InMemoryUsedTokenStore()

    await store.mark('jti-a', 'user-1', TTL)

    expect(await other.has('jti-a')).toBe(false)
    expect(await store.has('jti-a')).toBe(true)
  })

  it('does not initialise with any consumed JTI', async () => {
    expect(await store.has('')).toBe(false)
    expect(await store.has('jti-1')).toBe(false)
    expect(await store.has('undefined')).toBe(false)
  })

  describe('representative invalid and boundary JTI inputs', () => {
    it.each([
      ['an empty string', ''],
      ['whitespace only', '   '],
      ['a 4 KB JTI', `jti_${'x'.repeat(4096)}`],
      ['a non-ascii JTI', 'jti-🔐-ключ-鍵'],
    ])('stores %s literally and treats it as consumed once marked', async (_label, jti) => {
      expect(await store.has(jti)).toBe(false)

      await store.mark(jti, 'user-1', TTL)

      expect(await store.has(jti)).toBe(true)
    })

    it('treats a non-string JTI as an opaque value — the store performs no validation', async () => {
      const nonString = undefined as unknown as string

      expect(await store.has(nonString)).toBe(false)

      await store.mark(nonString, 'user-1', TTL)

      expect(await store.has(nonString)).toBe(true)
      // Values are stored by identity, never coerced to a string first.
      expect(await store.has('undefined')).toBe(false)
    })
  })
})

// ---------------------------------------------------------------------------
// DbUsedTokenStore
// ---------------------------------------------------------------------------

describe('DbUsedTokenStore', () => {
  let store: DbUsedTokenStore

  beforeEach(() => {
    mockQuery.mockReset()
    mockLoggerError.mockReset()
    store = new DbUsedTokenStore()
  })

  describe('has()', () => {
    it('returns false when DB returns no rows', async () => {
      mockQuery.mockResolvedValueOnce(queryResult(0))
      expect(await store.has('jti-x')).toBe(false)
    })

    it('returns true when DB returns a row', async () => {
      mockQuery.mockResolvedValueOnce(queryResult(1, [{ '?column?': 1 }]))
      expect(await store.has('jti-x')).toBe(true)
    })

    it('queries used_refresh_tokens with the JTI as a bound parameter', async () => {
      mockQuery.mockResolvedValueOnce(queryResult(0))

      await store.has('my-jti')

      expect(mockQuery).toHaveBeenCalledWith(
        'SELECT 1 FROM used_refresh_tokens WHERE jti = $1 LIMIT 1',
        ['my-jti']
      )
    })

    it('falls back to "not consumed" when the driver omits rowCount', async () => {
      // rowCount is nullable in pg; a nullish value is treated as 0 rows.
      mockQuery.mockResolvedValueOnce(queryResult(null, [{ '?column?': 1 }]))
      expect(await store.has('jti-x')).toBe(false)
    })

    it('propagates DB errors so callers can fail closed', async () => {
      const dbError = new Error('pool exhausted')
      mockQuery.mockRejectedValueOnce(dbError)

      await expect(store.has('jti-x')).rejects.toBe(dbError)
      expect(mockLoggerError).not.toHaveBeenCalled()
    })

    it('does not cache between calls', async () => {
      mockQuery.mockResolvedValueOnce(queryResult(0))
      expect(await store.has('jti-x')).toBe(false)

      mockQuery.mockResolvedValueOnce(queryResult(1))
      expect(await store.has('jti-x')).toBe(true)

      expect(mockQuery).toHaveBeenCalledTimes(2)
    })
  })

  describe('mark()', () => {
    it('executes an INSERT with jti, userId, and expiresAt', async () => {
      mockQuery.mockResolvedValueOnce(queryResult(1))
      const exp = new Date('2033-01-01T00:00:00Z')
      await store.mark('jti-y', 'user-42', exp)

      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO used_refresh_tokens'),
        ['jti-y', 'user-42', exp]
      )
    })

    it('lets the database absorb duplicate JTIs via ON CONFLICT DO NOTHING', async () => {
      mockQuery.mockResolvedValueOnce(queryResult(0))

      await store.mark('jti-y', 'user-42', TTL)

      const [sql] = mockQuery.mock.calls[0] as [string, unknown[]]
      expect(sql.replace(/\s+/g, ' ')).toContain(
        'INSERT INTO used_refresh_tokens (jti, user_id, expires_at) VALUES ($1, $2, $3) ON CONFLICT (jti) DO NOTHING'
      )
    })

    it('resolves to undefined and does not log on success', async () => {
      mockQuery.mockResolvedValueOnce(queryResult(1))

      await expect(store.mark('jti-y', 'user-42', TTL)).resolves.toBeUndefined()
      expect(mockLoggerError).not.toHaveBeenCalled()
    })

    it('resolves only after the INSERT settles', async () => {
      let releaseInsert: () => void = () => {}
      mockQuery.mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            releaseInsert = () => resolve(queryResult(1))
          })
      )

      let settled = false
      const pending = store.mark('jti-slow', 'user-1', TTL).then(() => {
        settled = true
      })

      await Promise.resolve()
      expect(settled).toBe(false)

      releaseInsert()
      await pending
      expect(settled).toBe(true)
    })

    it('re-throws a unique violation (23505) without logging it', async () => {
      const uniqueViolation = Object.assign(new Error('duplicate key'), {
        code: '23505',
      })
      mockQuery.mockRejectedValueOnce(uniqueViolation)

      await expect(store.mark('jti-dup', 'user-1', TTL)).rejects.toBe(uniqueViolation)
      // A concurrent replay is expected traffic, not an operational failure.
      expect(mockLoggerError).not.toHaveBeenCalled()
    })

    it('logs and re-throws other DB errors', async () => {
      const dbError = Object.assign(new Error('connection refused'), {
        code: 'ECONNREFUSED',
      })
      mockQuery.mockRejectedValueOnce(dbError)

      await expect(store.mark('jti-z', 'user-7', TTL)).rejects.toBe(dbError)
      expect(mockLoggerError).toHaveBeenCalledTimes(1)
      expect(mockLoggerError).toHaveBeenCalledWith('DbUsedTokenStore.mark failed', {
        jti: 'jti-z',
        userId: 'user-7',
        error: dbError,
      })
    })

    it('logs and re-throws non-Error rejections', async () => {
      mockQuery.mockRejectedValueOnce('boom')

      await expect(store.mark('jti-str', 'user-1', TTL)).rejects.toBe('boom')
      expect(mockLoggerError).toHaveBeenCalledWith('DbUsedTokenStore.mark failed', {
        jti: 'jti-str',
        userId: 'user-1',
        error: 'boom',
      })
    })

    it('passes the expiry through untouched so rows self-expire', async () => {
      const table = installFakeDatabase()

      await store.mark('jti-ttl', 'user-9', TTL)

      expect(table.get('jti-ttl')).toEqual({ userId: 'user-9', expiresAt: TTL })
    })
  })

  describe('clear()', () => {
    it('deletes every row', async () => {
      mockQuery.mockResolvedValueOnce(queryResult(2))

      await expect(store.clear()).resolves.toBeUndefined()
      expect(mockQuery).toHaveBeenCalledWith('DELETE FROM used_refresh_tokens')
    })

    it('propagates DB errors', async () => {
      const dbError = new Error('read-only transaction')
      mockQuery.mockRejectedValueOnce(dbError)

      await expect(store.clear()).rejects.toBe(dbError)
      expect(mockLoggerError).not.toHaveBeenCalled()
    })
  })
})

// ---------------------------------------------------------------------------
// Singleton selection
// ---------------------------------------------------------------------------

describe('default store selection', () => {
  it('exposes an empty InMemoryUsedTokenStore until setUsedTokenStore() is called', async () => {
    vi.resetModules()

    const fresh = await import('../../../../src/services/auth/usedTokenStore.js')

    expect(fresh.getUsedTokenStore()).toBeInstanceOf(fresh.InMemoryUsedTokenStore)
    expect(await fresh.getUsedTokenStore().has('jti-1')).toBe(false)
  })
})

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

  it('returns a stable reference across calls', () => {
    const store = new InMemoryUsedTokenStore()
    setUsedTokenStore(store)

    expect(getUsedTokenStore()).toBe(getUsedTokenStore())
  })

  it('swaps by reference — a re-instated store keeps its consumed JTIs', async () => {
    const original = new InMemoryUsedTokenStore()
    setUsedTokenStore(original)
    await getUsedTokenStore().mark('jti-kept', 'user-1', TTL)

    const replacement = new InMemoryUsedTokenStore()
    setUsedTokenStore(replacement)
    expect(await getUsedTokenStore().has('jti-kept')).toBe(false)

    setUsedTokenStore(original)
    expect(await getUsedTokenStore().has('jti-kept')).toBe(true)
  })

  it('accepts a DbUsedTokenStore as the production store', async () => {
    installFakeDatabase()
    setUsedTokenStore(new DbUsedTokenStore())

    try {
      await getUsedTokenStore().mark('jti-prod', 'user-1', TTL)

      expect(await getUsedTokenStore().has('jti-prod')).toBe(true)
    } finally {
      // Leave the module-level singleton in a clean state for other consumers.
      setUsedTokenStore(new InMemoryUsedTokenStore())
    }
  })
})
