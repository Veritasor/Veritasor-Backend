/**
 * tests/unit/repositories/business.test.ts
 *
 * Focused behaviour coverage for src/repositories/business.ts (issue #927).
 *
 * The repository is backed by a module-level in-memory `Map` and exposes the
 * public contract: the `ReportingPeriod` union, the `Business` shape, the
 * `CreateBusinessData` input shape, CRUD helpers, keyset-paginated `list()`
 * (which reads through the Postgres client) and the reminder-bookkeeping
 * helper `setLastReminderSentAt()`.
 *
 * Coverage targets
 * ────────────────
 * • ReportingPeriod  – both union members, defaults, contract boundaries
 * • create           – field mapping, defaults, id/timestamps, copy-on-return
 * • getById(s)       – hit, miss, ordering, mixed Business|Error results
 * • getByUserId      – first match, miss, cross-user isolation
 * • getAll           – empty and populated store
 * • update           – partial updates, null-vs-undefined, updatedAt bump,
 *                      unknown-id failure path, fields the contract ignores
 * • list             – SQL assembly, row mapping, cursor emission/decoding,
 *                      last page, invalid cursor, DB failure propagation
 * • setLastReminderSentAt – null → timestamp transitions, unknown id
 * • clearAll         – full store reset
 *
 * The `db` client is mocked so `list()` is exercised deterministically
 * without a Postgres instance; every other helper runs against the real
 * in-memory store.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import {
  businessRepository,
  create,
  getById,
  getByIds,
  getByUserId,
  getAll,
  list,
  update,
  setLastReminderSentAt,
  clearAll,
  type Business,
  type BusinessListOptions,
  type CreateBusinessData,
  type ReportingPeriod,
} from '../../../src/repositories/business.js'
import { decodeCursor, encodeCursor } from '../../../src/utils/pagination.js'

// ---------------------------------------------------------------------------
// Mocked Postgres client (used only by list())
// ---------------------------------------------------------------------------

const dbQuery = vi.hoisted(() => vi.fn())

vi.mock('../../../src/db/client.js', () => ({
  db: { query: dbQuery },
}))

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Build a valid CreateBusinessData payload. */
function validInput(overrides: Partial<CreateBusinessData> = {}): CreateBusinessData {
  return {
    userId: 'user-1',
    name: 'Acme Corporation',
    email: 'billing@acme.test',
    ...overrides,
  }
}

/** Raw snake_case row shape returned by the `businesses` table. */
interface BusinessRow {
  id: string
  user_id: string
  name: string
  email: string
  industry: string | null
  description: string | null
  website: string | null
  reporting_period?: string | null
  reporting_timezone?: string | null
  last_reminder_sent_at?: string | Date | null
  created_at: string | Date
  updated_at: string | Date
}

/** Build a DB row fixture for list() tests. */
function rowFixture(overrides: Partial<BusinessRow> = {}): BusinessRow {
  return {
    id: 'biz-1',
    user_id: 'user-1',
    name: 'Acme Corporation',
    email: 'billing@acme.test',
    industry: 'Technology',
    description: 'A leading technology company',
    website: 'https://acme.test',
    reporting_period: 'monthly',
    reporting_timezone: 'UTC',
    last_reminder_sent_at: null,
    created_at: '2026-01-01T00:00:00.000Z',
    updated_at: '2026-01-02T00:00:00.000Z',
    ...overrides,
  }
}

const ISO_DATE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

// ---------------------------------------------------------------------------
// Setup / teardown
// ---------------------------------------------------------------------------

beforeEach(() => {
  clearAll()
  dbQuery.mockReset()
  dbQuery.mockResolvedValue({ rows: [] })
})

afterEach(() => {
  vi.useRealTimers()
  vi.restoreAllMocks()
})

// ---------------------------------------------------------------------------
// ReportingPeriod
// ---------------------------------------------------------------------------

describe('ReportingPeriod', () => {
  it('accepts every member of the public union', async () => {
    const periods: ReportingPeriod[] = ['weekly', 'monthly']
    for (const period of periods) {
      const business = await create(validInput({ userId: `user-${period}`, reportingPeriod: period }))
      expect(business.reportingPeriod).toBe(period)
    }
  })

  it("defaults to 'monthly' when reportingPeriod is omitted", async () => {
    const business = await create(validInput())
    expect(business.reportingPeriod).toBe('monthly')
  })

  it("defaults reportingTimezone to 'UTC' when omitted", async () => {
    const business = await create(validInput())
    expect(business.reportingTimezone).toBe('UTC')
  })

  it('persists an explicit reportingTimezone alongside the period', async () => {
    const business = await create(
      validInput({ reportingPeriod: 'weekly', reportingTimezone: 'America/New_York' }),
    )
    expect(business.reportingPeriod).toBe('weekly')
    expect(business.reportingTimezone).toBe('America/New_York')
  })

  it('documents that a value outside the union is stored as given (no runtime discriminator)', async () => {
    // The union is enforced at compile time only; the repository does not
    // validate reportingPeriod at runtime. The database CHECK constraint
    // (businesses_reporting_period_check) is the authoritative guard.
    const outOfContract = 'daily' as unknown as ReportingPeriod
    const business = await create(validInput({ reportingPeriod: outOfContract }))
    expect(business.reportingPeriod).toBe('daily')
  })
})

// ---------------------------------------------------------------------------
// create
// ---------------------------------------------------------------------------

describe('create', () => {
  it('maps required fields and applies defaults for optional ones', async () => {
    const business = await create(validInput())

    expect(business.id).toMatch(UUID)
    expect(business.userId).toBe('user-1')
    expect(business.name).toBe('Acme Corporation')
    expect(business.email).toBe('billing@acme.test')
    expect(business.industry).toBeNull()
    expect(business.description).toBeNull()
    expect(business.website).toBeNull()
    expect(business.reportingPeriod).toBe('monthly')
    expect(business.reportingTimezone).toBe('UTC')
    expect(business.lastReminderSentAt).toBeNull()
  })

  it('keeps explicitly provided optional values', async () => {
    const business = await create(
      validInput({
        industry: 'Technology',
        description: 'A leading technology company',
        website: 'https://acme.test',
      }),
    )
    expect(business.industry).toBe('Technology')
    expect(business.description).toBe('A leading technology company')
    expect(business.website).toBe('https://acme.test')
  })

  it('assigns ISO-8601 createdAt/updatedAt and a unique UUID id', async () => {
    const [first, second] = [await create(validInput()), await create(validInput())]

    expect(first.createdAt).toMatch(ISO_DATE)
    expect(first.updatedAt).toMatch(ISO_DATE)
    expect(first.createdAt).toBe(first.updatedAt)
    expect(first.id).not.toBe(second.id)
    expect(first.id).toMatch(UUID)
    expect(second.id).toMatch(UUID)
  })

  it('returns a defensive copy: mutating the result does not affect stored state', async () => {
    const business = await create(validInput())

    business.name = 'Mutated Corp'
    business.industry = 'Mutated Industry'

    const stored = await getById(business.id)
    expect(stored).not.toBeNull()
    expect(stored!.name).toBe('Acme Corporation')
    expect(stored!.industry).toBeNull()
  })

  it('stores a defensive copy: mutating a later read does not affect the store', async () => {
    const business = await create(validInput())
    const read = await getById(business.id)
    expect(read).not.toBeNull()

    read!.name = 'Mutated Corp'

    expect((await getById(business.id))!.name).toBe('Acme Corporation')
    expect(await getAll()).toHaveLength(1)
  })
})

// ---------------------------------------------------------------------------
// getById / getByIds / getByUserId / getAll
// ---------------------------------------------------------------------------

describe('getById', () => {
  it('returns the business for a known id', async () => {
    const created = await create(validInput())
    const found = await getById(created.id)
    expect(found).toEqual(created)
  })

  it('returns null for an unknown id (failure path)', async () => {
    expect(await getById('no-such-id')).toBeNull()
  })

  it('returns null for an empty store', async () => {
    expect(await getAll()).toEqual([])
    expect(await getById('anything')).toBeNull()
  })
})

describe('getByIds', () => {
  it('resolves each id in input order', async () => {
    const first = await create(validInput({ userId: 'user-a' }))
    const second = await create(validInput({ userId: 'user-b' }))

    const result = await getByIds([second.id, first.id])
    expect(result).toHaveLength(2)
    expect(result[0]).toEqual(second)
    expect(result[1]).toEqual(first)
  })

  it('returns Error instances for missing ids while preserving position', async () => {
    const created = await create(validInput())
    const missing = 'ghost-id'

    const result = await getByIds([created.id, missing, 'another-ghost'])

    expect(result[0]).toEqual(created)
    expect(result[1]).toBeInstanceOf(Error)
    expect((result[1] as Error).message).toBe(`Business not found: ${missing}`)
    expect(result[2]).toBeInstanceOf(Error)
    expect((result[2] as Error).message).toBe('Business not found: another-ghost')
  })

  it('returns only Errors when nothing matches', async () => {
    const result = await getByIds(['ghost-1', 'ghost-2'])
    expect(result).toHaveLength(2)
    for (const entry of result) expect(entry).toBeInstanceOf(Error)
  })
})

describe('getByUserId', () => {
  it('returns the business owned by the user', async () => {
    const created = await create(validInput({ userId: 'owner-42' }))
    expect(await getByUserId('owner-42')).toEqual(created)
  })

  it('returns null when the user owns no business (failure path)', async () => {
    await create(validInput({ userId: 'owner-42' }))
    expect(await getByUserId('stranger')).toBeNull()
  })

  it('does not leak businesses across users', async () => {
    await create(validInput({ userId: 'owner-a' }))
    await create(validInput({ userId: 'owner-b' }))

    const forA = await getByUserId('owner-a')
    const forB = await getByUserId('owner-b')

    expect(forA!.userId).toBe('owner-a')
    expect(forB!.userId).toBe('owner-b')
    expect(forA!.id).not.toBe(forB!.id)
  })
})

describe('getAll', () => {
  it('returns every business in insertion order', async () => {
    const a = await create(validInput({ name: 'Alpha' }))
    const b = await create(validInput({ name: 'Beta' }))
    const c = await create(validInput({ name: 'Gamma' }))

    const all = await getAll()
    expect(all.map(b => b.id)).toEqual([a.id, b.id, c.id])
    expect(all).toHaveLength(3)
  })
})

// ---------------------------------------------------------------------------
// update (primary state transitions)
// ---------------------------------------------------------------------------

describe('update', () => {
  it('applies partial updates while preserving untouched fields', async () => {
    const created = await create(
      validInput({ industry: 'Technology', description: 'Original', website: 'https://acme.test' }),
    )

    const updated = await update(created.id, { name: 'Renamed Corp' })

    expect(updated).not.toBeNull()
    expect(updated!.name).toBe('Renamed Corp')
    expect(updated!.industry).toBe('Technology')
    expect(updated!.description).toBe('Original')
    expect(updated!.website).toBe('https://acme.test')
  })

  it('bumps updatedAt and preserves createdAt (deterministic under a frozen clock)', async () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-03-01T00:00:00.000Z'))
    const created = await create(validInput())
    expect(created.createdAt).toBe('2026-03-01T00:00:00.000Z')

    vi.setSystemTime(new Date('2026-03-15T12:00:00.000Z'))
    const updated = await update(created.id, { description: 'New description' })

    expect(updated).not.toBeNull()
    expect(updated!.createdAt).toBe('2026-03-01T00:00:00.000Z')
    expect(updated!.updatedAt).toBe('2026-03-15T12:00:00.000Z')
    expect(updated!.description).toBe('New description')
  })

  it('distinguishes null (clear the value) from undefined (leave it alone)', async () => {
    const created = await create(validInput({ industry: 'Technology', website: 'https://acme.test' }))

    const cleared = await update(created.id, { industry: null })
    expect(cleared!.industry).toBeNull()
    expect(cleared!.website).toBe('https://acme.test')

    const untouched = await update(created.id, { description: undefined })
    expect(untouched!.industry).toBeNull()
    expect(untouched!.description).toBeNull()
  })

  it('supports sequential transitions and keeps the latest values', async () => {
    const created = await create(validInput({ name: 'Version 1' }))

    const v2 = await update(created.id, { name: 'Version 2' })
    expect(v2!.name).toBe('Version 2')

    const v3 = await update(created.id, { name: 'Version 3', industry: 'Retail' })
    expect(v3!.name).toBe('Version 3')
    expect(v3!.industry).toBe('Retail')
  })

  it('returns null for an unknown id and stores nothing (failure path)', async () => {
    const result = await update('no-such-id', { name: 'Ghost Corp' })
    expect(result).toBeNull()
    expect(await getAll()).toEqual([])
  })

  it('ignores fields the update contract does not cover (email, reportingPeriod)', async () => {
    const created = await create(validInput({ reportingPeriod: 'monthly' }))

    const updated = await update(created.id, {
      email: 'new@acme.test',
      reportingPeriod: 'weekly',
    })

    expect(updated).not.toBeNull()
    expect(updated!.email).toBe('billing@acme.test')
    expect(updated!.reportingPeriod).toBe('monthly')
  })

  it('does not mutate the store when the caller mutates the returned copy', async () => {
    const created = await create(validInput())
    const updated = await update(created.id, { name: 'First Update' })

    updated!.name = 'Tampered'

    expect((await getById(created.id))!.name).toBe('First Update')
  })
})

// ---------------------------------------------------------------------------
// list (keyset pagination through the Postgres client)
// ---------------------------------------------------------------------------

describe('list', () => {
  function baseOptions(overrides: Partial<BusinessListOptions> = {}): BusinessListOptions {
    return { limit: 2, sortBy: 'createdAt', sortOrder: 'asc', ...overrides }
  }

  it('queries the businesses table with keyset-safe ordering and limit+1 lookahead', async () => {
    dbQuery.mockResolvedValueOnce({ rows: [] })

    await list(baseOptions())

    expect(dbQuery).toHaveBeenCalledTimes(1)
    const [sql, params] = dbQuery.mock.calls[0] as [string, unknown[]]
    expect(sql).toContain('FROM businesses')
    expect(sql).toContain('ORDER BY created_at ASC, id ASC')
    expect(sql).toContain('LIMIT $1')
    expect(params).toEqual([3]) // limit + 1 lookahead row, no filters
    expect(sql).not.toContain('WHERE')
  })

  it('maps snake_case rows onto the public Business shape', async () => {
    dbQuery.mockResolvedValueOnce({
      rows: [
        rowFixture({
          last_reminder_sent_at: new Date('2026-02-01T05:06:07.000Z'),
          reporting_period: 'weekly',
          reporting_timezone: 'Europe/Berlin',
        }),
        rowFixture({ id: 'biz-2', reporting_period: undefined, reporting_timezone: undefined }),
      ],
    })

    const result = await list(baseOptions())

    expect(result.items).toHaveLength(2)
    const first: Business = result.items[0]
    expect(first).toEqual({
      id: 'biz-1',
      userId: 'user-1',
      name: 'Acme Corporation',
      email: 'billing@acme.test',
      industry: 'Technology',
      description: 'A leading technology company',
      website: 'https://acme.test',
      reportingPeriod: 'weekly',
      reportingTimezone: 'Europe/Berlin',
      lastReminderSentAt: '2026-02-01T05:06:07.000Z',
      createdAt: '2026-01-01T00:00:00.000Z',
      updatedAt: '2026-01-02T00:00:00.000Z',
    })
    // Missing reporting columns fall back to the documented defaults.
    expect(result.items[1].reportingPeriod).toBe('monthly')
    expect(result.items[1].reportingTimezone).toBe('UTC')
  })

  it('normalises Date columns and null timestamps to ISO strings / null', async () => {
    dbQuery.mockResolvedValueOnce({
      rows: [
        rowFixture({
          created_at: new Date('2026-01-01T00:00:00.000Z'),
          updated_at: new Date('2026-01-02T00:00:00.000Z'),
          industry: null,
          description: null,
          website: null,
        }),
      ],
    })

    const result = await list(baseOptions({ limit: 1 }))
    const item = result.items[0]

    expect(typeof item.createdAt).toBe('string')
    expect(item.createdAt).toBe('2026-01-01T00:00:00.000Z')
    expect(item.updatedAt).toBe('2026-01-02T00:00:00.000Z')
    expect(item.industry).toBeNull()
    expect(item.description).toBeNull()
    expect(item.website).toBeNull()
  })

  it('emits a decodable nextCursor when the page is full', async () => {
    const rows = [
      rowFixture({ id: 'biz-1', created_at: '2026-01-01T00:00:00.000Z' }),
      rowFixture({ id: 'biz-2', created_at: '2026-01-02T00:00:00.000Z' }),
      rowFixture({ id: 'biz-3', created_at: '2026-01-03T00:00:00.000Z' }), // lookahead row
    ]
    dbQuery.mockResolvedValueOnce({ rows })

    const result = await list(baseOptions({ limit: 2, sortBy: 'createdAt', sortOrder: 'asc' }))

    expect(result.items.map(b => b.id)).toEqual(['biz-1', 'biz-2'])
    expect(result.nextCursor).toBeDefined()

    const decoded = decodeCursor(result.nextCursor!)
    expect(decoded).toEqual({ value: '2026-01-02T00:00:00.000Z', id: 'biz-2' })
  })

  it('omits nextCursor on the final page', async () => {
    dbQuery.mockResolvedValueOnce({ rows: [rowFixture()] })

    const result = await list(baseOptions({ limit: 2 }))

    expect(result.items).toHaveLength(1)
    expect(result.nextCursor).toBeUndefined()
  })

  it('uses the sort value of the last item when sorting by name descending', async () => {
    const rows = [
      rowFixture({ id: 'biz-1', name: 'Zeta Ltd' }),
      rowFixture({ id: 'biz-2', name: 'Alpha Ltd' }),
      rowFixture({ id: 'biz-3', name: 'Mu Ltd' }), // lookahead row
    ]
    dbQuery.mockResolvedValueOnce({ rows })

    const result = await list(baseOptions({ limit: 2, sortBy: 'name', sortOrder: 'desc' }))

    expect(result.items.map(b => b.name)).toEqual(['Zeta Ltd', 'Alpha Ltd'])

    const [sql] = dbQuery.mock.calls[0] as [string, unknown[]]
    expect(sql).toContain('ORDER BY name DESC, id DESC')

    expect(decodeCursor(result.nextCursor!)).toEqual({ value: 'Alpha Ltd', id: 'biz-2' })
  })

  it('adds an industry filter as the first positional parameter', async () => {
    dbQuery.mockResolvedValueOnce({ rows: [] })

    await list(baseOptions({ industry: 'Technology' }))

    const [sql, params] = dbQuery.mock.calls[0] as [string, unknown[]]
    expect(sql).toContain('industry = $1')
    expect(sql).toContain('WHERE')
    expect(params).toEqual(['Technology', 3])
  })

  it('advances the keyset predicate from a valid cursor', async () => {
    dbQuery.mockResolvedValueOnce({ rows: [] })
    const cursor = encodeCursor({ value: '2026-01-02T00:00:00.000Z', id: 'biz-2' })

    await list(baseOptions({ limit: 2, cursor }))

    const [sql, params] = dbQuery.mock.calls[0] as [string, unknown[]]
    expect(sql).toContain('(created_at, id) > ($1, $2)')
    expect(params).toEqual(['2026-01-02T00:00:00.000Z', 'biz-2', 3])
  })

  it('reverses the keyset comparison for descending order', async () => {
    dbQuery.mockResolvedValueOnce({ rows: [] })
    const cursor = encodeCursor({ value: 'Beta Ltd', id: 'biz-2' })

    await list(baseOptions({ sortBy: 'name', sortOrder: 'desc', cursor }))

    const [sql, params] = dbQuery.mock.calls[0] as [string, unknown[]]
    expect(sql).toContain('(name, id) < ($1, $2)')
    expect(params).toEqual(['Beta Ltd', 'biz-2', 3])
  })

  it('ignores an undecodable cursor instead of crashing (boundary behaviour)', async () => {
    dbQuery.mockResolvedValueOnce({ rows: [] })

    const result = await list(baseOptions({ cursor: 'not-a-valid-cursor' }))

    const [sql, params] = dbQuery.mock.calls[0] as [string, unknown[]]
    expect(sql).not.toContain('(created_at, id)')
    expect(params).toEqual([3])
    expect(result.items).toEqual([])
    expect(result.nextCursor).toBeUndefined()
  })

  it('propagates database failures to the caller (failure path)', async () => {
    dbQuery.mockRejectedValueOnce(new Error('connection refused'))

    await expect(list(baseOptions())).rejects.toThrow('connection refused')
  })
})

// ---------------------------------------------------------------------------
// setLastReminderSentAt (reminder state transitions)
// ---------------------------------------------------------------------------

describe('setLastReminderSentAt', () => {
  it('transitions lastReminderSentAt from null to a timestamp and bumps updatedAt', async () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-04-01T00:00:00.000Z'))
    const created = await create(validInput())
    expect(created.lastReminderSentAt).toBeNull()
    expect(created.updatedAt).toBe('2026-04-01T00:00:00.000Z')

    vi.setSystemTime(new Date('2026-04-01T10:00:00.000Z'))
    const sentAt = new Date('2026-04-01T09:30:00.000Z').toISOString()
    const ok = await setLastReminderSentAt(created.id, sentAt)

    expect(ok).toBe(true)
    const stored = await getById(created.id)
    expect(stored!.lastReminderSentAt).toBe('2026-04-01T09:30:00.000Z')
    // updatedAt reflects the frozen write time, not the reminder timestamp.
    expect(stored!.updatedAt).toBe('2026-04-01T10:00:00.000Z')
  })

  it('supports repeated reminder transitions (latest timestamp wins)', async () => {
    const created = await create(validInput())

    await setLastReminderSentAt(created.id, '2026-04-01T09:30:00.000Z')
    const ok = await setLastReminderSentAt(created.id, '2026-04-08T09:30:00.000Z')

    expect(ok).toBe(true)
    expect((await getById(created.id))!.lastReminderSentAt).toBe('2026-04-08T09:30:00.000Z')
  })

  it('returns false for an unknown business (failure path)', async () => {
    const ok = await setLastReminderSentAt('no-such-id', '2026-04-01T09:30:00.000Z')
    expect(ok).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// clearAll
// ---------------------------------------------------------------------------

describe('clearAll', () => {
  it('resets the entire store', async () => {
    await create(validInput({ userId: 'user-a' }))
    await create(validInput({ userId: 'user-b' }))
    expect(await getAll()).toHaveLength(2)

    clearAll()

    expect(await getAll()).toEqual([])
    expect(await getByUserId('user-a')).toBeNull()
    expect(await getByIds(['x'])).toEqual([new Error('Business not found: x')])
  })
})

// ---------------------------------------------------------------------------
// businessRepository facade (public export parity)
// ---------------------------------------------------------------------------

describe('businessRepository facade', () => {
  it('exposes the documented API surface', () => {
    expect(businessRepository.create).toBe(create)
    expect(businessRepository.getById).toBe(getById)
    expect(businessRepository.findById).toBe(getById)
    expect(businessRepository.getByUserId).toBe(getByUserId)
    expect(businessRepository.findByUserId).toBe(getByUserId)
    expect(businessRepository.getByIds).toBe(getByIds)
    expect(businessRepository.getAll).toBe(getAll)
    expect(businessRepository.list).toBe(list)
    expect(businessRepository.update).toBe(update)
    expect(businessRepository.setLastReminderSentAt).toBe(setLastReminderSentAt)
    expect(businessRepository.clearAll).toBe(clearAll)
  })

  it('delegates end-to-end through the facade', async () => {
    const created = await businessRepository.create(validInput({ name: 'Facade Corp' }))
    expect((await businessRepository.findById(created.id))!.name).toBe('Facade Corp')

    await businessRepository.update(created.id, { name: 'Facade Corp 2' })
    expect((await businessRepository.findByUserId('user-1'))!.name).toBe('Facade Corp 2')

    businessRepository.clearAll()
    expect(await businessRepository.getAll()).toEqual([])
  })
})
