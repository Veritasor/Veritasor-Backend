/**
 * Tests for src/db/migrate.ts
 * Covers: discoverMigrations, getUpSql, getDownSql, runMigrations, runRollback,
 *         timeout guards (lock_timeout / statement_timeout), overrides, audit.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { fileURLToPath } from 'node:url'

// ─── Mock node:fs/promises before importing the module ───────────────────────
vi.mock('node:fs/promises', () => ({
  readdir: vi.fn(),
  readFile: vi.fn(),
  access:  vi.fn(),
}))

vi.mock('../../src/utils/logger.js', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}))

import * as fsp from 'node:fs/promises'
import { logger } from '../../src/utils/logger.js'
import {
  discoverMigrations,
  getUpSql,
  getDownSql,
  runMigrations,
  runRollback,
  MIGRATIONS_DIR,
  parseDurationMs,
  parseMigrationTimeoutOverrides,
  resolveMigrationTimeouts,
  assertSafeTimeoutMs,
  applyMigrationTimeouts,
  classifyTimeoutBreach,
  emitMigrationTimeoutAudit,
  MigrationTimeoutError,
  DEFAULT_MIGRATION_LOCK_TIMEOUT_MS,
  DEFAULT_MIGRATION_STATEMENT_TIMEOUT_MS,
  MAX_MIGRATION_TIMEOUT_MS,
  PG_LOCK_NOT_AVAILABLE,
  PG_QUERY_CANCELED,
} from '../../src/db/migrate'

const mockReaddir = fsp.readdir  as ReturnType<typeof vi.fn>
const mockReadFile = fsp.readFile as ReturnType<typeof vi.fn>
const mockAccess  = fsp.access   as ReturnType<typeof vi.fn>

// ─── Mock pg client factory ──────────────────────────────────────────────────
function makeMockClient(defaultRows: { version: string }[] = []) {
  const calls: string[] = []

  const query = vi.fn(async (sql: string) => {
    calls.push(sql.trim())
    if (sql.includes('SELECT version FROM schema_migrations')) {
      return { rows: defaultRows }
    }
    return { rows: [] }
  })

  const client = { query, calls }
  return client
}

// helper: override query AND keep recording calls
function withQueryImpl(
  client: ReturnType<typeof makeMockClient>,
  impl: (sql: string, params?: unknown[]) => Promise<{ rows: unknown[] }>
) {
  client.query.mockImplementation(async (sql: string, params?: unknown[]) => {
    client.calls.push(sql.trim())
    return impl(sql, params)
  })
}

function stubLegacyMigration(sql = 'CREATE TABLE x();') {
  mockReaddir.mockResolvedValue(['001_users.sql'])
  mockAccess
    .mockRejectedValueOnce(new Error()) // .up.sql missing
    .mockResolvedValueOnce(undefined)   // legacy .sql exists
  mockReadFile.mockResolvedValue(sql)
}

// ─── discoverMigrations ───────────────────────────────────────────────────────
describe('discoverMigrations', () => {
  beforeEach(() => vi.clearAllMocks())

  it('discovers legacy .sql files', async () => {
    mockReaddir.mockResolvedValue(['001_users.sql', '002_posts.sql'])
    expect(await discoverMigrations('/fake')).toEqual(['001_users', '002_posts'])
  })

  it('discovers paired .up.sql files and ignores .down.sql', async () => {
    mockReaddir.mockResolvedValue(['001_users.up.sql', '001_users.down.sql'])
    expect(await discoverMigrations('/fake')).toEqual(['001_users'])
  })

  it('deduplicates when both legacy and .up.sql somehow coexist', async () => {
    mockReaddir.mockResolvedValue(['001_users.sql', '001_users.up.sql'])
    expect(await discoverMigrations('/fake')).toEqual(['001_users'])
  })

  it('returns results sorted ascending', async () => {
    mockReaddir.mockResolvedValue(['003_c.sql', '001_a.sql', '002_b.sql'])
    expect(await discoverMigrations('/fake')).toEqual(['001_a', '002_b', '003_c'])
  })

  it('returns empty array when no migration files exist', async () => {
    mockReaddir.mockResolvedValue(['README.md', 'seed.js'])
    expect(await discoverMigrations('/fake')).toEqual([])
  })
})

// ─── getUpSql ────────────────────────────────────────────────────────────────
describe('getUpSql', () => {
  beforeEach(() => vi.clearAllMocks())

  it('reads .up.sql when it exists', async () => {
    mockAccess.mockResolvedValue(undefined)
    mockReadFile.mockResolvedValue('CREATE TABLE foo();')
    const sql = await getUpSql('001_foo', '/fake')
    expect(sql).toBe('CREATE TABLE foo();')
    expect(mockAccess).toHaveBeenCalledWith(expect.stringContaining('001_foo.up.sql'))
  })

  it('falls back to legacy .sql when .up.sql is absent', async () => {
    mockAccess
      .mockRejectedValueOnce(new Error('not found'))
      .mockResolvedValueOnce(undefined)
    mockReadFile.mockResolvedValue('CREATE TABLE bar();')
    const sql = await getUpSql('001_bar', '/fake')
    expect(sql).toBe('CREATE TABLE bar();')
    expect(mockAccess).toHaveBeenCalledWith(expect.stringContaining('001_bar.sql'))
  })

  it('throws when neither .up.sql nor legacy .sql exists', async () => {
    mockAccess.mockRejectedValue(new Error('not found'))
    await expect(getUpSql('999_missing', '/fake')).rejects.toThrow(
      'No up-migration file found for version: 999_missing'
    )
  })
})

// ─── getDownSql ──────────────────────────────────────────────────────────────
describe('getDownSql', () => {
  beforeEach(() => vi.clearAllMocks())

  it('reads .down.sql when it exists', async () => {
    mockAccess.mockResolvedValue(undefined)
    mockReadFile.mockResolvedValue('DROP TABLE foo;')
    expect(await getDownSql('001_foo', '/fake')).toBe('DROP TABLE foo;')
  })

  it('throws a clear error when .down.sql is missing', async () => {
    mockAccess.mockRejectedValue(new Error('not found'))
    await expect(getDownSql('001_foo', '/fake')).rejects.toThrow(
      'Cannot roll back "001_foo"'
    )
  })

  it('error message includes the missing filename', async () => {
    mockAccess.mockRejectedValue(new Error('not found'))
    await expect(getDownSql('001_foo', '/fake')).rejects.toThrow('001_foo.down.sql')
  })
})

// ─── timeout helpers ─────────────────────────────────────────────────────────
describe('parseDurationMs', () => {
  it('parses bare milliseconds', () => {
    expect(parseDurationMs('5000')).toBe(5000)
  })

  it('parses unit suffixes', () => {
    expect(parseDurationMs('5s')).toBe(5_000)
    expect(parseDurationMs('2m')).toBe(120_000)
    expect(parseDurationMs('500ms')).toBe(500)
    expect(parseDurationMs('1.5s')).toBe(1_500)
  })

  it('rejects empty and malformed values', () => {
    expect(() => parseDurationMs('')).toThrow(/empty/)
    expect(() => parseDurationMs('5 hours')).toThrow(/Invalid duration/)
    expect(() => parseDurationMs('abc')).toThrow(/Invalid duration/)
  })
})

describe('assertSafeTimeoutMs', () => {
  it('accepts zero and positive integers within the ceiling', () => {
    expect(assertSafeTimeoutMs(0, 'x')).toBe(0)
    expect(assertSafeTimeoutMs(MAX_MIGRATION_TIMEOUT_MS, 'x')).toBe(MAX_MIGRATION_TIMEOUT_MS)
  })

  it('rejects negatives, floats, and values above the ceiling', () => {
    expect(() => assertSafeTimeoutMs(-1, 'x')).toThrow(/Invalid x/)
    expect(() => assertSafeTimeoutMs(1.5, 'x')).toThrow(/Invalid x/)
    expect(() => assertSafeTimeoutMs(MAX_MIGRATION_TIMEOUT_MS + 1, 'x')).toThrow(/Invalid x/)
  })
})

describe('parseMigrationTimeoutOverrides', () => {
  it('parses leading @lock_timeout_ms and @statement_timeout_ms comments', () => {
    const sql = `
-- @lock_timeout_ms 3000
-- @statement_timeout_ms 0
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx ON t(id);
`.trim()
    expect(parseMigrationTimeoutOverrides(sql)).toEqual({
      lockTimeoutMs: 3000,
      statementTimeoutMs: 0,
    })
  })

  it('accepts unit suffixes and alternate directive names', () => {
    const sql = `
-- @lock_timeout 5s
-- @statement_timeout: 10m
ALTER TABLE t ADD COLUMN x int;
`.trim()
    expect(parseMigrationTimeoutOverrides(sql)).toEqual({
      lockTimeoutMs: 5_000,
      statementTimeoutMs: 600_000,
    })
  })

  it('stops at the first non-comment line (ignores mid-file comments)', () => {
    const sql = `
CREATE TABLE t(id int);
-- @lock_timeout_ms 1
`.trim()
    expect(parseMigrationTimeoutOverrides(sql)).toEqual({})
  })

  it('rejects unsafe override values', () => {
    expect(() =>
      parseMigrationTimeoutOverrides('-- @lock_timeout_ms -5\nSELECT 1;')
    ).toThrow(/Invalid/)
  })
})

describe('resolveMigrationTimeouts', () => {
  const ORIGINAL = { ...process.env }

  afterEach(() => {
    process.env.MIGRATION_LOCK_TIMEOUT_MS = ORIGINAL.MIGRATION_LOCK_TIMEOUT_MS
    process.env.MIGRATION_STATEMENT_TIMEOUT_MS = ORIGINAL.MIGRATION_STATEMENT_TIMEOUT_MS
    if (ORIGINAL.MIGRATION_LOCK_TIMEOUT_MS === undefined) delete process.env.MIGRATION_LOCK_TIMEOUT_MS
    if (ORIGINAL.MIGRATION_STATEMENT_TIMEOUT_MS === undefined) {
      delete process.env.MIGRATION_STATEMENT_TIMEOUT_MS
    }
  })

  it('uses documented defaults when env and overrides are absent', () => {
    delete process.env.MIGRATION_LOCK_TIMEOUT_MS
    delete process.env.MIGRATION_STATEMENT_TIMEOUT_MS
    expect(resolveMigrationTimeouts({}, {})).toEqual({
      lockTimeoutMs: DEFAULT_MIGRATION_LOCK_TIMEOUT_MS,
      statementTimeoutMs: DEFAULT_MIGRATION_STATEMENT_TIMEOUT_MS,
    })
  })

  it('reads env defaults', () => {
    expect(
      resolveMigrationTimeouts({}, {
        MIGRATION_LOCK_TIMEOUT_MS: '2500',
        MIGRATION_STATEMENT_TIMEOUT_MS: '120000',
      })
    ).toEqual({ lockTimeoutMs: 2500, statementTimeoutMs: 120_000 })
  })

  it('prefers explicit overrides over env', () => {
    expect(
      resolveMigrationTimeouts(
        { lockTimeoutMs: 100, statementTimeoutMs: 0 },
        { MIGRATION_LOCK_TIMEOUT_MS: '9999', MIGRATION_STATEMENT_TIMEOUT_MS: '9999' }
      )
    ).toEqual({ lockTimeoutMs: 100, statementTimeoutMs: 0 })
  })

  it('rejects invalid env values', () => {
    expect(() =>
      resolveMigrationTimeouts({}, { MIGRATION_LOCK_TIMEOUT_MS: 'nope' })
    ).toThrow(/MIGRATION_LOCK_TIMEOUT_MS/)
  })
})

describe('applyMigrationTimeouts', () => {
  it('issues SET LOCAL for lock and statement timeouts with integer ms', async () => {
    const client = makeMockClient()
    await applyMigrationTimeouts(client as never, {
      lockTimeoutMs: 5_000,
      statementTimeoutMs: 60_000,
    })
    expect(client.calls).toEqual([
      'SET LOCAL lock_timeout = 5000',
      'SET LOCAL statement_timeout = 60000',
    ])
  })

  it('allows statement_timeout = 0 for long index builds', async () => {
    const client = makeMockClient()
    await applyMigrationTimeouts(client as never, {
      lockTimeoutMs: 5_000,
      statementTimeoutMs: 0,
    })
    expect(client.calls).toContain('SET LOCAL statement_timeout = 0')
    expect(client.calls).toContain('SET LOCAL lock_timeout = 5000')
  })
})

describe('classifyTimeoutBreach', () => {
  it('classifies PostgreSQL lock_timeout (55P03)', () => {
    expect(classifyTimeoutBreach({ code: PG_LOCK_NOT_AVAILABLE, message: 'canceling statement due to lock timeout' }))
      .toBe('lock_timeout')
  })

  it('classifies PostgreSQL statement_timeout (57014)', () => {
    expect(classifyTimeoutBreach({ code: PG_QUERY_CANCELED, message: 'canceling statement due to statement timeout' }))
      .toBe('statement_timeout')
  })

  it('falls back to message matching when code is absent', () => {
    expect(classifyTimeoutBreach({ message: 'ERROR: lock timeout' })).toBe('lock_timeout')
    expect(classifyTimeoutBreach({ message: 'canceling statement due to statement timeout' }))
      .toBe('statement_timeout')
  })

  it('returns null for unrelated errors', () => {
    expect(classifyTimeoutBreach({ code: '23505', message: 'duplicate key' })).toBeNull()
    expect(classifyTimeoutBreach(null)).toBeNull()
  })
})

describe('emitMigrationTimeoutAudit', () => {
  it('emits a structured audit record via the provided sink', () => {
    const sink = vi.fn()
    const record = emitMigrationTimeoutAudit(
      {
        version: '001_users',
        direction: 'up',
        breach: 'lock_timeout',
        lockTimeoutMs: 5000,
        statementTimeoutMs: 60000,
        pgCode: PG_LOCK_NOT_AVAILABLE,
        message: 'lock timeout',
        timestamp: '2026-01-01T00:00:00.000Z',
      },
      sink
    )
    expect(record.event).toBe('migration_timeout_breach')
    expect(sink).toHaveBeenCalledWith(record)
  })

  it('defaults to logger.error when no sink is provided', () => {
    emitMigrationTimeoutAudit({
      version: '001_users',
      direction: 'up',
      breach: 'statement_timeout',
      lockTimeoutMs: 5000,
      statementTimeoutMs: 60000,
      message: 'statement timeout',
    })
    expect(logger.error).toHaveBeenCalledWith(
      expect.objectContaining({ event: 'migration_timeout_breach', breach: 'statement_timeout' })
    )
  })
})

// ─── runMigrations ───────────────────────────────────────────────────────────
describe('runMigrations', () => {
  beforeEach(() => vi.clearAllMocks())

  it('applies pending migrations in order', async () => {
    mockReaddir.mockResolvedValue(['001_users.sql', '002_posts.sql'])
    mockAccess
      .mockRejectedValueOnce(new Error()) // 001 .up.sql missing
      .mockResolvedValueOnce(undefined)   // 001 legacy .sql exists
      .mockRejectedValueOnce(new Error()) // 002 .up.sql missing
      .mockResolvedValueOnce(undefined)   // 002 legacy .sql exists
    mockReadFile.mockResolvedValue('CREATE TABLE x();')

    const client = makeMockClient([])
    await runMigrations(client as never, '/fake')

    expect(client.calls).toContain('BEGIN')
    expect(client.calls).toContain('COMMIT')
    expect(client.calls.filter((q) => q === 'COMMIT')).toHaveLength(2)
  })

  it('sets default lock_timeout and statement_timeout before DDL', async () => {
    stubLegacyMigration('CREATE TABLE x();')
    const client = makeMockClient([])
    await runMigrations(client as never, '/fake')

    const beginIdx = client.calls.indexOf('BEGIN')
    const lockIdx = client.calls.findIndex((q) => q.startsWith('SET LOCAL lock_timeout'))
    const stmtIdx = client.calls.findIndex((q) => q.startsWith('SET LOCAL statement_timeout'))
    const ddlIdx = client.calls.findIndex((q) => q.trim() === 'CREATE TABLE x();')

    expect(beginIdx).toBeGreaterThanOrEqual(0)
    expect(lockIdx).toBeGreaterThan(beginIdx)
    expect(stmtIdx).toBeGreaterThan(lockIdx)
    expect(ddlIdx).toBeGreaterThan(stmtIdx)
    expect(client.calls[lockIdx]).toBe(`SET LOCAL lock_timeout = ${DEFAULT_MIGRATION_LOCK_TIMEOUT_MS}`)
    expect(client.calls[stmtIdx]).toBe(
      `SET LOCAL statement_timeout = ${DEFAULT_MIGRATION_STATEMENT_TIMEOUT_MS}`
    )
  })

  it('honours per-migration overrides for long index builds', async () => {
    const sql = `
-- @lock_timeout_ms 5000
-- @statement_timeout_ms 0
CREATE INDEX idx_big ON events (created_at);
`.trim()
    stubLegacyMigration(sql)
    const client = makeMockClient([])
    await runMigrations(client as never, '/fake')

    expect(client.calls).toContain('SET LOCAL lock_timeout = 5000')
    expect(client.calls).toContain('SET LOCAL statement_timeout = 0')
    expect(client.calls).toContain(sql)
    expect(client.calls).toContain('COMMIT')
  })

  it('fails fast on lock_timeout breach, rolls back, and emits audit', async () => {
    stubLegacyMigration('ALTER TABLE users ADD COLUMN x int;')
    const audit = vi.fn()
    const client = makeMockClient([])
    withQueryImpl(client, async (sql) => {
      if (sql.includes('SELECT version FROM schema_migrations')) return { rows: [] }
      if (sql.includes('ALTER TABLE')) {
        const err = Object.assign(new Error('canceling statement due to lock timeout'), {
          code: PG_LOCK_NOT_AVAILABLE,
        })
        throw err
      }
      return { rows: [] }
    })

    await expect(
      runMigrations(client as never, '/fake', { onAudit: audit })
    ).rejects.toSatisfy((err: unknown) => {
      expect(err).toBeInstanceOf(MigrationTimeoutError)
      const e = err as MigrationTimeoutError
      expect(e.breach).toBe('lock_timeout')
      expect(e.version).toBe('001_users')
      expect(e.code).toBe('MIGRATION_TIMEOUT')
      return true
    })

    expect(client.calls).toContain('ROLLBACK')
    expect(client.calls).not.toContain('COMMIT')
    expect(audit).toHaveBeenCalledWith(
      expect.objectContaining({
        event: 'migration_timeout_breach',
        breach: 'lock_timeout',
        version: '001_users',
        direction: 'up',
        pgCode: PG_LOCK_NOT_AVAILABLE,
      })
    )
  })

  it('fails fast on statement_timeout breach and emits audit', async () => {
    stubLegacyMigration('CREATE INDEX idx ON t(id);')
    const audit = vi.fn()
    const client = makeMockClient([])
    withQueryImpl(client, async (sql) => {
      if (sql.includes('SELECT version FROM schema_migrations')) return { rows: [] }
      if (sql.includes('CREATE INDEX')) {
        throw Object.assign(new Error('canceling statement due to statement timeout'), {
          code: PG_QUERY_CANCELED,
        })
      }
      return { rows: [] }
    })

    await expect(
      runMigrations(client as never, '/fake', { onAudit: audit })
    ).rejects.toBeInstanceOf(MigrationTimeoutError)

    expect(audit).toHaveBeenCalledWith(
      expect.objectContaining({
        event: 'migration_timeout_breach',
        breach: 'statement_timeout',
        direction: 'up',
      })
    )
    expect(client.calls).toContain('ROLLBACK')
  })

  it('does not emit timeout audit for unrelated SQL failures', async () => {
    stubLegacyMigration('CREATE TABLE x();')
    const audit = vi.fn()
    const client = makeMockClient([])
    withQueryImpl(client, async (sql) => {
      if (sql.includes('SELECT version FROM schema_migrations')) return { rows: [] }
      if (sql.trim() === 'CREATE TABLE x();') throw new Error('Simulated DB failure')
      return { rows: [] }
    })

    await expect(
      runMigrations(client as never, '/fake', { onAudit: audit })
    ).rejects.toThrow('Simulated DB failure')
    expect(audit).not.toHaveBeenCalled()
    expect(client.calls).toContain('ROLLBACK')
  })

  it('skips already-applied migrations', async () => {
    mockReaddir.mockResolvedValue(['001_users.sql'])
    const client = makeMockClient([{ version: '001_users' }])
    await runMigrations(client as never, '/fake')
    expect(client.calls).not.toContain('BEGIN')
  })

  it('prints "No pending migrations" when all are applied', async () => {
    mockReaddir.mockResolvedValue(['001_users.sql'])
    const client = makeMockClient([{ version: '001_users' }])
    const spy = vi.spyOn(console, 'log').mockImplementation(() => {})
    await runMigrations(client as never, '/fake')
    expect(spy).toHaveBeenCalledWith('No pending migrations.')
    spy.mockRestore()
  })

  it('rolls back transaction and throws on SQL failure', async () => {
    mockReaddir.mockResolvedValue(['001_users.sql'])
    mockAccess
      .mockRejectedValueOnce(new Error()) // .up.sql missing
      .mockResolvedValueOnce(undefined)   // legacy .sql exists
    mockReadFile.mockResolvedValue('CREATE TABLE x();')

    const client = makeMockClient([])
    withQueryImpl(client, async (sql) => {
      if (sql.includes('SELECT version FROM schema_migrations')) return { rows: [] }
      if (sql.trim() === 'CREATE TABLE x();') throw new Error('Simulated DB failure')
      return { rows: [] }
    })

    await expect(runMigrations(client as never, '/fake')).rejects.toThrow('Simulated DB failure')
    expect(client.calls).toContain('ROLLBACK')
  })

  it('applies run-level timeout options when file has none', async () => {
    stubLegacyMigration('CREATE TABLE x();')
    const client = makeMockClient([])
    await runMigrations(client as never, '/fake', {
      timeouts: { lockTimeoutMs: 1500, statementTimeoutMs: 45_000 },
    })
    expect(client.calls).toContain('SET LOCAL lock_timeout = 1500')
    expect(client.calls).toContain('SET LOCAL statement_timeout = 45000')
  })
})

// ─── runRollback ─────────────────────────────────────────────────────────────
describe('runRollback', () => {
  beforeEach(() => vi.clearAllMocks())

  it('rolls back the most recent migration', async () => {
    mockAccess.mockResolvedValue(undefined)
    mockReadFile.mockResolvedValue('DROP TABLE users;')

    const client = makeMockClient([])
    withQueryImpl(client, async (sql) => {
      if (sql.includes('SELECT version FROM schema_migrations')) {
        return { rows: [{ version: '001_users' }] }
      }
      return { rows: [] }
    })

    await runRollback(client as never, 1, '/fake')

    expect(client.calls).toContain('BEGIN')
    expect(client.calls).toContain('COMMIT')
    expect(client.calls).toContain('DELETE FROM schema_migrations WHERE version = $1')
  })

  it('applies timeout guards during rollback', async () => {
    mockAccess.mockResolvedValue(undefined)
    mockReadFile.mockResolvedValue('DROP TABLE users;')

    const client = makeMockClient([])
    withQueryImpl(client, async (sql) => {
      if (sql.includes('SELECT version FROM schema_migrations')) {
        return { rows: [{ version: '001_users' }] }
      }
      return { rows: [] }
    })

    await runRollback(client as never, 1, '/fake')
    expect(client.calls).toContain(`SET LOCAL lock_timeout = ${DEFAULT_MIGRATION_LOCK_TIMEOUT_MS}`)
    expect(client.calls).toContain(
      `SET LOCAL statement_timeout = ${DEFAULT_MIGRATION_STATEMENT_TIMEOUT_MS}`
    )
  })

  it('emits audit and fails fast when rollback hits lock_timeout', async () => {
    mockAccess.mockResolvedValue(undefined)
    mockReadFile.mockResolvedValue('DROP TABLE users;')
    const audit = vi.fn()

    const client = makeMockClient([])
    withQueryImpl(client, async (sql) => {
      if (sql.includes('SELECT version FROM schema_migrations')) {
        return { rows: [{ version: '001_users' }] }
      }
      if (sql.trim() === 'DROP TABLE users;') {
        throw Object.assign(new Error('canceling statement due to lock timeout'), {
          code: PG_LOCK_NOT_AVAILABLE,
        })
      }
      return { rows: [] }
    })

    await expect(
      runRollback(client as never, 1, '/fake', { onAudit: audit })
    ).rejects.toBeInstanceOf(MigrationTimeoutError)

    expect(audit).toHaveBeenCalledWith(
      expect.objectContaining({
        event: 'migration_timeout_breach',
        direction: 'down',
        breach: 'lock_timeout',
        version: '001_users',
      })
    )
    expect(client.calls).toContain('ROLLBACK')
  })

  it('does nothing when schema_migrations is empty', async () => {
    const client = makeMockClient([])
    const spy = vi.spyOn(console, 'log').mockImplementation(() => {})
    await runRollback(client as never, 1, '/fake')
    expect(spy).toHaveBeenCalledWith('Nothing to roll back.')
    spy.mockRestore()
  })

  it('refuses rollback when .down.sql is missing', async () => {
    mockAccess.mockRejectedValue(new Error('not found'))
    const client = makeMockClient([])
    withQueryImpl(client, async (sql) => {
      if (sql.includes('SELECT version FROM schema_migrations')) {
        return { rows: [{ version: '001_users' }] }
      }
      return { rows: [] }
    })
    await expect(runRollback(client as never, 1, '/fake')).rejects.toThrow('Cannot roll back')
    expect(client.calls).not.toContain('BEGIN')
  })

  it('supports multi-step rollback', async () => {
    mockAccess.mockResolvedValue(undefined)
    mockReadFile.mockResolvedValue('DROP TABLE x;')

    const client = makeMockClient([])
    withQueryImpl(client, async (sql) => {
      if (sql.includes('SELECT version FROM schema_migrations')) {
        return { rows: [{ version: '002_b' }, { version: '001_a' }] }
      }
      return { rows: [] }
    })

    await runRollback(client as never, 2, '/fake')
    expect(client.calls.filter((s) => s === 'COMMIT')).toHaveLength(2)
  })

  it('rolls back transaction and throws on mid-rollback DB failure', async () => {
    mockAccess.mockResolvedValue(undefined)
    mockReadFile.mockResolvedValue('DROP TABLE users;')

    const client = makeMockClient([])
    withQueryImpl(client, async (sql) => {
      if (sql.includes('SELECT version FROM schema_migrations')) {
        return { rows: [{ version: '001_users' }] }
      }
      if (sql.trim() === 'DROP TABLE users;') throw new Error('Simulated DB failure')
      return { rows: [] }
    })

    await expect(runRollback(client as never, 1, '/fake')).rejects.toThrow('Rollback failed')
    expect(client.calls).toContain('ROLLBACK')
  })

  it('validates ALL down files exist before touching the DB', async () => {
    mockAccess
      .mockResolvedValueOnce(undefined)
      .mockRejectedValueOnce(new Error('missing'))

    const client = makeMockClient([])
    withQueryImpl(client, async (sql) => {
      if (sql.includes('SELECT version FROM schema_migrations')) {
        return { rows: [{ version: '002_b' }, { version: '001_a' }] }
      }
      return { rows: [] }
    })

    await expect(runRollback(client as never, 2, '/fake')).rejects.toThrow('Cannot roll back')
    expect(client.calls).not.toContain('BEGIN')
  })
})

describe('MIGRATIONS_DIR', () => {
  it('points at the migrations directory under src/db', () => {
    expect(MIGRATIONS_DIR).toMatch(/migrations$/)
  })
})

describe('CLI helpers', () => {
  it('isMigrateCliEntrypoint compares argv path to module URL', async () => {
    const { isMigrateCliEntrypoint } = await import('../../src/db/migrate')
    const moduleUrl = import.meta.url
    const selfPath = fileURLToPath(moduleUrl)
    expect(isMigrateCliEntrypoint(selfPath, moduleUrl)).toBe(true)
    expect(isMigrateCliEntrypoint(undefined, moduleUrl)).toBe(false)
    expect(isMigrateCliEntrypoint('/other/path', moduleUrl)).toBe(false)
  })

  it('handleMigrateCliFailure logs and exits', async () => {
    const { handleMigrateCliFailure } = await import('../../src/db/migrate')
    const exitFn = vi.fn(() => {
      throw new Error('exited')
    }) as unknown as (code: number) => never
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {})

    await expect(handleMigrateCliFailure(new Error('boom'), exitFn)).rejects.toThrow('exited')
    expect(errSpy).toHaveBeenCalledWith('Fatal:', 'boom')
    expect(exitFn).toHaveBeenCalledWith(1)
    errSpy.mockRestore()
  })

  it('runMigrateCli exits when DATABASE_URL is missing', async () => {
    const { runMigrateCli } = await import('../../src/db/migrate')
    const exitFn = vi.fn(() => {
      throw new Error('exited')
    }) as unknown as (code: number) => never
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {})

    await expect(runMigrateCli({}, ['node', 'migrate.ts'], exitFn)).rejects.toThrow('exited')
    expect(errSpy).toHaveBeenCalledWith('DATABASE_URL is required.')
    expect(exitFn).toHaveBeenCalledWith(1)
    errSpy.mockRestore()
  })

  it('runMigrateCli connects and runs migrations', async () => {
    const { runMigrateCli } = await import('../../src/db/migrate')
    mockReaddir.mockResolvedValue([])
    const connect = vi.fn(async () => {})
    const end = vi.fn(async () => {})
    const query = vi.fn(async (sql: string) => {
      if (sql.includes('SELECT version FROM schema_migrations')) return { rows: [] }
      return { rows: [] }
    })
    class FakeClient {
      connect = connect
      end = end
      query = query
      constructor(_opts: { connectionString: string }) {}
    }

    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {})
    await runMigrateCli(
      { DATABASE_URL: 'postgresql://localhost/test' },
      ['node', 'migrate.ts'],
      ((() => {
        throw new Error('should not exit')
      }) as never),
      FakeClient as never
    )
    expect(connect).toHaveBeenCalled()
    expect(end).toHaveBeenCalled()
    expect(logSpy).toHaveBeenCalledWith('No pending migrations.')
    logSpy.mockRestore()
  })

  it('runMigrateCli runs rollback when argv requests it', async () => {
    const { runMigrateCli } = await import('../../src/db/migrate')
    const connect = vi.fn(async () => {})
    const end = vi.fn(async () => {})
    const query = vi.fn(async (sql: string) => {
      if (sql.includes('SELECT version FROM schema_migrations')) return { rows: [] }
      return { rows: [] }
    })
    class FakeClient {
      connect = connect
      end = end
      query = query
      constructor(_opts: { connectionString: string }) {}
    }

    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {})
    await runMigrateCli(
      { DATABASE_URL: 'postgresql://localhost/test' },
      ['node', 'migrate.ts', 'rollback', '2'],
      ((() => {
        throw new Error('should not exit')
      }) as never),
      FakeClient as never
    )
    expect(connect).toHaveBeenCalled()
    expect(end).toHaveBeenCalled()
    expect(logSpy).toHaveBeenCalledWith('Nothing to roll back.')
    logSpy.mockRestore()
  })
})
