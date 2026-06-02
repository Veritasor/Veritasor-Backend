/**
 * Tests for src/db/migrate.ts
 * Covers: discoverMigrations, getUpSql, getDownSql, runMigrations, runRollback
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'

// ─── Mock node:fs/promises before importing the module ───────────────────────
vi.mock('node:fs/promises', () => ({
  readdir: vi.fn(),
  readFile: vi.fn(),
  access:  vi.fn(),
}))

import * as fsp from 'node:fs/promises'
import {
  discoverMigrations,
  getUpSql,
  getDownSql,
  runMigrations,
  runRollback,
  MIGRATIONS_DIR,
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