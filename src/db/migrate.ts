/**
 * Migration runner: applies pending SQL migrations and supports rollback.
 * Tracks applied migrations in schema_migrations so each runs once.
 *
 * Usage:
 *   npm run migrate              – apply all pending migrations
 *   npm run migrate:rollback     – roll back the last 1 migration
 *   npm run migrate:rollback 3   – roll back the last 3 migrations
 *
 * File conventions (both supported):
 *   Legacy:  001_foo.sql          → up-only, no rollback available
 *   Paired:  001_foo.up.sql  +  001_foo.down.sql  → supports rollback
 */

import pg from 'pg'
import { readdir, readFile, access } from 'node:fs/promises'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
export const MIGRATIONS_DIR = join(__dirname, 'migrations')

// ─── helpers ────────────────────────────────────────────────────────────────

/** Returns all unique migration versions, sorted ascending. */
export async function discoverMigrations(dir: string = MIGRATIONS_DIR): Promise<string[]> {
  const files = await readdir(dir)
  const versions = new Set<string>()

  for (const f of files) {
    if (f.endsWith('.up.sql')) {
      versions.add(f.replace(/\.up\.sql$/, ''))
    } else if (f.endsWith('.sql') && !f.endsWith('.down.sql')) {
      // legacy up-only file
      versions.add(f.replace(/\.sql$/, ''))
    }
  }

  return [...versions].sort()
}

/** Reads the UP sql for a version. Prefers .up.sql, falls back to legacy .sql */
export async function getUpSql(version: string, dir: string = MIGRATIONS_DIR): Promise<string> {
  const upPath = join(dir, `${version}.up.sql`)
  try {
    await access(upPath)
    return readFile(upPath, 'utf-8')
  } catch {
    // try legacy
    const legacyPath = join(dir, `${version}.sql`)
    try {
      await access(legacyPath)
      return readFile(legacyPath, 'utf-8')
    } catch {
      throw new Error(`No up-migration file found for version: ${version}`)
    }
  }
}

/**
 * Reads the DOWN sql for a version.
 * Throws a clear error if the .down.sql file is missing — rollback is refused.
 */
export async function getDownSql(version: string, dir: string = MIGRATIONS_DIR): Promise<string> {
  const downPath = join(dir, `${version}.down.sql`)
  try {
    await access(downPath)
    return readFile(downPath, 'utf-8')
  } catch {
    throw new Error(
      `Cannot roll back "${version}": missing ${version}.down.sql — ` +
      `create this file to enable rollback for this migration.`
    )
  }
}

// ─── core logic ─────────────────────────────────────────────────────────────

export async function runMigrations(client: pg.Client, dir: string = MIGRATIONS_DIR): Promise<void> {
  await client.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version TEXT PRIMARY KEY,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `)

  const versions = await discoverMigrations(dir)
  const applied = new Set(
    (await client.query('SELECT version FROM schema_migrations'))
      .rows.map((r: { version: string }) => r.version)
  )

  const pending = versions.filter((v) => !applied.has(v))

  if (pending.length === 0) {
    console.log('No pending migrations.')
    return
  }

  for (const version of pending) {
    const sql = await getUpSql(version, dir)
    await client.query('BEGIN')
    try {
      await client.query(sql)
      await client.query('INSERT INTO schema_migrations (version) VALUES ($1)', [version])
      await client.query('COMMIT')
      console.log(`Applied: ${version}`)
    } catch (err) {
      await client.query('ROLLBACK')
      throw new Error(`Migration failed for "${version}": ${(err as Error).message}`)
    }
  }
}

export async function runRollback(
  client: pg.Client,
  steps: number = 1,
  dir: string = MIGRATIONS_DIR
): Promise<void> {
  await client.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version TEXT PRIMARY KEY,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `)

  const { rows } = await client.query<{ version: string }>(
    'SELECT version FROM schema_migrations ORDER BY version DESC LIMIT $1',
    [steps]
  )

  if (rows.length === 0) {
    console.log('Nothing to roll back.')
    return
  }

  // Validate ALL .down.sql files exist BEFORE touching the database
  for (const { version } of rows) {
    await getDownSql(version, dir) // throws immediately if missing
  }

  for (const { version } of rows) {
    const sql = await getDownSql(version, dir)
    await client.query('BEGIN')
    try {
      await client.query(sql)
      await client.query('DELETE FROM schema_migrations WHERE version = $1', [version])
      await client.query('COMMIT')
      console.log(`Rolled back: ${version}`)
    } catch (err) {
      await client.query('ROLLBACK')
      throw new Error(`Rollback failed for "${version}": ${(err as Error).message}`)
    }
  }
}

// ─── CLI entry point ─────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const connectionString = process.env.DATABASE_URL
  if (!connectionString) {
    console.error('DATABASE_URL is required.')
    process.exit(1)
  }

  const command = process.argv[2]   // 'rollback' or undefined
  const steps   = parseInt(process.argv[3] ?? '1', 10)

  const client = new pg.Client({ connectionString })
  try {
    await client.connect()
    if (command === 'rollback') {
      await runRollback(client, steps)
    } else {
      await runMigrations(client)
    }
  } finally {
    await client.end()
  }
}

// Only run when executed directly (not when imported in tests)
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main().catch((err) => {
    console.error('Fatal:', err.message)
    process.exit(1)
  })
}