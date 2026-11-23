/**
 * Migration runner: applies pending SQL migrations and supports rollback.
 * Tracks applied migrations in schema_migrations so each runs once.
 *
 * Timeout guard (issue #571):
 *   Each migration runs inside a transaction with SET LOCAL lock_timeout and
 *   statement_timeout so long-running DDL cannot hold locks and stall traffic.
 *   Defaults are env-tunable; individual SQL files may override via header
 *   comments. Timeout breaches fail fast and emit a structured audit event.
 *
 * Usage:
 *   npm run migrate                    – apply all pending migrations
 *   npm run migrate:rollback           – roll back the last 1 migration
 *   npm run migrate:rollback 3         – roll back the last 3 migrations
 *   npm run migrate:verify-rollback    – dry-run apply+rollback every migration
 *                                         against a scratch database
 *   npm run migrate:verify-rollback -- --only=001_foo,002_bar
 *
 * File conventions (both supported):
 *   Legacy:  001_foo.sql          → up-only, no rollback available
 *   Paired:  001_foo.up.sql  +  001_foo.down.sql  → supports rollback
 *
 * See docs/migration-rollback-verification.md for the verification design.
 */

import pg from 'pg'
import { readdir, readFile, access, appendFile } from 'node:fs/promises'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { logger } from '../utils/logger.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
export const MIGRATIONS_DIR = join(__dirname, 'migrations')

/** Default: fail fast if a lock cannot be acquired within 5 seconds. */
export const DEFAULT_MIGRATION_LOCK_TIMEOUT_MS = 5_000

/**
 * Default: abort a single migration statement after 60 seconds.
 * Override per file (e.g. `@statement_timeout_ms 0`) for long index builds.
 */
export const DEFAULT_MIGRATION_STATEMENT_TIMEOUT_MS = 60_000

/** Hard ceiling to reject absurd / injection-prone override values. */
export const MAX_MIGRATION_TIMEOUT_MS = 24 * 60 * 60 * 1000

/** PostgreSQL: lock_not_available (lock_timeout). */
export const PG_LOCK_NOT_AVAILABLE = '55P03'

/** PostgreSQL: query_canceled (statement_timeout / cancel). */
export const PG_QUERY_CANCELED = '57014'

export type MigrationTimeouts = {
  lockTimeoutMs: number
  statementTimeoutMs: number
}

export type MigrationTimeoutBreach = 'lock_timeout' | 'statement_timeout'

export type MigrationDirection = 'up' | 'down'

export type MigrationTimeoutAuditRecord = {
  event: 'migration_timeout_breach'
  version: string
  direction: MigrationDirection
  breach: MigrationTimeoutBreach
  lockTimeoutMs: number
  statementTimeoutMs: number
  pgCode?: string
  message: string
  timestamp: string
}

export type MigrationAuditLogger = (record: MigrationTimeoutAuditRecord) => void

export type RunMigrationOptions = {
  /** Global timeout overrides for this run (still overridable per SQL file). */
  timeouts?: Partial<MigrationTimeouts>
  /** Optional audit sink; defaults to structured logger.error. */
  onAudit?: MigrationAuditLogger
}

export class MigrationTimeoutError extends Error {
  readonly code = 'MIGRATION_TIMEOUT'
  readonly breach: MigrationTimeoutBreach
  readonly version: string
  readonly direction: MigrationDirection
  readonly timeouts: MigrationTimeouts
  readonly pgCode?: string

  constructor(params: {
    version: string
    direction: MigrationDirection
    breach: MigrationTimeoutBreach
    timeouts: MigrationTimeouts
    pgCode?: string
    cause?: Error
  }) {
    const { version, direction, breach, timeouts, pgCode, cause } = params
    super(
      `Migration "${version}" (${direction}) aborted: ${breach} breached ` +
        `(lock_timeout=${timeouts.lockTimeoutMs}ms, statement_timeout=${timeouts.statementTimeoutMs}ms)` +
        (pgCode ? ` [pg=${pgCode}]` : '')
    )
    this.name = 'MigrationTimeoutError'
    this.breach = breach
    this.version = version
    this.direction = direction
    this.timeouts = { ...timeouts }
    this.pgCode = pgCode
    if (cause) {
      ;(this as Error & { cause?: Error }).cause = cause
    }
  }
}

// ─── expand/contract migration helpers ──────────────────────────────────────
//
// The expand/contract (a.k.a. "blue-green") pattern keeps database changes
// backwards-compatible so deploys are zero-downtime:
//
//   1. EXPAND – add new schema elements (columns, tables, indexes) without
//      removing anything the running code still relies on.
//   2. CONTRACT – after *all* application instances have been updated to use
//      only the new schema, a separate migration removes the old elements.
//
// These helpers provide:
//   • A template for paired (up+down) migration files that document the phase.
//   • A lint check that surfaces legacy .sql files that lack a .down.sql
//     companion, nudging authors toward paired migrations by default.
//   • A `versionHasCompanionDown` helper so CI can gate on this policy.

/**
 * Template for a new paired migration.
 *
 * Replace `{name}` with a short snake_case description and fill in the
 * expand-phase DDL. The contract-phase `.down.sql` is generated automatically
 * as the reverse — add the clean-up DDL that drops the elements introduced
 * in the expand phase.
 *
 * Example:
 *   generateExpandContractTemplate('add_businesses_verified_at')
 *   → creates two SQL files in MIGRATIONS_DIR.
 */
export const EXPAND_CONTRACT_UP_TEMPLATE = `-- ${'{name}'}
-- Phase: EXPAND
--
-- This is the expand phase of a two-phase expand/contract migration.
-- The DDL *adds* schema elements (columns, tables, indexes, constraints)
-- but does NOT drop anything.  After this migration is deployed everywhere
-- and all code has been updated to use only the new schema, run the
-- corresponding contract migration to clean up old artifacts.
--
-- Usage:
--   1. Copy this file, rename to {seq}_{name}.up.sql
--   2. Create a companion {seq}_{name}.down.sql with the reverse DDL.
--   3. Run the migration.
--   4. After all instances are on the new code, create a second paired
--      migration (contract) that drops the old elements.

-- Example DDL (replace with your schema change):
-- ALTER TABLE businesses ADD COLUMN IF NOT EXISTS verified_at TIMESTAMPTZ;
-- CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_businesses_verified_at ON businesses (verified_at);
`

/**
 * Template for the contract-phase companion down migration.
 * Generated alongside the up template so rollback works from day one.
 */
export const EXPAND_CONTRACT_DOWN_TEMPLATE = `-- ${'{name}'}
-- Phase: ROLLBACK (reverses the EXPAND phase)
--
-- Reverses the DDL from the corresponding up migration.
-- This MUST bring the schema back to exactly the state it was in before
-- the up migration ran.

-- Example DDL (replace with the reverse of your .up.sql):
-- DROP INDEX CONCURRENTLY IF EXISTS idx_businesses_verified_at;
-- ALTER TABLE businesses DROP COLUMN IF EXISTS verified_at;
`

/** Outcome of linting a single migration version. */
export type MigrationLintResult = {
  version: string
  /** True when the version has a .down.sql companion. */
  hasCompanion: boolean
  /** True when the version uses the legacy .sql (up-only) format. */
  isLegacy: boolean
}

/** Report returned by {@link lintAllMigrations}. */
export type LintMigrationReport = {
  total: number
  /** Migrations that have a .down.sql companion. */
  withCompanion: number
  /** Migrations that are legacy (up-only, no rollback possible). */
  legacy: number
  /** Per-version details. */
  results: MigrationLintResult[]
}

/**
 * Check whether a migration version has a companion .down.sql file.
 *
 * Does NOT throw — returns `false` when the directory cannot be read or
 * the file is absent. Callers can therefore use this in CI gates without
 * worrying about filesystem flakes crashing the pipeline.
 */
export async function versionHasCompanionDown(
  version: string,
  dir: string = MIGRATIONS_DIR
): Promise<boolean> {
  try {
    await access(join(dir, `${version}.down.sql`))
    return true
  } catch {
    return false
  }
}

/**
 * Lint a single migration version.
 *
 * Returns a {@link MigrationLintResult} describing whether the version:
 *   - has a .down.sql companion (paired),
 *   - is a legacy .sql file (up-only, no companion possible).
 */
export async function lintMigrationCompanion(
  version: string,
  dir: string = MIGRATIONS_DIR
): Promise<MigrationLintResult> {
  const hasCompanion = await versionHasCompanionDown(version, dir)
  // Detect legacy format: a bare .sql file (not .up.sql and not .down.sql)
  let isLegacy = false
  try {
    await access(join(dir, `${version}.sql`))
    isLegacy = true
  } catch {
    // No legacy file — it's paired (or nonexistent)
  }
  return { version, hasCompanion, isLegacy }
}

/**
 * Lint every discovered migration and return a report.
 *
 * This is the function you'd call from a CI step:
 *   import { lintAllMigrations } from './db/migrate.js'
 *   const report = await lintAllMigrations()
 *   if (report.legacy > 0) process.exit(1)
 *
 * @param dir - Migration directory (defaults to MIGRATIONS_DIR).
 * @returns A roll-up {@link LintMigrationReport}.
 */
export async function lintAllMigrations(
  dir: string = MIGRATIONS_DIR
): Promise<LintMigrationReport> {
  const versions = await discoverMigrations(dir)
  const results = await Promise.all(
    versions.map((v) => lintMigrationCompanion(v, dir))
  )
  return {
    total: results.length,
    withCompanion: results.filter((r) => r.hasCompanion).length,
    legacy: results.filter((r) => r.isLegacy).length,
    results,
  }
}

/**
 * Renders a migration lint report as a human-readable string.
 * Suitable for console output or CI annotations.
 */
export function formatLintMigrationReport(report: LintMigrationReport): string {
  const lines: string[] = []
  lines.push('Migration companion lint')
  lines.push(`Total: ${report.total} | With companion: ${report.withCompanion} | Legacy (up-only): ${report.legacy}`)
  lines.push('')

  if (report.legacy === 0) {
    lines.push('All migrations have companion .down.sql files.')
    return lines.join('\n')
  }

  lines.push('Legacy migrations (no .down.sql companion):')
  for (const r of report.results) {
    if (r.isLegacy) {
      lines.push(`  - ${r.version}`)
    }
  }
  lines.push('')
  lines.push('Create a companion .down.sql or migrate to the paired (.up.sql/.down.sql) format.')
  return lines.join('\n')
}

/**
 * Generate the content for a new paired migration (expand phase .up.sql).
 *
 * Returns the template string with `{name}` replaced by `migrationName`.
 */
export function generateExpandUpSql(migrationName: string): string {
  return EXPAND_CONTRACT_UP_TEMPLATE.replaceAll('{name}', migrationName)
}

/**
 * Generate the content for the companion contract-phase .down.sql.
 *
 * Returns the template string with `{name}` replaced by `migrationName`.
 */
export function generateExpandDownSql(migrationName: string): string {
  return EXPAND_CONTRACT_DOWN_TEMPLATE.replaceAll('{name}', migrationName)
}

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

/** Reads the DOWN sql for a version. Returns null when no companion exists. */
export async function getDownSql(version: string, dir: string = MIGRATIONS_DIR): Promise<string | null> {
  const downPath = join(dir, `${version}.down.sql`)
  try {
    await access(downPath)
    return readFile(downPath, 'utf-8')
  } catch {
    return null
  }
}

/**
 * Parse a duration string (e.g. "5s", "500ms", "2m") into milliseconds.
 *
 * Throws when the input is empty or does not match the supported format.
 */
export function parseDurationMs(input: string): number {
  if (!input || input.trim() === '') {
    throw new Error('Duration must not be empty')
  }
  const match = /^(\d+)(ms|s|m)?$/.exec(input.trim())
  if (!match) {
    throw new Error(`Invalid duration: ${input}`)
  }
  const value = Number(match[1])
  const unit = match[2] ?? 'ms'
  switch (unit) {
    case 'ms':
      return value
    case 's':
      return value * 1000
    case 'm':
      return value * 60 * 1000
    default:
      throw new Error(`Invalid duration unit: ${unit}`)
  }
}
