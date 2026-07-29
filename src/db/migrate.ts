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

/**
 * Parse a duration string into milliseconds.
 * Accepts bare integers (ms) or values with units: ms, s, m.
 */
export function parseDurationMs(raw: string): number {
  const trimmed = raw.trim().toLowerCase()
  if (!trimmed) {
    throw new Error('Duration must not be empty')
  }
  if (/^\d+$/.test(trimmed)) {
    return Number.parseInt(trimmed, 10)
  }
  const match = trimmed.match(/^(\d+(?:\.\d+)?)(ms|s|m)$/)
  if (!match) {
    throw new Error(
      `Invalid duration "${raw}": use milliseconds (e.g. 5000) or a unit suffix (5s, 2m, 500ms)`
    )
  }
  const value = Number(match[1])
  const unit = match[2]
  if (unit === 'ms') return Math.round(value)
  if (unit === 's') return Math.round(value * 1_000)
  return Math.round(value * 60_000)
}

/**
 * Assert a timeout value is a safe non-negative integer within the hard ceiling.
 * Values are interpolated into SET LOCAL; rejecting non-integers prevents injection.
 */
export function assertSafeTimeoutMs(value: number, label: string): number {
  if (!Number.isInteger(value) || value < 0 || value > MAX_MIGRATION_TIMEOUT_MS) {
    throw new Error(
      `Invalid ${label}: must be an integer in [0, ${MAX_MIGRATION_TIMEOUT_MS}] ms; got ${String(value)}`
    )
  }
  return value
}

function readEnvTimeoutMs(
  env: NodeJS.ProcessEnv,
  key: string,
  fallback: number
): number {
  const raw = env[key]
  if (raw == null || raw === '') return fallback
  const parsed = Number.parseInt(raw, 10)
  if (!Number.isFinite(parsed) || !Number.isInteger(parsed) || parsed < 0) {
    throw new Error(`${key} must be a non-negative integer (milliseconds); got "${raw}"`)
  }
  return assertSafeTimeoutMs(parsed, key)
}

/**
 * Resolve effective timeouts: defaults ← env ← run options ← per-file overrides.
 */
export function resolveMigrationTimeouts(
  overrides: Partial<MigrationTimeouts> = {},
  env: NodeJS.ProcessEnv = process.env
): MigrationTimeouts {
  const lockTimeoutMs = assertSafeTimeoutMs(
    overrides.lockTimeoutMs ??
      readEnvTimeoutMs(env, 'MIGRATION_LOCK_TIMEOUT_MS', DEFAULT_MIGRATION_LOCK_TIMEOUT_MS),
    'lock_timeout'
  )
  const statementTimeoutMs = assertSafeTimeoutMs(
    overrides.statementTimeoutMs ??
      readEnvTimeoutMs(
        env,
        'MIGRATION_STATEMENT_TIMEOUT_MS',
        DEFAULT_MIGRATION_STATEMENT_TIMEOUT_MS
      ),
    'statement_timeout'
  )
  return { lockTimeoutMs, statementTimeoutMs }
}

/**
 * Parse optional `@lock_timeout_ms` / `@statement_timeout_ms` directives from
 * leading SQL comment lines. Stops at the first non-comment, non-blank line.
 */
export function parseMigrationTimeoutOverrides(sql: string): Partial<MigrationTimeouts> {
  const overrides: Partial<MigrationTimeouts> = {}

  for (const line of sql.split(/\r?\n/)) {
    const trimmed = line.trim()
    if (!trimmed) continue
    if (!trimmed.startsWith('--')) break

    const lockMatch = trimmed.match(
      /^--\s*@lock_timeout(?:_ms)?\s*[:=]?\s*(.+?)\s*$/i
    )
    if (lockMatch) {
      overrides.lockTimeoutMs = assertSafeTimeoutMs(
        parseDurationMs(lockMatch[1]),
        'lock_timeout override'
      )
      continue
    }

    const statementMatch = trimmed.match(
      /^--\s*@statement_timeout(?:_ms)?\s*[:=]?\s*(.+?)\s*$/i
    )
    if (statementMatch) {
      overrides.statementTimeoutMs = assertSafeTimeoutMs(
        parseDurationMs(statementMatch[1]),
        'statement_timeout override'
      )
    }
  }

  return overrides
}

/**
 * Apply SET LOCAL lock_timeout / statement_timeout for the current transaction.
 * Values are validated integers only — never raw user strings.
 */
export async function applyMigrationTimeouts(
  client: Pick<pg.Client, 'query'>,
  timeouts: MigrationTimeouts
): Promise<void> {
  const lockMs = assertSafeTimeoutMs(timeouts.lockTimeoutMs, 'lock_timeout')
  const statementMs = assertSafeTimeoutMs(timeouts.statementTimeoutMs, 'statement_timeout')
  await client.query(`SET LOCAL lock_timeout = ${lockMs}`)
  await client.query(`SET LOCAL statement_timeout = ${statementMs}`)
}

/**
 * Classify a PostgreSQL (or simulated) error as a timeout breach, or null.
 */
export function classifyTimeoutBreach(err: unknown): MigrationTimeoutBreach | null {
  const e = err as { code?: string; message?: string } | null | undefined
  if (!e) return null

  if (e.code === PG_LOCK_NOT_AVAILABLE) return 'lock_timeout'
  if (e.code === PG_QUERY_CANCELED) {
    const msg = (e.message ?? '').toLowerCase()
    // Prefer explicit statement-timeout wording; otherwise treat cancel as statement.
    if (msg.includes('lock') && msg.includes('timeout')) return 'lock_timeout'
    return 'statement_timeout'
  }

  const msg = (e.message ?? '').toLowerCase()
  if (msg.includes('lock_not_available') || /\block timeout\b/.test(msg)) {
    return 'lock_timeout'
  }
  if (msg.includes('statement timeout') || msg.includes('canceling statement due to statement timeout')) {
    return 'statement_timeout'
  }
  return null
}

export function emitMigrationTimeoutAudit(
  record: Omit<MigrationTimeoutAuditRecord, 'event' | 'timestamp'> & {
    timestamp?: string
  },
  onAudit: MigrationAuditLogger = defaultMigrationAuditLogger
): MigrationTimeoutAuditRecord {
  const full: MigrationTimeoutAuditRecord = {
    event: 'migration_timeout_breach',
    timestamp: record.timestamp ?? new Date().toISOString(),
    version: record.version,
    direction: record.direction,
    breach: record.breach,
    lockTimeoutMs: record.lockTimeoutMs,
    statementTimeoutMs: record.statementTimeoutMs,
    pgCode: record.pgCode,
    message: record.message,
  }
  onAudit(full)
  return full
}

const defaultMigrationAuditLogger: MigrationAuditLogger = (record) => {
  logger.error(record)
}

function mergeTimeouts(
  runOverrides: Partial<MigrationTimeouts> | undefined,
  fileSql: string,
  env: NodeJS.ProcessEnv = process.env
): MigrationTimeouts {
  const fileOverrides = parseMigrationTimeoutOverrides(fileSql)
  return resolveMigrationTimeouts({ ...runOverrides, ...fileOverrides }, env)
}

async function runMigrationSql(
  client: Pick<pg.Client, 'query'>,
  version: string,
  direction: MigrationDirection,
  sql: string,
  options: RunMigrationOptions
): Promise<void> {
  const timeouts = mergeTimeouts(options.timeouts, sql)
  await client.query('BEGIN')
  try {
    await applyMigrationTimeouts(client, timeouts)
    await client.query(sql)
    if (direction === 'up') {
      await client.query('INSERT INTO schema_migrations (version) VALUES ($1)', [version])
    } else {
      await client.query('DELETE FROM schema_migrations WHERE version = $1', [version])
    }
    await client.query('COMMIT')
    console.log(direction === 'up' ? `Applied: ${version}` : `Rolled back: ${version}`)
  } catch (err) {
    await client.query('ROLLBACK')
    const breach = classifyTimeoutBreach(err)
    if (breach) {
      const pgCode = (err as { code?: string }).code
      const message = (err as Error).message ?? String(err)
      emitMigrationTimeoutAudit(
        {
          version,
          direction,
          breach,
          lockTimeoutMs: timeouts.lockTimeoutMs,
          statementTimeoutMs: timeouts.statementTimeoutMs,
          pgCode,
          message,
        },
        options.onAudit
      )
      throw new MigrationTimeoutError({
        version,
        direction,
        breach,
        timeouts,
        pgCode,
        cause: err instanceof Error ? err : undefined,
      })
    }
    throw new Error(
      `${direction === 'up' ? 'Migration' : 'Rollback'} failed for "${version}": ${(err as Error).message}`
    )
  }
}

// ─── core logic ─────────────────────────────────────────────────────────────

export async function runMigrations(
  client: Pick<pg.Client, 'query'>,
  dir: string = MIGRATIONS_DIR,
  options: RunMigrationOptions = {}
): Promise<void> {
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
    await runMigrationSql(client, version, 'up', sql, options)
  }
}

export async function runRollback(
  client: Pick<pg.Client, 'query'>,
  steps: number = 1,
  dir: string = MIGRATIONS_DIR,
  options: RunMigrationOptions = {}
): Promise<void> {
  await client.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version TEXT PRIMARY KEY,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `)

  const { rows } = await client.query(
    'SELECT version FROM schema_migrations ORDER BY version DESC LIMIT $1',
    [steps]
  ) as { rows: { version: string }[] }

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
    await runMigrationSql(client, version, 'down', sql, options)
  }
}

// ─── rollback dry-run verification ─────────────────────────────────────────
//
// Verifies that a migration's down.sql cleanly reverses its up.sql: applies
// up, applies down, and diffs the database schema before/after. This never
// touches production data — it is a structural (DDL) check run against a
// disposable scratch database (see `assertScratchDatabase`).

/**
 * Statement patterns that PostgreSQL refuses to run inside a transaction
 * block (they implicitly commit or require to run outside BEGIN/COMMIT).
 * Migrations containing these are executed in autocommit mode: each
 * statement takes effect immediately and a failure partway through cannot
 * be rolled back by us — only reported.
 */
const NON_TRANSACTIONAL_DDL_RE =
  /\b(CREATE\s+(?:UNIQUE\s+)?INDEX\s+CONCURRENTLY|DROP\s+INDEX\s+CONCURRENTLY|REINDEX\s+CONCURRENTLY|ALTER\s+TYPE\s+\S+\s+ADD\s+VALUE|VACUUM|CREATE\s+DATABASE|DROP\s+DATABASE|ALTER\s+SYSTEM|CLUSTER)\b/i

/** Returns true if `sql` contains a statement that cannot run inside BEGIN/COMMIT. */
export function requiresAutocommit(sql: string): boolean {
  return NON_TRANSACTIONAL_DDL_RE.test(sql)
}

/**
 * Captures a structural snapshot of the public schema: columns, indexes,
 * and constraints. Deliberately excludes `schema_migrations` (its row
 * content changes as versions are applied/rolled back, but its structure
 * never does) and excludes table data — this is a DDL/shape check only.
 */
export async function captureSchemaSnapshot(client: pg.Client): Promise<string[]> {
  const { rows } = await client.query<{ entry: string }>(`
    SELECT 'column:' || table_name || '.' || column_name || ':' || data_type
      || ':' || is_nullable || ':' || COALESCE(column_default, '') AS entry
    FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name != 'schema_migrations'
    UNION ALL
    SELECT 'index:' || indexname || ':' || indexdef AS entry
    FROM pg_indexes
    WHERE schemaname = 'public' AND tablename != 'schema_migrations'
    UNION ALL
    SELECT 'constraint:' || tc.table_name || '.' || tc.constraint_name || ':' || tc.constraint_type AS entry
    FROM information_schema.table_constraints tc
    WHERE tc.table_schema = 'public' AND tc.table_name != 'schema_migrations'
    ORDER BY 1
  `)
  return rows.map((r) => r.entry)
}

export type SchemaDrift = { onlyBefore: string[]; onlyAfter: string[] }

/** Diffs two schema snapshots. Empty result on both sides means no drift. */
export function diffSchemaSnapshots(before: string[], after: string[]): SchemaDrift {
  const beforeSet = new Set(before)
  const afterSet = new Set(after)
  return {
    onlyBefore: before.filter((e) => !afterSet.has(e)),
    onlyAfter: after.filter((e) => !beforeSet.has(e)),
  }
}

/**
 * Runs `sql` transactionally unless `autocommit` is set, in which case it
 * runs as-is (required for statements like CREATE INDEX CONCURRENTLY that
 * PostgreSQL refuses inside BEGIN/COMMIT).
 */
async function execMaybeTransactional(client: pg.Client, sql: string, autocommit: boolean): Promise<void> {
  if (autocommit) {
    await client.query(sql)
    return
  }
  await client.query('BEGIN')
  try {
    await client.query(sql)
    await client.query('COMMIT')
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {})
    throw err
  }
}

export interface RollbackVerificationResult {
  version: string
  ok: boolean
  upMs: number
  downMs: number
  autocommit: boolean
  schemaDrift: SchemaDrift | null
  error?: string
  phase?: 'discover' | 'up' | 'down' | 'reapply' | 'diff'
}

/**
 * Verifies a single migration's rollback: apply up, apply down, diff the
 * schema against the pre-up snapshot, then re-apply up so the scratch
 * database ends up fully migrated (matching what subsequent migrations in
 * the sequence — and a real deploy — expect).
 *
 * Assumes all migrations preceding `version` are already applied.
 */
export async function verifyMigrationRollback(
  client: pg.Client,
  version: string,
  dir: string = MIGRATIONS_DIR,
): Promise<RollbackVerificationResult> {
  let upSql: string
  let downSql: string
  try {
    upSql = await getUpSql(version, dir)
    downSql = await getDownSql(version, dir)
  } catch (err) {
    return {
      version, ok: false, upMs: 0, downMs: 0, autocommit: false,
      schemaDrift: null, error: (err as Error).message, phase: 'discover',
    }
  }

  const autocommit = requiresAutocommit(upSql) || requiresAutocommit(downSql)
  const before = await captureSchemaSnapshot(client)

  const upStart = Date.now()
  try {
    await execMaybeTransactional(client, upSql, autocommit)
    await client.query(
      'INSERT INTO schema_migrations (version) VALUES ($1) ON CONFLICT (version) DO NOTHING',
      [version],
    )
  } catch (err) {
    return {
      version, ok: false, upMs: Date.now() - upStart, downMs: 0, autocommit,
      schemaDrift: null, error: `up migration failed: ${(err as Error).message}`, phase: 'up',
    }
  }
  const upMs = Date.now() - upStart

  const downStart = Date.now()
  try {
    await execMaybeTransactional(client, downSql, autocommit)
    await client.query('DELETE FROM schema_migrations WHERE version = $1', [version])
  } catch (err) {
    // Best effort: up succeeded but down failed partway, so the scratch DB
    // is left with the migration applied. That's fine (it's disposable) —
    // the important thing is reporting it, not hiding it.
    return {
      version, ok: false, upMs, downMs: Date.now() - downStart, autocommit,
      schemaDrift: null, error: `down migration failed: ${(err as Error).message}`, phase: 'down',
    }
  }
  const downMs = Date.now() - downStart

  const afterDown = await captureSchemaSnapshot(client)
  const drift = diffSchemaSnapshots(before, afterDown)
  const hasDrift = drift.onlyBefore.length > 0 || drift.onlyAfter.length > 0

  try {
    await execMaybeTransactional(client, upSql, autocommit)
    await client.query(
      'INSERT INTO schema_migrations (version) VALUES ($1) ON CONFLICT (version) DO NOTHING',
      [version],
    )
  } catch (err) {
    return {
      version, ok: false, upMs, downMs, autocommit,
      schemaDrift: hasDrift ? drift : null,
      error: `re-apply after rollback failed: ${(err as Error).message}`,
      phase: 'reapply',
    }
  }

  return {
    version,
    ok: !hasDrift,
    upMs,
    downMs,
    autocommit,
    schemaDrift: hasDrift ? drift : null,
    error: hasDrift ? 'schema drift detected: rollback did not fully reverse the up migration' : undefined,
    phase: hasDrift ? 'diff' : undefined,
  }
}

export interface RollbackVerificationReport {
  total: number
  passed: number
  failed: number
  results: RollbackVerificationResult[]
}

/**
 * Verifies rollback for `options.versions` (default: every discovered
 * migration), applying — but not verifying — any earlier migrations not in
 * that list so later target migrations have the schema they depend on.
 */
export async function runRollbackVerification(
  client: pg.Client,
  options: { versions?: string[]; dir?: string; stopOnFirstFailure?: boolean } = {},
): Promise<RollbackVerificationReport> {
  const dir = options.dir ?? MIGRATIONS_DIR
  const allVersions = await discoverMigrations(dir)
  const targets = options.versions ?? allVersions
  const targetSet = new Set(targets)

  await client.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version TEXT PRIMARY KEY,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `)

  const results: RollbackVerificationResult[] = []

  for (const version of allVersions) {
    if (!targetSet.has(version)) {
      // Dependency migration: apply it (not under test) so later target
      // migrations in the sequence see the schema they expect.
      const { rows: existing } = await client.query('SELECT 1 FROM schema_migrations WHERE version = $1', [version])
      if (existing.length === 0) {
        const sql = await getUpSql(version, dir)
        await client.query('BEGIN')
        try {
          await client.query(sql)
          await client.query('INSERT INTO schema_migrations (version) VALUES ($1)', [version])
          await client.query('COMMIT')
        } catch (err) {
          await client.query('ROLLBACK')
          throw new Error(`Dependency migration "${version}" failed to apply: ${(err as Error).message}`)
        }
      }
      continue
    }

    const result = await verifyMigrationRollback(client, version, dir)
    results.push(result)
    if (!result.ok && options.stopOnFirstFailure) break
  }

  const passed = results.filter((r) => r.ok).length
  return { total: results.length, passed, failed: results.length - passed, results }
}

/** Renders a rollback verification report as a Markdown table for CI summaries. */
export function formatRollbackReportMarkdown(report: RollbackVerificationReport): string {
  const lines: string[] = []
  lines.push('## Migration rollback verification')
  lines.push('')
  lines.push(
    report.failed === 0
      ? `All ${report.total} migration(s) rolled back cleanly.`
      : `${report.failed}/${report.total} migration(s) failed rollback verification.`,
  )
  lines.push('')
  lines.push('| Version | Result | Up (ms) | Down (ms) | Mode | Notes |')
  lines.push('|---|---|---|---|---|---|')
  for (const r of report.results) {
    const result = r.ok ? 'pass' : 'FAIL'
    const mode = r.autocommit ? 'autocommit (non-transactional DDL)' : 'transactional'
    let notes = r.error ?? ''
    if (r.schemaDrift) {
      notes = `schema drift: +${r.schemaDrift.onlyAfter.length} leftover, -${r.schemaDrift.onlyBefore.length} not restored`
    }
    lines.push(`| ${r.version} | ${result} | ${r.upMs} | ${r.downMs} | ${mode} | ${notes} |`)
  }
  return lines.join('\n')
}

/**
 * Refuses to run rollback verification against anything that doesn't look
 * like a disposable database. Verification applies and re-applies DDL
 * repeatedly and can leave a database mid-migration on failure — never
 * something to risk against a real environment.
 *
 * Passes for localhost/loopback hosts (the normal shape of a CI service
 * container or local scratch DB) or when the database name signals intent
 * (contains "test", "scratch", "ci", or "ephemeral"). Anything else must
 * opt in explicitly via MIGRATION_VERIFY_FORCE=true.
 */
export function assertScratchDatabase(connectionString: string): void {
  if (process.env.MIGRATION_VERIFY_FORCE === 'true') return

  let url: URL
  try {
    url = new URL(connectionString)
  } catch {
    throw new Error('Refusing to run rollback verification: DATABASE_URL is not a valid connection URL.')
  }

  const host = url.hostname.toLowerCase()
  const dbName = url.pathname.replace(/^\//, '').toLowerCase()
  const isLoopback = host === 'localhost' || host === '127.0.0.1' || host === '::1'
  const looksScratch = /(^|[_-])(test|scratch|ci|ephemeral)([_-]|$)/.test(dbName)

  if (isLoopback || looksScratch) return

  throw new Error(
    `Refusing to run rollback verification against "${host}/${dbName}": it does not look like a ` +
    `disposable scratch database. Point DATABASE_URL at a throwaway database (localhost, or a name ` +
    `containing "test"/"scratch"/"ci"), or set MIGRATION_VERIFY_FORCE=true to override.`,
  )
}

// ─── migration companion lint CLI ───────────────────────────────────────────

/**
 * CLI entry point for migration companion lint.
 *
 * npm run migrate:lint-companions
 *
 * Exits with code 1 when any legacy (up-only) migration is found.
 */
export async function runMigrationCompanionLint(
  dir: string = MIGRATIONS_DIR,
  env: NodeJS.ProcessEnv = process.env,
  exitFn: (code: number) => never = ((code) => process.exit(code)) as (code: number) => never
): Promise<void> {
  const report = await lintAllMigrations(dir)
  const output = formatLintMigrationReport(report)
  console.log(output)

  if (process.env.GITHUB_STEP_SUMMARY) {
    await appendFile(process.env.GITHUB_STEP_SUMMARY, output + '\n')
  }

  if (report.legacy > 0) {
    exitFn(1)
  }
}

// ─── CLI entry point ─────────────────────────────────────────────────────────

/** True when this module is the process entrypoint (not imported by tests). */
export function isMigrateCliEntrypoint(
  argv1: string | undefined,
  moduleUrl: string
): boolean {
  return Boolean(argv1 && fileURLToPath(moduleUrl) === argv1)
}

/**
 * CLI driver for `npm run migrate` / `migrate:rollback`.
 * Exported for unit tests; production entry uses {@link isMigrateCliEntrypoint}.
 */
export async function runMigrateCli(
  env: NodeJS.ProcessEnv = process.env,
  argv: string[] = process.argv,
  exitFn: (code: number) => never = ((code) => process.exit(code)) as (code: number) => never,
  ClientCtor: typeof pg.Client = pg.Client
): Promise<void> {
  const connectionString = env.DATABASE_URL
  if (!connectionString) {
    console.error('DATABASE_URL is required.')
    exitFn(1)
    return
  }

  const command = process.argv[2]   // 'rollback' | 'verify-rollback' | undefined
  const steps   = parseInt(process.argv[3] ?? '1', 10)

  const client = new ClientCtor({ connectionString })
  try {
    await client.connect()
    if (command === 'lint-companions') {
      await runMigrationCompanionLint(MIGRATIONS_DIR, env, exitFn)
      return
    } else if (command === 'rollback') {
      await runRollback(client, steps)
    } else if (command === 'verify-rollback') {
      assertScratchDatabase(connectionString)

      const onlyArg = process.argv.slice(3).find((a) => a.startsWith('--only='))
      const versions = onlyArg
        ? onlyArg.slice('--only='.length).split(',').map((v) => v.trim()).filter(Boolean)
        : undefined

      const report = await runRollbackVerification(client, { versions })
      const markdown = formatRollbackReportMarkdown(report)
      console.log(markdown)

      if (process.env.GITHUB_STEP_SUMMARY) {
        await appendFile(process.env.GITHUB_STEP_SUMMARY, markdown + '\n')
      }

      if (report.failed > 0) {
        process.exitCode = 1
      }
    } else {
      await runMigrations(client)
    }
  } finally {
    await client.end()
  }
}

export async function handleMigrateCliFailure(
  err: unknown,
  exitFn: (code: number) => never = ((code) => process.exit(code)) as (code: number) => never
): Promise<never> {
  console.error('Fatal:', err instanceof Error ? err.message : String(err))
  exitFn(1)
}

// Only run when executed directly (not when imported in tests)
if (isMigrateCliEntrypoint(process.argv[1], import.meta.url)) {
  runMigrateCli().catch(handleMigrateCliFailure)
}
