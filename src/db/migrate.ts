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
 *   npm run migrate              – apply all pending migrations
 *   npm run migrate:rollback     – roll back the last 1 migration
 *   npm run migrate:rollback 3   – roll back the last 3 migrations
 *
 * File conventions (both supported):
 *   Legacy:  001_foo.sql          → up-only, no rollback available
 *   Paired:  001_foo.up.sql  +  001_foo.down.sql  → supports rollback
 *
 * Per-migration timeout overrides (optional leading SQL comments):
 *   -- @lock_timeout_ms 5000
 *   -- @statement_timeout_ms 0
 *   Durations may also use units: 5s, 2m, 500ms. `0` disables that timeout
 *   (e.g. long index builds that need a raised/disabled statement_timeout
 *   while keeping a tight lock_timeout).
 */

import pg from 'pg'
import { readdir, readFile, access } from 'node:fs/promises'
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

  const command = argv[2]   // 'rollback' or undefined
  const steps   = parseInt(argv[3] ?? '1', 10)

  const client = new ClientCtor({ connectionString })
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
