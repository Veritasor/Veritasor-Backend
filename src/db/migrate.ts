/**
 * Migration runner for SQL files in src/db/migrations/.
 *
 * The runner coordinates concurrent invocations with a PostgreSQL advisory
 * lock so only one process applies migrations at a time. Other runners wait
 * for the lock for a bounded time and then fail with a clear error.
 */
import pg from 'pg'
import { readdir, readFile } from 'node:fs/promises'
import { join, dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))

const MIGRATIONS_DIR = join(__dirname, 'migrations')
const DEFAULT_LOCK_KEY = 2_147_454_701
const DEFAULT_LOCK_TIMEOUT_MS = 30_000
const DEFAULT_LOCK_POLL_INTERVAL_MS = 1_000

type QueryResultRow = Record<string, unknown>

export type MigrationClient = {
  connect(): Promise<unknown>
  end(): Promise<void>
  query<T extends QueryResultRow = QueryResultRow>(
    text: string,
    params?: unknown[]
  ): Promise<{ rows: T[] }>
}

export type MigrationLogger = Pick<typeof console, 'log' | 'error'>

export type MigrationRunnerOptions = {
  connectionString?: string
  migrationsDir?: string
  lockKey?: number
  lockTimeoutMs?: number
  lockPollIntervalMs?: number
  client?: MigrationClient
  createClient?: (connectionString: string) => MigrationClient
  readdirFn?: typeof readdir
  readFileFn?: typeof readFile
  sleep?: (ms: number) => Promise<void>
  logger?: MigrationLogger
}

type LockRow = { locked: boolean }
type VersionRow = { version: string }

function parseEnvNumber(
  value: string | undefined,
  fallback: number,
  variableName: string
): number {
  if (!value) {
    return fallback
  }

  const parsed = Number.parseInt(value, 10)
  if (!Number.isFinite(parsed) || parsed < 0) {
    throw new Error(`${variableName} must be a non-negative integer.`)
  }

  return parsed
}

/**
 * Sleep helper used between advisory lock attempts.
 */
export async function delay(ms: number): Promise<void> {
  await new Promise((resolveDelay) => setTimeout(resolveDelay, ms))
}

function createPgMigrationClient(connectionString: string): MigrationClient {
  const client = new pg.Client({ connectionString })

  return {
    connect: () => client.connect(),
    end: () => client.end(),
    query: <T extends QueryResultRow = QueryResultRow>(
      text: string,
      params?: unknown[]
    ) => client.query<T>(text, params as never[] | undefined),
  }
}

/**
 * Attempts to acquire the advisory lock dedicated to migration execution.
 * The lock is session-scoped and is released in a finally block.
 */
export async function acquireMigrationLock(
  client: MigrationClient,
  {
    lockKey = DEFAULT_LOCK_KEY,
    lockTimeoutMs = DEFAULT_LOCK_TIMEOUT_MS,
    lockPollIntervalMs = DEFAULT_LOCK_POLL_INTERVAL_MS,
    sleep = delay,
    logger = console,
  }: Pick<
    MigrationRunnerOptions,
    'lockKey' | 'lockTimeoutMs' | 'lockPollIntervalMs' | 'sleep' | 'logger'
  > = {}
): Promise<void> {
  const deadline = Date.now() + lockTimeoutMs

  while (true) {
    const result = await client.query<LockRow>(
      'SELECT pg_try_advisory_lock($1) AS locked',
      [lockKey]
    )

    if (result.rows[0]?.locked) {
      logger.log(`Migration lock acquired (key: ${lockKey}).`)
      return
    }

    if (Date.now() >= deadline) {
      throw new Error(
        `Timed out waiting for migration lock after ${lockTimeoutMs}ms.`
      )
    }

    logger.log(
      `Migration lock busy; retrying in ${lockPollIntervalMs}ms (key: ${lockKey}).`
    )
    await sleep(lockPollIntervalMs)
  }
}

/**
 * Releases the advisory lock if it is currently held by this session.
 * Failures here are logged and rethrown so operational issues are visible.
 */
export async function releaseMigrationLock(
  client: MigrationClient,
  {
    lockKey = DEFAULT_LOCK_KEY,
    logger = console,
  }: Pick<MigrationRunnerOptions, 'lockKey' | 'logger'> = {}
): Promise<void> {
  try {
    await client.query('SELECT pg_advisory_unlock($1)', [lockKey])
    logger.log(`Migration lock released (key: ${lockKey}).`)
  } catch (error) {
    logger.error('Failed to release migration lock:', error)
    throw error
  }
}

/**
 * Runs all pending SQL migrations exactly once, guarded by an advisory lock.
 * Each migration executes inside its own transaction and is recorded only
 * after the SQL file completes successfully.
 */
export async function runMigrations(
  options: MigrationRunnerOptions = {}
): Promise<void> {
  const connectionString = options.connectionString ?? process.env.DATABASE_URL
  if (!connectionString) {
    throw new Error('DATABASE_URL is required to run migrations.')
  }

  const logger = options.logger ?? console
  const lockKey =
    options.lockKey ??
    parseEnvNumber(
      process.env.MIGRATION_LOCK_KEY,
      DEFAULT_LOCK_KEY,
      'MIGRATION_LOCK_KEY'
    )
  const lockTimeoutMs =
    options.lockTimeoutMs ??
    parseEnvNumber(
      process.env.MIGRATION_LOCK_TIMEOUT_MS,
      DEFAULT_LOCK_TIMEOUT_MS,
      'MIGRATION_LOCK_TIMEOUT_MS'
    )
  const lockPollIntervalMs =
    options.lockPollIntervalMs ??
    parseEnvNumber(
      process.env.MIGRATION_LOCK_POLL_INTERVAL_MS,
      DEFAULT_LOCK_POLL_INTERVAL_MS,
      'MIGRATION_LOCK_POLL_INTERVAL_MS'
    )
  const client =
    options.client ??
    (options.createClient
      ? options.createClient(connectionString)
      : createPgMigrationClient(connectionString))
  const readdirFn = options.readdirFn ?? readdir
  const readFileFn = options.readFileFn ?? readFile
  const migrationsDir = options.migrationsDir ?? MIGRATIONS_DIR
  let connected = false
  let lockAcquired = false

  try {
    await client.connect()
    connected = true
    await acquireMigrationLock(client, {
      lockKey,
      lockTimeoutMs,
      lockPollIntervalMs,
      sleep: options.sleep,
      logger,
    })
    lockAcquired = true

    await client.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version TEXT PRIMARY KEY,
        applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )
    `)

    const files = (await readdirFn(migrationsDir))
      .filter((file) => file.endsWith('.sql'))
      .sort()
    const applied = new Set(
      (
        await client.query<VersionRow>('SELECT version FROM schema_migrations')
      ).rows.map((row: VersionRow) => row.version)
    )

    for (const file of files) {
      const version = file.replace(/\.sql$/, '')
      if (applied.has(version)) {
        logger.log(`Skip (already applied): ${file}`)
        continue
      }

      const sql = await readFileFn(join(migrationsDir, file), 'utf-8')
      await client.query('BEGIN')
      try {
        await client.query(sql)
        await client.query(
          'INSERT INTO schema_migrations (version) VALUES ($1)',
          [version]
        )
        await client.query('COMMIT')
        logger.log(`Applied: ${file}`)
      } catch (error) {
        await client.query('ROLLBACK')
        throw error
      }
    }
  } finally {
    try {
      if (connected && lockAcquired) {
        await releaseMigrationLock(client, {
          lockKey,
          logger,
        })
      }
    } finally {
      if (connected) {
        await client.end()
      }
    }
  }
}

function isDirectExecution(): boolean {
  const entrypoint = process.argv[1]
  return Boolean(entrypoint && fileURLToPath(import.meta.url) === resolve(entrypoint))
}

if (isDirectExecution()) {
  runMigrations().catch((error) => {
    console.error('Migration failed:', error)
    process.exit(1)
  })
}
