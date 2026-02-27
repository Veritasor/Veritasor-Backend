/**
 * Migration runner: runs pending SQL migrations from src/db/migrations/.
 * Tracks applied migrations in schema_migrations so each runs once.
 *
 * Usage: npm run migrate (reads DATABASE_URL from .env or env)
 */
import pg from 'pg'
import { readdir, readFile } from 'node:fs/promises'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))

const MIGRATIONS_DIR = join(__dirname, 'migrations')

async function runMigrations(): Promise<void> {
  const connectionString = process.env.DATABASE_URL
  if (!connectionString) {
    console.error('DATABASE_URL is required to run migrations.')
    process.exit(1)
  }

  const client = new pg.Client({ connectionString })
  try {
    await client.connect()

    await client.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version TEXT PRIMARY KEY,
        applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )
    `)

    const files = (await readdir(MIGRATIONS_DIR))
      .filter((f) => f.endsWith('.sql'))
      .sort()
    const applied = new Set(
      (await client.query('SELECT version FROM schema_migrations'))
        .rows
        .map((r: { version: string }) => r.version)
    )

    for (const file of files) {
      const version = file.replace(/\.sql$/, '')
      if (applied.has(version)) {
        console.log(`Skip (already applied): ${file}`)
        continue
      }
      const sql = await readFile(join(MIGRATIONS_DIR, file), 'utf-8')
      await client.query('BEGIN')
      try {
        await client.query(sql)
        await client.query(
          'INSERT INTO schema_migrations (version) VALUES ($1)',
          [version]
        )
        await client.query('COMMIT')
        console.log(`Applied: ${file}`)
      } catch (err) {
        await client.query('ROLLBACK')
        throw err
      }
    }
  } finally {
    await client.end()
  }
}

runMigrations().catch((err) => {
  console.error('Migration failed:', err)
  process.exit(1)
})
