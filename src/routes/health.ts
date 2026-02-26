/**
 * Health check endpoint.
 *
 * Reports DB and Redis connectivity when enabled via env:
 * - DATABASE_URL: if set, runs SELECT 1 (db: 'ok' | 'down')
 * - REDIS_URL: if set, runs PING (redis: 'ok' | 'down'). Optional; Redis down does not fail overall status.
 *
 * Uses timeouts (default 2s each) to keep response time low.
 */
import { Router } from 'express'

const PING_TIMEOUT_MS = 2000

function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  return Promise.race([
    p,
    new Promise<T>((_, reject) =>
      setTimeout(() => reject(new Error('timeout')), ms)
    ),
  ])
}

async function checkDb(): Promise<'ok' | 'down' | undefined> {
  const url = process.env.DATABASE_URL
  if (!url) return undefined
  try {
    const { default: pg } = await import('pg')
    const client = new pg.Client({ connectionString: url })
    await withTimeout(
      (async () => {
        await client.connect()
        try {
          await client.query('SELECT 1')
          return
        } finally {
          await client.end()
        }
      })(),
      PING_TIMEOUT_MS
    )
    return 'ok'
  } catch {
    return 'down'
  }
}

async function checkRedis(): Promise<'ok' | 'down' | undefined> {
  const url = process.env.REDIS_URL
  if (!url) return undefined
  try {
    const { createClient } = await import('redis')
    const client = createClient({ url })
    await withTimeout(
      (async () => {
        await client.connect()
        try {
          await client.ping()
        } finally {
          await client.quit()
        }
      })(),
      PING_TIMEOUT_MS
    )
    return 'ok'
  } catch {
    return 'down'
  }
}

export const healthRouter = Router()

healthRouter.get('/', async (_req, res) => {
  const [db, redis] = await Promise.all([checkDb(), checkRedis()])
  const degraded = db === 'down'
  // Redis is optional: only DB down affects overall status

  const body: {
    status: string
    service: string
    timestamp: string
    db?: 'ok' | 'down'
    redis?: 'ok' | 'down'
  } = {
    status: degraded ? 'degraded' : 'ok',
    service: 'veritasor-backend',
    timestamp: new Date().toISOString(),
  }
  if (db !== undefined) body.db = db
  if (redis !== undefined) body.redis = redis

  res.json(body)
})
