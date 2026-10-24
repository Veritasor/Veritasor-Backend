import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import { execSync } from 'node:child_process'
import { Client } from 'pg'
import { GenericContainer, type StartedTestContainer } from 'testcontainers'

const state = vi.hoisted(() => ({ client: null as Client | null }))
vi.mock('../../src/db/client.js', () => ({
  db: {
    query: (sql: string, params?: unknown[]) => {
      if (!state.client) throw new Error('PostgreSQL test client is not initialized')
      return state.client.query(sql, params)
    },
  },
}))

import { DeadLetterQueue, saveDeadLetter } from '../../src/services/webhooks/deadLetterQueue.js'

const dockerAvailable = (() => {
  try {
    execSync('docker info --format "{{.ServerVersion}}"', { stdio: 'pipe', timeout: 5000 })
    return true
  } catch {
    return false
  }
})()

const describeWithDocker = dockerAvailable ? describe : describe.skip

describeWithDocker('saveDeadLetter (PostgreSQL)', () => {
  let container: StartedTestContainer
  let client: Client

  beforeAll(async () => {
    container = await new GenericContainer('postgres:16-alpine')
      .withEnvironment({ POSTGRES_USER: 'test', POSTGRES_PASSWORD: 'test', POSTGRES_DB: 'dlq_test' })
      .withExposedPorts(5432)
      .withStartupTimeout(60_000)
      .start()

    client = new Client({
      host: container.getHost(),
      port: container.getMappedPort(5432),
      user: 'test',
      password: 'test',
      database: 'dlq_test',
    })
    await client.connect()
    state.client = client
    await client.query(`CREATE TABLE webhook_dead_letters (
      id SERIAL PRIMARY KEY,
      provider TEXT NOT NULL,
      event_id TEXT NOT NULL,
      payload_hash TEXT NOT NULL,
      error_code TEXT NOT NULL,
      attempt_count INTEGER NOT NULL DEFAULT 1,
      integration TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CONSTRAINT webhook_dead_letters_provider_event_id_key UNIQUE (provider, event_id)
    )`)
  }, 90_000)

  afterAll(async () => {
    state.client = null
    if (client) await client.end()
    if (container) await container.stop()
  })

  it('increments attempts across repeated events without creating duplicate rows', async () => {
    await saveDeadLetter('razorpay', 'evt-repeat', { event: 'payment.failed' }, new Error('first'), 3)
    await saveDeadLetter('razorpay', 'evt-repeat', { event: 'payment.failed' }, new Error('retry'), 2)

    const result = await client.query(
      'SELECT COUNT(*) AS row_count, MAX(attempt_count) AS attempt_count FROM webhook_dead_letters WHERE provider = $1 AND event_id = $2',
      ['razorpay', 'evt-repeat'],
    )
    expect(result.rows[0]).toEqual({ row_count: '1', attempt_count: 5 })
  })

  it('returns the requested page over seeded entries', async () => {
    for (let index = 1; index <= 25; index++) {
      await client.query(
        'INSERT INTO webhook_dead_letters (provider, event_id, payload_hash, error_code, attempt_count, integration) VALUES ($1, $2, $3, $4, 1, $1)',
        ['test', `evt-${index}`, `hash-${index}`, 'Error'],
      )
    }

    const result = await new DeadLetterQueue().getEntries({ page: 2, pageSize: 10, type: 'test' })

    expect(result.total).toBe(25)
    expect(result.entries).toHaveLength(10)
    expect(result.entries[0].event_id).toBe('evt-15')
    expect(result.entries[9].event_id).toBe('evt-6')
  })
})
