import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const originalEnv = process.env
const poolMock = vi.fn()

vi.mock('pg', () => ({
  default: {
    Pool: poolMock,
  },
}))

async function importClient() {
  return import('../../../src/db/client.ts')
}

describe('db client pool configuration', () => {
  beforeEach(() => {
    vi.resetModules()
    poolMock.mockReset()
    poolMock.mockImplementation(function Pool(options) {
      return {
        options,
        query: vi.fn(),
      }
    })
    process.env = {
      ...originalEnv,
      DATABASE_URL: 'postgresql://user:password@localhost:5432/app_db',
      NODE_ENV: 'test',
      SOROBAN_CONTRACT_ID: 'CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM',
    }
    delete process.env.PGPOOL_MAX
    delete process.env.PG_IDLE_TIMEOUT_MS
    delete process.env.PG_CONN_TIMEOUT_MS
    delete process.env.PGSSL
    delete process.env.PGSSL_REJECT_UNAUTHORIZED
  })

  afterEach(() => {
    process.env = originalEnv
  })

  it('creates a pool with validated defaults when optional vars are unset', async () => {
    await importClient()

    expect(poolMock).toHaveBeenCalledWith({
      connectionString: 'postgresql://user:password@localhost:5432/app_db',
      max: 10,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 2000,
      ssl: undefined,
    })
  })

  it('uses env-driven pool tuning values', async () => {
    process.env.PGPOOL_MAX = '25'
    process.env.PG_IDLE_TIMEOUT_MS = '45000'
    process.env.PG_CONN_TIMEOUT_MS = '5000'

    await importClient()

    expect(poolMock).toHaveBeenCalledWith({
      connectionString: 'postgresql://user:password@localhost:5432/app_db',
      max: 25,
      idleTimeoutMillis: 45000,
      connectionTimeoutMillis: 5000,
      ssl: undefined,
    })
  })

  it('enables SSL with rejectUnauthorized by default when PGSSL=true', async () => {
    process.env.PGSSL = 'true'

    await importClient()

    expect(poolMock).toHaveBeenCalledWith({
      connectionString: 'postgresql://user:password@localhost:5432/app_db',
      max: 10,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 2000,
      ssl: {
        rejectUnauthorized: true,
      },
    })
  })

  it('allows SSL rejectUnauthorized to be disabled explicitly', async () => {
    process.env.PGSSL = 'true'
    process.env.PGSSL_REJECT_UNAUTHORIZED = 'false'

    await importClient()

    expect(poolMock).toHaveBeenCalledWith({
      connectionString: 'postgresql://user:password@localhost:5432/app_db',
      max: 10,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 2000,
      ssl: {
        rejectUnauthorized: false,
      },
    })
  })

  it('fails fast when DATABASE_URL is missing', async () => {
    delete process.env.DATABASE_URL

    await expect(importClient()).rejects.toThrow(
      'DATABASE_URL environment variable is required',
    )
    expect(poolMock).not.toHaveBeenCalled()
  })

  it.each([
    ['PGPOOL_MAX', '0', 'PGPOOL_MAX must be a positive integer'],
    ['PG_IDLE_TIMEOUT_MS', '-1', 'PG_IDLE_TIMEOUT_MS must be a positive integer'],
    ['PG_CONN_TIMEOUT_MS', 'abc', 'PG_CONN_TIMEOUT_MS must be a positive integer'],
  ])('rejects invalid numeric env values for %s', async (name, value, message) => {
    process.env[name] = value

    await expect(importClient()).rejects.toThrow(message)
    expect(poolMock).not.toHaveBeenCalled()
  })

  it.each([
    ['PGSSL', 'maybe'],
    ['PGSSL_REJECT_UNAUTHORIZED', 'sometimes'],
  ])('rejects invalid boolean values for %s', async (name, value) => {
    process.env.PGSSL = 'true'
    process.env[name] = value

    await expect(importClient()).rejects.toThrow(
      `${name} must be a boolean value (true/false, 1/0, yes/no, on/off)`,
    )
    expect(poolMock).not.toHaveBeenCalled()
  })
})
