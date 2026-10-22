import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { PgClient, getPgClient, db } from '../../../src/db/client.ts'
import pg from 'pg'

vi.mock('pg', () => {
  const mPool = {
    connect: vi.fn(),
    query: vi.fn(),
    end: vi.fn(),
  }
  return {
    Pool: vi.fn(() => mPool),
  }
})

describe('PgClient', () => {
  const originalEnv = process.env
  let poolMock: any

  beforeEach(() => {
    vi.resetModules()
    vi.clearAllMocks()
    poolMock = new pg.Pool()
    process.env = { ...originalEnv }
  })

  afterEach(() => {
    process.env = originalEnv
  })

  describe('PgClient construction and detection', () => {
    it('initializes with default safe session mode when no pgbouncer vars present', () => {
      const client = new PgClient()
      expect(client.getPgBouncerStatus()?.mode).toBe('session')
      expect(client.isPreparedStatementsDisabled()).toBe(false)
    })

    it('detects transaction mode via environment variable and disables prepared statements', () => {
      process.env.PGBOUNCER_MODE = 'transaction'
      const client = new PgClient()
      expect(client.getPgBouncerStatus()?.mode).toBe('transaction')
      expect(client.isPreparedStatementsDisabled()).toBe(true)
    })

    it('respects disablePreparedStatements option', () => {
      const client = new PgClient({ disablePreparedStatements: true })
      expect(client.isPreparedStatementsDisabled()).toBe(true)
    })

    it('respects pgbouncerMode override option', () => {
      const client = new PgClient({ pgbouncerMode: 'transaction' })
      expect(client.getPgBouncerStatus()?.mode).toBe('transaction')
      expect(client.isPreparedStatementsDisabled()).toBe(true)
    })
  })

  describe('Query handling', () => {
    it('uses unnamed statement for simple queries', async () => {
      const client = new PgClient()
      poolMock.query.mockResolvedValueOnce({ rows: [] })
      
      await client.query('SELECT * FROM users')
      
      expect(poolMock.query).toHaveBeenCalledWith('SELECT * FROM users', undefined)
    })

    it('uses prepared statement for complex queries with where clause', async () => {
      const client = new PgClient()
      poolMock.query.mockResolvedValue({ rows: [] })
      
      const queryText = 'SELECT id, name FROM users WHERE id = $1 AND status = $2' + ' '.repeat(100)
      await client.query(queryText, [1, 'active'])
      
      expect(poolMock.query).toHaveBeenCalledWith(expect.stringContaining('PREPARE prep_0 AS ' + queryText))
      expect(poolMock.query).toHaveBeenCalledWith('EXECUTE prep_0', [1, 'active'])
      expect(poolMock.query).toHaveBeenCalledWith('DEALLOCATE prep_0')
    })

    it('falls back to unnamed statement if prepared statement throws error', async () => {
      const client = new PgClient()
      poolMock.query.mockRejectedValueOnce(new Error('Prepare failed')) // prepare fails
      poolMock.query.mockResolvedValueOnce({ rows: [] }) // fallback succeeds
      
      const queryText = 'SELECT id, name FROM users WHERE id = $1 AND status = $2' + ' '.repeat(100)
      await client.query(queryText, [1, 'active'])
      
      // Fallback unnamed execution
      expect(poolMock.query).toHaveBeenCalledWith(queryText, [1, 'active'])
    })

    it('forces unnamed statement if in transaction mode', async () => {
      process.env.PGBOUNCER_MODE = 'transaction'
      const client = new PgClient()
      poolMock.query.mockResolvedValueOnce({ rows: [] })
      
      const queryText = 'SELECT id, name FROM users WHERE id = $1 AND status = $2' + ' '.repeat(100)
      await client.query(queryText, [1, 'active'])
      
      expect(poolMock.query).toHaveBeenCalledWith(queryText, [1, 'active'])
      // Ensure PREPARE was never called
      expect(poolMock.query).not.toHaveBeenCalledWith(expect.stringContaining('PREPARE'))
    })
  })

  describe('Singleton and DB proxy', () => {
    it('getPgClient returns the same singleton instance', () => {
      const client1 = getPgClient()
      const client2 = getPgClient()
      expect(client1).toBe(client2)
    })

    it('db proxy forwards calls to getPgClient', async () => {
      const client = getPgClient()
      
      const statusFromDb = db.getPgBouncerStatus()
      const statusFromClient = client.getPgBouncerStatus()
      
      expect(statusFromDb).toEqual(statusFromClient)
    })
  })

  describe('State transitions and health check', () => {
    it('healthCheck returns true on success', async () => {
      const client = new PgClient()
      poolMock.query.mockResolvedValueOnce({ rows: [{ '?column?': 1 }] })
      
      const isHealthy = await client.healthCheck()
      expect(isHealthy).toBe(true)
    })

    it('healthCheck returns false on failure', async () => {
      const client = new PgClient()
      poolMock.query.mockRejectedValueOnce(new Error('Connection failed'))
      
      const isHealthy = await client.healthCheck()
      expect(isHealthy).toBe(false)
    })

    it('getClient returns a connection from pool', async () => {
      const client = new PgClient()
      poolMock.connect.mockResolvedValueOnce({} as any)
      
      await client.getClient()
      expect(poolMock.connect).toHaveBeenCalled()
    })

    it('end closes the pool', async () => {
      const client = new PgClient()
      await client.end()
      expect(poolMock.end).toHaveBeenCalled()
    })
  })
})
