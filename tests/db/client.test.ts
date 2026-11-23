import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { PgClient } from '../../src/db/client';

describe('PgClient', () => {
  let client: PgClient;

  beforeEach(() => {
    vi.resetModules();
    process.env.PGBOUNCER_MODE = '';
  });

  afterEach(async () => {
    if (client) {
      await client.end();
    }
  });

  describe('PgBouncer Mode Detection', () => {
    it('should default to session mode when no indicators present', () => {
      client = new PgClient();
      const status = client.getPgBouncerStatus();
      expect(status?.mode).toBe('session');
      expect(status?.safe).toBe(true);
    });

    it('should detect transaction mode from environment variable', () => {
      process.env.PGBOUNCER_MODE = 'transaction';
      client = new PgClient();
      const status = client.getPgBouncerStatus();
      expect(status?.mode).toBe('transaction');
      expect(status?.safe).toBe(false);
    });

    it('should detect session mode from environment variable', () => {
      process.env.PGBOUNCER_MODE = 'session';
      client = new PgClient();
      const status = client.getPgBouncerStatus();
      expect(status?.mode).toBe('session');
      expect(status?.safe).toBe(true);
    });

    it('should override detection with options', () => {
      client = new PgClient({ pgbouncerMode: 'transaction' });
      const status = client.getPgBouncerStatus();
      expect(status?.mode).toBe('transaction');
      expect(status?.safe).toBe(false);
    });

    it('should disable prepared statements in transaction mode', () => {
      process.env.PGBOUNCER_MODE = 'transaction';
      client = new PgClient();
      expect(client.isPreparedStatementsDisabled()).toBe(true);
    });

    it('should not disable prepared statements in session mode', () => {
      process.env.PGBOUNCER_MODE = 'session';
      client = new PgClient();
      expect(client.isPreparedStatementsDisabled()).toBe(false);
    });
  });

  describe('query', () => {
    it('should execute unnamed queries when prepared statements are disabled', async () => {
      process.env.PGBOUNCER_MODE = 'transaction';
      client = new PgClient();
      
      // Mock the pool query
      const mockQuery = vi.fn().mockResolvedValue({ rows: [], rowCount: 0 });
      client['pool'].query = mockQuery;

      await client.query('SELECT * FROM users');

      expect(mockQuery).toHaveBeenCalledWith('SELECT * FROM users', undefined);
    });

    it('should use unnamed queries when disablePrepared is true', async () => {
      client = new PgClient({ disablePreparedStatements: true });
      
      const mockQuery = vi.fn().mockResolvedValue({ rows: [], rowCount: 0 });
      client['pool'].query = mockQuery;

      await client.query('SELECT * FROM users WHERE id = $1', [1]);

      expect(mockQuery).toHaveBeenCalled();
    });

    it('should log warning when prepared statement attempted in transaction mode', async () => {
      process.env.PGBOUNCER_MODE = 'transaction';
      client = new PgClient();
      
      const mockQuery = vi.fn().mockResolvedValue({ rows: [], rowCount: 0 });
      client['pool'].query = mockQuery;
      
      const loggerWarn = vi.spyOn(client['logger'], 'warn');

      await client.query('SELECT * FROM users WHERE id = $1', [1]);

      expect(loggerWarn).toHaveBeenCalled();
    });
  });

  describe('healthCheck', () => {
    it('should return true when database is healthy', async () => {
      client = new PgClient();
      const mockQuery = vi.fn().mockResolvedValue({});
      client['pool'].query = mockQuery;

      const result = await client.healthCheck();
      expect(result).toBe(true);
    });

    it('should return false when database is unhealthy', async () => {
      client = new PgClient();
      const mockQuery = vi.fn().mockRejectedValue(new Error('Connection failed'));
      client['pool'].query = mockQuery;

      const result = await client.healthCheck();
      expect(result).toBe(false);
    });
  });

  describe('getPgBouncerStatus', () => {
    it('should return the detection status', () => {
      process.env.PGBOUNCER_MODE = 'transaction';
      client = new PgClient();
      const status = client.getPgBouncerStatus();
      expect(status).toBeDefined();
      expect(status?.mode).toBe('transaction');
    });
  });

  describe('isPreparedStatementsDisabled', () => {
    it('should return true when disabled', () => {
      client = new PgClient({ disablePreparedStatements: true });
      expect(client.isPreparedStatementsDisabled()).toBe(true);
    });

    it('should return false when enabled', () => {
      client = new PgClient({ disablePreparedStatements: false });
      expect(client.isPreparedStatementsDisabled()).toBe(false);
    });
  });
});
