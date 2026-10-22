import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { logger } from '../utils/logger.js';

const poolConstructorSpy = vi.fn();

vi.mock('pg', () => {
  const MockPool = vi.fn().mockImplementation((config) => {
    poolConstructorSpy(config);
    return {
      connect: vi.fn().mockResolvedValue({}),
      query: vi.fn().mockResolvedValue({ rows: [] }),
      end: vi.fn().mockResolvedValue(undefined),
    };
  });
  return {
    Pool: MockPool,
    default: {
      Pool: MockPool,
    },
  };
});

describe('src/db/client.ts', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
    poolConstructorSpy.mockClear();
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe('getPgClient configuration wiring', () => {
    it('passes connectionString from DATABASE_URL and does not pass legacy DB_* defaults', async () => {
      delete process.env.DB_HOST;
      delete process.env.DB_PORT;
      delete process.env.DB_NAME;
      delete process.env.DB_USER;
      delete process.env.DB_PASSWORD;
      delete process.env.DB_MAX_CONNECTIONS;
      delete process.env.DB_IDLE_TIMEOUT;

      process.env.DATABASE_URL = 'postgres://u:p@db.example:6543/x';

      const { getPgClient, resetPgClient } = await import('./client.js');
      resetPgClient();
      getPgClient();

      expect(poolConstructorSpy).toHaveBeenCalledTimes(1);
      const poolOptions = poolConstructorSpy.mock.calls[0][0];

      expect(poolOptions.connectionString).toBe('postgres://u:p@db.example:6543/x');
      expect(poolOptions.host).toBeUndefined();
      expect(poolOptions.database).toBeUndefined();
      expect(poolOptions.user).toBeUndefined();
    });

    it('sets max from PGPOOL_MAX and ssl from PGSSL and PGSSL_REJECT_UNAUTHORIZED', async () => {
      process.env.DATABASE_URL = 'postgres://u:p@db.example:6543/x';
      process.env.PGPOOL_MAX = '7';
      process.env.PGSSL = 'true';
      process.env.PGSSL_REJECT_UNAUTHORIZED = 'false';

      const { getPgClient, resetPgClient } = await import('./client.js');
      resetPgClient();
      getPgClient();

      expect(poolConstructorSpy).toHaveBeenCalledTimes(1);
      const poolOptions = poolConstructorSpy.mock.calls[0][0];

      expect(poolOptions.connectionString).toBe('postgres://u:p@db.example:6543/x');
      expect(poolOptions.max).toBe(7);
      expect(poolOptions.ssl).toEqual({ rejectUnauthorized: false });
    });

    it('logs warning when legacy DB_* variables are present alongside DATABASE_URL', async () => {
      process.env.DATABASE_URL = 'postgres://u:p@db.example:6543/x';
      process.env.DB_HOST = 'legacy-host';

      const warnSpy = vi.spyOn(logger, 'warn');

      const { getPgClient, resetPgClient } = await import('./client.js');
      resetPgClient();
      getPgClient();

      expect(warnSpy).toHaveBeenCalledWith(
        expect.stringContaining('legacy DB_* environment variables')
      );
      const poolOptions = poolConstructorSpy.mock.calls[0][0];
      expect(poolOptions.connectionString).toBe('postgres://u:p@db.example:6543/x');
      expect(poolOptions.host).toBeUndefined();
    });

    it('falls back to legacy DB_* variables when DATABASE_URL is absent and logs deprecation warning', async () => {
      const warnSpy = vi.spyOn(logger, 'warn');

      vi.doMock('../config/index.js', () => ({
        config: {
          db: {
            url: undefined,
          },
        },
      }));

      process.env.DB_HOST = 'custom-db-host';
      process.env.DB_PORT = '5433';
      process.env.DB_NAME = 'custom_db';
      process.env.DB_USER = 'custom_user';
      process.env.DB_PASSWORD = 'custom_password';
      process.env.DB_MAX_CONNECTIONS = '15';
      process.env.DB_IDLE_TIMEOUT = '45000';

      const { getPgClient, resetPgClient } = await import('./client.js');
      resetPgClient();
      getPgClient();

      expect(warnSpy).toHaveBeenCalledWith(
        expect.stringContaining('falling back to legacy DB_* environment variables')
      );

      expect(poolConstructorSpy).toHaveBeenCalledTimes(1);
      const poolOptions = poolConstructorSpy.mock.calls[0][0];
      expect(poolOptions.host).toBe('custom-db-host');
      expect(poolOptions.port).toBe(5433);
      expect(poolOptions.database).toBe('custom_db');
      expect(poolOptions.user).toBe('custom_user');
      expect(poolOptions.password).toBe('custom_password');
      expect(poolOptions.max).toBe(15);
      expect(poolOptions.idleTimeoutMillis).toBe(45000);
    });
  });

  describe('PgBouncer detection with connectionString', () => {
    it('detects transaction mode from connection string query parameter and disables prepared statements', async () => {
      const { PgClient } = await import('./client.js');
      const client = new PgClient({
        connectionString: 'postgres://u:p@db.example:6543/x?pool_mode=transaction',
      });

      const status = client.getPgBouncerStatus();
      expect(status?.mode).toBe('transaction');
      expect(status?.safe).toBe(false);
      expect(client.isPreparedStatementsDisabled()).toBe(true);
    });

    it('detects session mode from connection string query parameter and leaves prepared statements enabled', async () => {
      const { PgClient } = await import('./client.js');
      const client = new PgClient({
        connectionString: 'postgres://u:p@db.example:6543/x?pool_mode=session',
      });

      const status = client.getPgBouncerStatus();
      expect(status?.mode).toBe('session');
      expect(status?.safe).toBe(true);
      expect(client.isPreparedStatementsDisabled()).toBe(false);
    });

    it('detects PgBouncer from hostname and port in connection string', async () => {
      const { PgClient } = await import('./client.js');
      const client = new PgClient({
        connectionString: 'postgres://u:p@pgbouncer-prod:6432/x',
      });

      const status = client.getPgBouncerStatus();
      expect(status?.detected).toBe(true);
      expect(status?.safe).toBe(true);
    });

    it('detects PgBouncer from pgbouncer query parameter in connection string', async () => {
      const { PgClient } = await import('./client.js');
      const client = new PgClient({
        connectionString: 'postgres://u:p@db.example:6543/x?pgbouncer=true',
      });

      const status = client.getPgBouncerStatus();
      expect(status?.detected).toBe(true);
      expect(status?.safe).toBe(true);
    });
  });

  describe('Prepared statement handling preserved', () => {
    it('uses unnamed statement for short queries', async () => {
      const { PgClient } = await import('./client.js');
      const client = new PgClient();
      const mockPoolInstance = poolConstructorSpy.mock.results[0].value;

      await client.query('SELECT 1');
      expect(mockPoolInstance.query).toHaveBeenCalledWith('SELECT 1', undefined);
    });

    it('uses prepared statement for queries with WHERE and length > 100 in safe session mode', async () => {
      const { PgClient } = await import('./client.js');
      const client = new PgClient();
      const mockPoolInstance = poolConstructorSpy.mock.results[0].value;

      const longQuery = 'SELECT id, username FROM users WHERE status = $1' + ' '.repeat(100);
      await client.query(longQuery, ['active']);

      expect(mockPoolInstance.query).toHaveBeenCalledWith(
        expect.stringContaining('PREPARE prep_0 AS ' + longQuery)
      );
      expect(mockPoolInstance.query).toHaveBeenCalledWith('EXECUTE prep_0', ['active']);
      expect(mockPoolInstance.query).toHaveBeenCalledWith('DEALLOCATE prep_0');
    });

    it('does not use prepared statement when prepared statements are disabled', async () => {
      const { PgClient } = await import('./client.js');
      const client = new PgClient({ disablePreparedStatements: true });
      const mockPoolInstance = poolConstructorSpy.mock.results[0].value;

      const longQuery = 'SELECT id, username FROM users WHERE status = $1' + ' '.repeat(100);
      await client.query(longQuery, ['active']);

      expect(mockPoolInstance.query).toHaveBeenCalledWith(longQuery, ['active']);
      expect(mockPoolInstance.query).not.toHaveBeenCalledWith(expect.stringContaining('PREPARE'));
    });
  });
});
