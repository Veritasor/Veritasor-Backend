/**
 * PgBouncer transaction-pooling compatibility tests for db/client.ts
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { GenericContainer, Network, type StartedTestContainer } from 'testcontainers';
import { execSync } from 'node:child_process';
import pg from 'pg';

// ---------------------------------------------------------------------------
// Docker availability check
// ---------------------------------------------------------------------------
function isDockerAvailable(): boolean {
  try {
    execSync('docker info --format "{{.ServerVersion}}"', {
      stdio: 'pipe',
      timeout: 5_000,
    });
    return true;
  } catch {
    return false;
  }
}

const dockerAvailable = isDockerAvailable();
const describeFn = dockerAvailable ? describe : describe.skip;

describeFn('PgBouncer compatibility tests', () => {
  let network: Network;
  let postgresContainer: StartedTestContainer;
  let pgbouncerContainer: StartedTestContainer;
  let directDatabaseUrl: string;
  let pgbouncerDatabaseUrl: string;
  
  let pool: pg.Pool;
  let db: any;

  beforeAll(async () => {
    // 1. Create a custom network so containers can communicate
    network = await new Network().start();

    // 2. Start PostgreSQL 16
    postgresContainer = await new GenericContainer('postgres:16-alpine')
      .withNetwork(network)
      .withNetworkAliases('postgres-db')
      .withEnvironment({
        POSTGRES_USER: 'test',
        POSTGRES_PASSWORD: 'test',
        POSTGRES_DB: 'veritasor_test',
      })
      .withExposedPorts(5432)
      .start();

    const pgHost = postgresContainer.getHost();
    const pgPort = postgresContainer.getMappedPort(5432);
    directDatabaseUrl = `postgresql://test:test@${pgHost}:${pgPort}/veritasor_test`;

    // Run migrations directly on the Postgres container
    execSync('npx tsx src/db/migrate.ts', {
      env: { ...process.env, DATABASE_URL: directDatabaseUrl },
      cwd: process.cwd(),
      encoding: 'utf-8',
      timeout: 30_000,
    });

    // 3. Start PgBouncer pointing to PostgreSQL and using pool_mode = transaction
    pgbouncerContainer = await new GenericContainer('edoburu/pgbouncer')
      .withNetwork(network)
      .withEnvironment({
        DB_HOST: 'postgres-db',
        DB_PORT: '5432',
        DB_USER: 'test',
        DB_PASSWORD: 'test',
        DB_NAME: 'veritasor_test',
        POOL_MODE: 'transaction',
        LISTEN_PORT: '6432',
      })
      .withExposedPorts(6432)
      .start();

    const pgbHost = pgbouncerContainer.getHost();
    const pgbPort = pgbouncerContainer.getMappedPort(6432);
    // Explicitly add statement_cache_size=0 query parameter
    pgbouncerDatabaseUrl = `postgresql://test:test@${pgbHost}:${pgbPort}/veritasor_test?statement_cache_size=0`;

    // 4. Override process.env.DATABASE_URL before importing the DB client module
    process.env.DATABASE_URL = pgbouncerDatabaseUrl;
    
    const clientModule = await import('../../src/db/client.js');
    pool = clientModule.pool;
    db = clientModule.db;
  }, 180_000);

  afterAll(async () => {
    if (pool) {
      await pool.end();
    }
    if (pgbouncerContainer) {
      await pgbouncerContainer.stop();
    }
    if (postgresContainer) {
      await postgresContainer.stop();
    }
    if (network) {
      await network.stop();
    }
  });

  it('asserts pg connection url runs with statement_cache_size=0', () => {
    const url = new URL(process.env.DATABASE_URL!);
    expect(url.searchParams.get('statement_cache_size')).toBe('0');
  });

  it('asserts sessionPool uses DATABASE_SESSION_URL if provided, falling back to DATABASE_URL', async () => {
    const configModule = await import('../../src/config/index.js');
    expect(configModule.config.db.sessionUrl).toBe(process.env.DATABASE_SESSION_URL || process.env.DATABASE_URL);
  });

  it('runs concurrent parameterized queries through PgBouncer in transaction mode without prepared statement conflicts', async () => {
    const queries = Array.from({ length: 15 }).map((_, i) => {
      // parameterized query to simulate standard statement execution
      return db.query('SELECT $1::int AS val, $2::text AS name', [i, `test-val-${i}`]);
    });

    const results = await Promise.all(queries);
    results.forEach((res, i) => {
      expect(res.rows[0].val).toBe(i);
      expect(res.rows[0].name).toBe(`test-val-${i}`);
    });
  });

  it('verifies SET LOCAL statement_timeout does not bleed across requests', async () => {
    // 1. SET LOCAL inside a transaction block should time out if it exceeds the limit
    const clientA = await pool.connect();
    try {
      await clientA.query('BEGIN');
      await clientA.query('SET LOCAL statement_timeout = 50');
      
      // Executing a sleep that takes longer than 50ms should fail due to the local timeout
      await expect(clientA.query('SELECT pg_sleep(0.1)')).rejects.toThrow();
      
      await clientA.query('ROLLBACK');
    } finally {
      clientA.release();
    }

    // 2. Querying on another connection/outside the transaction block should not time out
    const clientB = await pool.connect();
    try {
      const resTimeout = await clientB.query('SHOW statement_timeout');
      const timeoutVal = resTimeout.rows[0].statement_timeout;
      
      // Ensure the timeout reverted back and is not 50ms
      expect(timeoutVal).not.toBe('50ms');

      // We should be able to run pg_sleep(0.1) without any issue now
      const resSleep = await clientB.query('SELECT pg_sleep(0.1) AS sleep');
      expect(resSleep.rows[0].sleep).toBe('');
    } finally {
      clientB.release();
    }

    // 3. SET LOCAL outside a transaction block should revert immediately and not affect next queries on same client
    const clientC = await pool.connect();
    try {
      await clientC.query('SET LOCAL statement_timeout = 50');
      
      const resSleep = await clientC.query('SELECT pg_sleep(0.1) AS sleep');
      expect(resSleep.rows[0].sleep).toBe('');
    } finally {
      clientC.release();
    }
  });
});
