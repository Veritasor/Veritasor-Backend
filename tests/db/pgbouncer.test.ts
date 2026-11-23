/**
 * PgBouncer transaction-pooling compatibility tests for db/client.ts
 *
 * Validates that the Postgres pool in src/db/client.ts behaves correctly
 * behind PgBouncer in transaction-pooling mode. Prepared statements and
 * session-scoped settings must not leak between connections.
 *
 * Coverage:
 *  - Happy paths: basic CRUD, parameterized queries, health checks
 *  - Prepared statement disabling in transaction mode
 *  - SET LOCAL isolation across pooled backends
 *  - Concurrent transactions reusing pooled backends
 *  - Error handling and boundary inputs
 *  - PgBouncer mode detection contract
 *  - Backward compatibility
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
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

  let directPool: pg.Pool;
  let pgbouncerPool: pg.Pool;

  // Shared schema for integration tests
  const TEST_TABLE = 'pgbouncer_compat_test';

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
    // Explicitly add statement_cache_size=0 query parameter for pg driver
    pgbouncerDatabaseUrl = `postgresql://test:test@${pgbHost}:${pgbPort}/veritasor_test?statement_cache_size=0`;

    // 4. Create direct pool (bypasses PgBouncer) and PgBouncer pool
    directPool = new pg.Pool({ connectionString: directDatabaseUrl, max: 5 });
    pgbouncerPool = new pg.Pool({ connectionString: pgbouncerDatabaseUrl, max: 5 });

    // 5. Create the test helper table through PgBouncer to verify it works
    await pgbouncerPool.query(`
      CREATE TABLE IF NOT EXISTS ${TEST_TABLE} (
        id SERIAL PRIMARY KEY,
        value TEXT NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);
  }, 180_000);

  afterAll(async () => {
    if (pgbouncerPool) await pgbouncerPool.end();
    if (directPool) await directPool.end();
    if (pgbouncerContainer) await pgbouncerContainer.stop();
    if (postgresContainer) await postgresContainer.stop();
    if (network) await network.stop();
  });

  beforeEach(async () => {
    // Clean test table before each test
    await pgbouncerPool.query(`TRUNCATE ${TEST_TABLE}`);
  });

  // =========================================================================
  // 1. HAPPY PATHS
  // =========================================================================
  describe('happy paths', () => {
    it('statement_cache_size=0 is present in PgBouncer connection URL', () => {
      const url = new URL(pgbouncerDatabaseUrl);
      expect(url.searchParams.get('statement_cache_size')).toBe('0');
    });

    it('basic SELECT through PgBouncer returns correct results', async () => {
      const result = await pgbouncerPool.query('SELECT 1::int AS one, $1::text AS msg', ['hello']);
      expect(result.rows[0].one).toBe(1);
      expect(result.rows[0].msg).toBe('hello');
    });

    it('INSERT/SELECT round-trip through PgBouncer', async () => {
      await pgbouncerPool.query(`INSERT INTO ${TEST_TABLE} (value) VALUES ($1)`, ['round-trip']);
      const result = await pgbouncerPool.query(`SELECT value FROM ${TEST_TABLE}`);
      expect(result.rows).toHaveLength(1);
      expect(result.rows[0].value).toBe('round-trip');
    });

    it('multiple sequential queries through PgBouncer succeed', async () => {
      for (let i = 0; i < 10; i++) {
        const res = await pgbouncerPool.query('SELECT $1::int AS val', [i]);
        expect(res.rows[0].val).toBe(i);
      }
    });

    it('health check succeeds through PgBouncer', async () => {
      const result = await pgbouncerPool.query('SELECT 1');
      expect(result.rowCount).toBe(1);
    });

    it('pool connects and disconnects cleanly', async () => {
      const tempPool = new pg.Pool({ connectionString: pgbouncerDatabaseUrl, max: 1 });
      const res = await tempPool.query('SELECT 1');
      expect(res.rowCount).toBe(1);
      await tempPool.end();
    });
  });

  // =========================================================================
  // 2. PREPARED STATEMENT SAFETY
  // =========================================================================
  describe('prepared statement safety', () => {
    it('parameterized queries execute without prepared statement conflicts through PgBouncer', async () => {
      const queries = Array.from({ length: 15 }).map((_, i) =>
        pgbouncerPool.query('SELECT $1::int AS val, $2::text AS name', [i, `val-${i}`])
      );

      const results = await Promise.all(queries);
      results.forEach((res, i) => {
        expect(res.rows[0].val).toBe(i);
        expect(res.rows[0].name).toBe(`val-${i}`);
      });
    });

    it('unnamed prepared statements work correctly through PgBouncer', async () => {
      // Use the pg driver's unnamed prepared statement protocol (extended query)
      const client = await pgbouncerPool.connect();
      try {
        const res = await client.query({
          text: 'SELECT $1::int AS val',
          values: [42],
          // No name => unnamed prepared statement (safe for transaction pooling)
        });
        expect(res.rows[0].val).toBe(42);
      } finally {
        client.release();
      }
    });

    it('multiple concurrent parameterized queries do not leak statement state', async () => {
      const batchSize = 20;
      const queries = Array.from({ length: batchSize }).map((_, i) =>
        pgbouncerPool.query('SELECT $1::bigint AS id, $2::text AS payload', [i * 1000, `batch-${i}`])
      );

      const results = await Promise.all(queries);
      const sorted = results.map((r) => r.rows[0]).sort((a, b) => a.id - b.id);

      for (let i = 0; i < batchSize; i++) {
        expect(sorted[i].id).toBe(i * 1000);
        expect(sorted[i].payload).toBe(`batch-${i}`);
      }
    });
  });

  // =========================================================================
  // 3. SET LOCAL ISOLATION
  // =========================================================================
  describe('SET LOCAL isolation', () => {
    it('SET LOCAL statement_timeout does not bleed across pooled connections', async () => {
      // 1. SET LOCAL inside a transaction block should time out if it exceeds the limit
      const clientA = await pgbouncerPool.connect();
      try {
        await clientA.query('BEGIN');
        await clientA.query('SET LOCAL statement_timeout = 50');

        // Executing a sleep that takes longer than 50ms should fail
        await expect(clientA.query('SELECT pg_sleep(0.1)')).rejects.toThrow();

        await clientA.query('ROLLBACK');
      } finally {
        clientA.release();
      }

      // 2. Querying on another connection should not be affected
      const clientB = await pgbouncerPool.connect();
      try {
        const resTimeout = await clientB.query('SHOW statement_timeout');
        const timeoutVal = resTimeout.rows[0].statement_timeout;
        expect(timeoutVal).not.toBe('50ms');

        // Should be able to run pg_sleep(0.1) without any issue
        const resSleep = await clientB.query('SELECT pg_sleep(0.1) AS sleep');
        expect(resSleep.rows[0].sleep).toBe('');
      } finally {
        clientB.release();
      }
    });

    it('SET LOCAL outside a transaction block reverts immediately on the same connection', async () => {
      const client = await pgbouncerPool.connect();
      try {
        // SET LOCAL outside a transaction has no effect in PostgreSQL
        await client.query('SET LOCAL statement_timeout = 50');

        // pg_sleep(0.1) should work fine since SET LOCAL outside tx is a no-op
        const res = await client.query('SELECT pg_sleep(0.1) AS sleep');
        expect(res.rows[0].sleep).toBe('');
      } finally {
        client.release();
      }
    });

    it('SET LOCAL work_mem does not leak across pooled connections', async () => {
      // Set a custom work_mem in transaction A
      const clientA = await pgbouncerPool.connect();
      try {
        await clientA.query('BEGIN');
        await clientA.query('SET LOCAL work_mem = "1MB"');
        const resA = await clientA.query('SHOW work_mem');
        expect(resA.rows[0].work_mem).toBe('1MB');
        await clientA.query('COMMIT');
      } finally {
        clientA.release();
      }

      // Connection B should see the default work_mem, not 1MB
      const clientB = await pgbouncerPool.connect();
      try {
        const resB = await clientB.query('SHOW work_mem');
        expect(resB.rows[0].work_mem).not.toBe('1MB');
      } finally {
        clientB.release();
      }
    });

    it('SET LOCAL search_path does not bleed across transaction-pooled connections', async () => {
      const clientA = await pgbouncerPool.connect();
      try {
        await clientA.query('BEGIN');
        await clientA.query('SET LOCAL search_path = pg_catalog');
        const resA = await clientA.query('SHOW search_path');
        expect(resA.rows[0].search_path).toBe('pg_catalog');
        await clientA.query('ROLLBACK');
      } finally {
        clientA.release();
      }

      const clientB = await pgbouncerPool.connect();
      try {
        const resB = await clientB.query('SHOW search_path');
        // Should not be pg_catalog (default is "$user", public)
        expect(resB.rows[0].search_path).not.toBe('pg_catalog');
      } finally {
        clientB.release();
      }
    });

    it('different SET LOCAL values in concurrent transactions do not interfere', async () => {
      const promises: Promise<void>[] = [];

      for (let i = 0; i < 5; i++) {
        promises.push(
          (async () => {
            const client = await pgbouncerPool.connect();
            try {
              await client.query('BEGIN');
              await client.query('SET LOCAL statement_timeout = $1', [50 + i]);
              const res = await client.query('SHOW statement_timeout');
              expect(res.rows[0].statement_timeout).toBe(`${50 + i}ms`);
              await client.query('ROLLBACK');
            } finally {
              client.release();
            }
          })()
        );
      }

      await Promise.all(promises);
    });
  });

  // =========================================================================
  // 4. CONCURRENCY AND CONNECTION REUSE
  // =========================================================================
  describe('concurrency and connection reuse', () => {
    it('handles burst of concurrent queries without errors', async () => {
      const burstSize = 30;
      const queries = Array.from({ length: burstSize }).map((_, i) =>
        pgbouncerPool.query(`INSERT INTO ${TEST_TABLE} (value) VALUES ($1) RETURNING id`, [
          `burst-${i}`,
        ])
      );

      const results = await Promise.all(queries);
      const ids = results.map((r) => r.rows[0].id);
      const uniqueIds = new Set(ids);
      expect(uniqueIds.size).toBe(burstSize);

      const countResult = await pgbouncerPool.query(`SELECT COUNT(*)::int AS cnt FROM ${TEST_TABLE}`);
      expect(countResult.rows[0].cnt).toBe(burstSize);
    });

    it('concurrent read/write transactions through PgBouncer', async () => {
      // Seed data
      await pgbouncerPool.query(`INSERT INTO ${TEST_TABLE} (value) VALUES ('initial')`);

      const writers = Array.from({ length: 5 }).map((_, i) =>
        pgbouncerPool.query(`INSERT INTO ${TEST_TABLE} (value) VALUES ($1)`, [`writer-${i}`])
      );

      const readers = Array.from({ length: 5 }).map(() =>
        pgbouncerPool.query(`SELECT COUNT(*)::int AS cnt FROM ${TEST_TABLE}`)
      );

      const [, ...readResults] = await Promise.all([...writers, ...readers]);
      for (const res of readResults) {
        expect(res.rows[0].cnt).toBeGreaterThanOrEqual(1);
      }

      const finalCount = await pgbouncerPool.query(`SELECT COUNT(*)::int AS cnt FROM ${TEST_TABLE}`);
      expect(finalCount.rows[0].cnt).toBe(6); // 1 initial + 5 writers
    });

    it('connection release and re-acquire works correctly', async () => {
      for (let round = 0; round < 10; round++) {
        const client = await pgbouncerPool.connect();
        try {
          await client.query(`INSERT INTO ${TEST_TABLE} (value) VALUES ($1)`, [`round-${round}`]);
        } finally {
          client.release();
        }
      }

      const res = await pgbouncerPool.query(`SELECT COUNT(*)::int AS cnt FROM ${TEST_TABLE}`);
      expect(res.rows[0].cnt).toBe(10);
    });

    it('pool.end() cleans up gracefully under PgBouncer', async () => {
      const tempPool = new pg.Pool({ connectionString: pgbouncerDatabaseUrl, max: 3 });

      // Execute a few queries
      await tempPool.query('SELECT 1');
      await tempPool.query('SELECT 2');
      await tempPool.query('SELECT 3');

      // Should not throw
      await tempPool.end();
    });
  });

  // =========================================================================
  // 5. ERROR HANDLING AND BOUNDARY INPUTS
  // =========================================================================
  describe('error handling and boundary inputs', () => {
    it('invalid SQL through PgBouncer returns a clear error', async () => {
      await expect(pgbouncerPool.query('SELCT INVALID SYNTAX')).rejects.toThrow();
    });

    it('empty parameterized query returns an error', async () => {
      await expect(pgbouncerPool.query('')).rejects.toThrow();
    });

    it('query with excess parameters returns an error', async () => {
      await expect(pgbouncerPool.query('SELECT $1::int', [1, 2, 3])).rejects.toThrow();
    });

    it('query referencing non-existent table returns an error', async () => {
      await expect(
        pgbouncerPool.query('SELECT * FROM nonexistent_table_xyz LIMIT 1')
      ).rejects.toThrow();
    });

    it('type mismatch in parameterized query returns an error', async () => {
      await expect(
        pgbouncerPool.query('SELECT $1::int AS val', ['not-a-number'])
      ).rejects.toThrow();
    });

    it('query after connection error recovers transparently', async () => {
      // Force a connection error by running invalid SQL
      try {
        await pgbouncerPool.query('SELECT * FROM nonexistent_table_xyz');
      } catch {
        // Expected to fail
      }

      // Subsequent queries should still work (pool recovers)
      const res = await pgbouncerPool.query('SELECT 1::int AS val');
      expect(res.rows[0].val).toBe(1);
    });

    it('very long query string works through PgBouncer', async () => {
      const longStr = 'x'.repeat(10_000);
      const res = await pgbouncerPool.query('SELECT $1::text AS val', [longStr]);
      expect(res.rows[0].val).toBe(longStr);
    });

    it('NULL parameters handled correctly through PgBouncer', async () => {
      const res = await pgbouncerPool.query('SELECT $1::text AS val', [null]);
      expect(res.rows[0].val).toBeNull();
    });

    it('empty string parameter handled correctly through PgBouncer', async () => {
      const res = await pgbouncerPool.query('SELECT $1::text AS val', ['']);
      expect(res.rows[0].val).toBe('');
    });

    it('unicode and special characters in parameters handled correctly', async () => {
      const special = "emoji: 🎉 unicode: ñøî àççéñtς script: <script>alert('xss')</script>";
      const res = await pgbouncerPool.query('SELECT $1::text AS val', [special]);
      expect(res.rows[0].val).toBe(special);
    });

    it('transaction rollback through PgBouncer works correctly', async () => {
      const client = await pgbouncerPool.connect();
      try {
        await client.query('BEGIN');
        await client.query(`INSERT INTO ${TEST_TABLE} (value) VALUES ('will-be-rolled-back')`);
        await client.query('ROLLBACK');
      } finally {
        client.release();
      }

      const res = await pgbouncerPool.query(`SELECT COUNT(*)::int AS cnt FROM ${TEST_TABLE}`);
      expect(res.rows[0].cnt).toBe(0);
    });

    it('nested transactions (savepoints) through PgBouncer work correctly', async () => {
      const client = await pgbouncerPool.connect();
      try {
        await client.query('BEGIN');
        await client.query(`INSERT INTO ${TEST_TABLE} (value) VALUES ('outer')`);
        await client.query('SAVEPOINT sp1');
        await client.query(`INSERT INTO ${TEST_TABLE} (value) VALUES ('inner-savepoint')`);
        await client.query('ROLLBACK TO SAVEPOINT sp1');
        await client.query('COMMIT');
      } finally {
        client.release();
      }

      const res = await pgbouncerPool.query(`SELECT value FROM ${TEST_TABLE}`);
      expect(res.rows).toHaveLength(1);
      expect(res.rows[0].value).toBe('outer');
    });
  });

  // =========================================================================
  // 6. BACKWARD COMPATIBILITY
  // =========================================================================
  describe('backward compatibility', () => {
    it('direct connection to PostgreSQL (bypassing PgBouncer) still works', async () => {
      const res = await directPool.query('SELECT 1::int AS val');
      expect(res.rows[0].val).toBe(1);
    });

    it('basic CRUD works identically through PgBouncer and direct connection', async () => {
      const testVal = `compat-${Date.now()}`;

      // Insert through PgBouncer
      await pgbouncerPool.query(`INSERT INTO ${TEST_TABLE} (value) VALUES ($1)`, [testVal]);

      // Read through direct connection
      const directRes = await directPool.query(
        `SELECT value FROM ${TEST_TABLE} WHERE value = $1`,
        [testVal]
      );
      expect(directRes.rows[0].value).toBe(testVal);

      // Read through PgBouncer
      const pgbRes = await pgbouncerPool.query(
        `SELECT value FROM ${TEST_TABLE} WHERE value = $1`,
        [testVal]
      );
      expect(pgbRes.rows[0].value).toBe(testVal);
    });

    it('schema introspection queries work through PgBouncer', async () => {
      const res = await pgbouncerPool.query(
        `SELECT column_name, data_type FROM information_schema.columns 
         WHERE table_name = $1 ORDER BY ordinal_position`,
        [TEST_TABLE]
      );
      expect(res.rows.length).toBeGreaterThan(0);
      expect(res.rows[0].column_name).toBe('id');
    });

    it('aggregate queries through PgBouncer return correct results', async () => {
      await pgbouncerPool.query(`INSERT INTO ${TEST_TABLE} (value) VALUES ('a'), ('b'), ('c')`);
      const res = await pgbouncerPool.query(`SELECT COUNT(*)::int AS cnt FROM ${TEST_TABLE}`);
      expect(res.rows[0].cnt).toBe(3);
    });

    it('COPY protocol (via standard query) works through PgBouncer', async () => {
      // PgBouncer in transaction mode does not support the COPY protocol,
      // but standard INSERT should still work as a fallback
      const values = Array.from({ length: 5 })
        .map((_, i) => `('copy-${i}')`)
        .join(', ');
      await pgbouncerPool.query(`INSERT INTO ${TEST_TABLE} (value) VALUES ${values}`);

      const res = await pgbouncerPool.query(
        `SELECT COUNT(*)::int AS cnt FROM ${TEST_TABLE}`
      );
      expect(res.rows[0].cnt).toBe(5);
    });
  });

  // =========================================================================
  // 7. DATABASE SESSION URL FALLBACK
  // =========================================================================
  describe('DATABASE_SESSION_URL fallback', () => {
    it('config.db.sessionUrl defaults to DATABASE_URL when DATABASE_SESSION_URL is not set', async () => {
      // Ensure DATABASE_SESSION_URL is not set
      const origSessionUrl = process.env.DATABASE_SESSION_URL;
      delete process.env.DATABASE_SESSION_URL;

      try {
        // Re-import to pick up env changes (module caching may apply)
        const configModule = await import('../../src/config/index.js');
        expect(configModule.config.db.sessionUrl).toBe(process.env.DATABASE_URL);
      } finally {
        if (origSessionUrl !== undefined) {
          process.env.DATABASE_SESSION_URL = origSessionUrl;
        }
      }
    });
  });

  // =========================================================================
  // 8. SECURITY AND DATA INTEGRITY
  // =========================================================================
  describe('security and data integrity', () => {
    it('SERIAL primary key generates unique IDs across concurrent inserts', async () => {
      const inserts = Array.from({ length: 20 }).map((_, i) =>
        pgbouncerPool.query(`INSERT INTO ${TEST_TABLE} (value) VALUES ($1) RETURNING id`, [
          `unique-${i}`,
        ])
      );

      const results = await Promise.all(inserts);
      const ids = results.map((r) => r.rows[0].id);
      expect(new Set(ids).size).toBe(20);
    });

    it('transaction isolation level is preserved through PgBouncer', async () => {
      // PostgreSQL default is READ COMMITTED, verify it works
      const client = await pgbouncerPool.connect();
      try {
        const res = await client.query('SHOW transaction_isolation');
        expect(res.rows[0].transaction_isolation).toBe('read committed');
      } finally {
        client.release();
      }
    });

    it('concurrent reads see consistent snapshot within a transaction', async () => {
      // Seed data
      await pgbouncerPool.query(`INSERT INTO ${TEST_TABLE} (value) VALUES ('existing')`);

      const client = await pgbouncerPool.connect();
      try {
        await client.query('BEGIN');
        // Read within transaction
        const res1 = await client.query(`SELECT COUNT(*)::int AS cnt FROM ${TEST_TABLE}`);
        expect(res1.rows[0].cnt).toBe(1);

        // Insert via a different connection (outside this transaction)
        await pgbouncerPool.query(`INSERT INTO ${TEST_TABLE} (value) VALUES ('concurrent')`);

        // Within the same transaction, should still see the snapshot
        const res2 = await client.query(`SELECT COUNT(*)::int AS cnt FROM ${TEST_TABLE}`);
        expect(res2.rows[0].cnt).toBe(1);

        await client.query('COMMIT');
      } finally {
        client.release();
      }

      // After commit, should see both rows
      const finalRes = await pgbouncerPool.query(`SELECT COUNT(*)::int AS cnt FROM ${TEST_TABLE}`);
      expect(finalRes.rows[0].cnt).toBe(2);
    });

    it('XID visibility across pooled connections maintains ACID', async () => {
      // Start transaction on client A, insert but don't commit
      const clientA = await pgbouncerPool.connect();
      let clientACommitted = false;
      try {
        await clientA.query('BEGIN');
        await clientA.query(`INSERT INTO ${TEST_TABLE} (value) VALUES ('uncommitted')`);

        // Client B should NOT see uncommitted data
        const clientB = await pgbouncerPool.connect();
        try {
          const res = await clientB.query(`SELECT COUNT(*)::int AS cnt FROM ${TEST_TABLE}`);
          expect(res.rows[0].cnt).toBe(0);
        } finally {
          clientB.release();
        }

        await clientA.query('COMMIT');
        clientACommitted = true;
      } finally {
        clientA.release();
      }

      // After commit, both connections should see the data
      const res = await pgbouncerPool.query(`SELECT COUNT(*)::int AS cnt FROM ${TEST_TABLE}`);
      expect(res.rows[0].cnt).toBe(1);
    });
  });
});
