/**
 * @vitest-environment node
 */
import { describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest';
import { ToxiproxyClient, latencyToxic, timeoutToxic, resetPeerToxic } from './toxiproxy-client.js';
import { db } from '../../src/db/client.js';
import { getRedisClient, resetRedisClient, redisHealthProbe } from '../../src/redis.js';

const describeChaos = process.env.CHAOS_TESTS ? describe : describe.skip;

describeChaos('Chaos Testing with Toxiproxy (Smoke)', () => {
  const toxiproxy = new ToxiproxyClient(process.env.TOXIPROXY_URL || 'http://localhost:8474');
  let pgProxy: Awaited<ReturnType<typeof toxiproxy.getOrCreateProxy>>;
  let redisProxy: Awaited<ReturnType<typeof toxiproxy.getOrCreateProxy>>;

  const PG_PROXY_NAME = 'postgres';
  const REDIS_PROXY_NAME = 'redis';

  const pgUpstream = process.env.PG_UPSTREAM || 'postgres:5432';
  const redisUpstream = process.env.REDIS_UPSTREAM || 'redis:6379';

  beforeAll(async () => {
    await toxiproxy.reset().catch(() => {});

    pgProxy = await toxiproxy.getOrCreateProxy({
      name: PG_PROXY_NAME,
      listen: '0.0.0.0:5432',
      upstream: pgUpstream,
    });

    redisProxy = await toxiproxy.getOrCreateProxy({
      name: REDIS_PROXY_NAME,
      listen: '0.0.0.0:6379',
      upstream: redisUpstream,
    });

    resetRedisClient();
    process.env.REDIS_URL = process.env.REDIS_URL || 'redis://localhost:6379';
  });

  afterEach(async () => {
    await pgProxy?.refreshToxics();
    await redisProxy?.refreshToxics();
    for (const t of [...(pgProxy?.toxics ?? [])]) {
      await pgProxy.removeToxic(t.name).catch(() => {});
    }
    for (const t of [...(redisProxy?.toxics ?? [])]) {
      await redisProxy.removeToxic(t.name).catch(() => {});
    }
  });

  afterAll(async () => {
    resetRedisClient();
  });

  it('Postgres - reset_peer forces connection drop', async () => {
    await pgProxy.addToxic(resetPeerToxic(50));
    try {
      await db.query('SELECT 1');
      expect.fail('Should have thrown due to reset_peer');
    } catch (error: any) {
      expect(error.message || error.code || '').toMatch(/reset|closed|terminated|ECONN/i);
    }
  });

  it('Postgres - latency with jitter adds measurable delay', async () => {
    await pgProxy.addToxic(latencyToxic(200, 50));
    const start = Date.now();
    try {
      await db.query('SELECT 1');
    } catch {
      // acceptable
    }
    const duration = Date.now() - start;
    expect(duration).toBeGreaterThanOrEqual(150);
  });

  it('Postgres - timeout toxic causes query failure', async () => {
    await pgProxy.addToxic(timeoutToxic(50));
    try {
      await db.query('SELECT pg_sleep(1)');
      expect.fail('Expected timeout');
    } catch (error: any) {
      const msg = error?.message || error?.code || String(error);
      expect(msg).toMatch(/timeout|closed|terminated|ECONN|ETIMEDOUT/i);
    }
  });

  it('Redis - latency with jitter delays PING response', async () => {
    await redisProxy.addToxic(latencyToxic(150, 50));
    const client = getRedisClient();
    const start = Date.now();
    try {
      await client.ping();
    } catch {
      // acceptable
    }
    const duration = Date.now() - start;
    expect(duration).toBeGreaterThanOrEqual(100);
  });

  it('Redis - timeout toxic triggers health probe error', async () => {
    await redisProxy.addToxic(timeoutToxic(10));
    const result = await redisHealthProbe();
    expect(result.startsWith('error:')).toBe(true);
  });

  it('Toxiproxy version is reachable', async () => {
    const version = await toxiproxy.version();
    expect(typeof version).toBe('string');
    expect(version.length).toBeGreaterThan(0);
  });
});
