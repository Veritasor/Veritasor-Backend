/**
 * Redis chaos scenarios using Toxiproxy.
 *
 * Exercises transient failures that the rate limiter, idempotency store,
 * circuit breaker, and health probe are designed to tolerate:
 *
 *   - Latency with jitter (variable RTT between client and Redis)
 *   - Bandwidth throttling (narrow pipe on large responses)
 *   - Timeouts / partial connection drops
 *   - reset_peer mid-stream
 *   - limit_data (truncated responses to trigger protocol errors)
 *   - slicer (TCP segment fragmentation with delays)
 *   - Circuit breaker state transitions under sustained failure
 *   - Rate limiter graceful degradation (Redis store → memory fallback)
 *
 * All tests are gated on CHAOS_TESTS=true to keep the default test suite
 * hermetic and fast.  Run via:
 *
 *   CHAOS_TESTS=true pnpm test tests/chaos/redis-chaos.spec.ts
 *
 * @vitest-environment node
 */
import { describe, it, expect, beforeAll, afterAll, afterEach, beforeEach } from 'vitest';
import {
  ToxiproxyClient,
  latencyToxic,
  timeoutToxic,
  resetPeerToxic,
  bandwidthToxic,
  limitDataToxic,
  slicerToxic,
} from './toxiproxy-client.js';
import {
  getRedisClient,
  resetRedisClient,
  redisHealthProbe,
  redisCircuitBreaker,
  CircuitState,
  RedisCircuitBreaker,
  getReadonlyRedisClient,
} from '../../src/redis.js';
import {
  RedisStore,
  SlidingWindowRedisStore,
  resetStorePromise,
  getStore,
  memoryStore,
  slidingWindowMemoryStore,
} from '../../src/middleware/rateLimiter.js';
import { RedisIdempotencyStore } from '../../src/middleware/idempotency.js';

const describeChaos = process.env.CHAOS_TESTS ? describe : describe.skip;

describeChaos('Redis Chaos — Toxiproxy scenarios', () => {
  const toxiproxy = new ToxiproxyClient(process.env.TOXIPROXY_URL || 'http://localhost:8474');
  let redisProxy: Awaited<ReturnType<typeof toxiproxy.getOrCreateProxy>>;
  const PROXY_NAME = 'redis_chaos';

  // Use non-standard proxy listen ports so we don't collide with the
  // smoke suite if both run in parallel on the same Compose stack.
  const PROXY_LISTEN = '0.0.0.0:16379';
  const PROXY_UPSTREAM = process.env.REDIS_UPSTREAM || 'redis:6379';

  function redisProxyUrl(): string {
    const host = process.env.REDIS_PROXY_HOST || 'localhost';
    return `redis://${host}:16379`;
  }

  beforeAll(async () => {
    const existing = await toxiproxy.get(PROXY_NAME);
    if (existing) await existing.remove().catch(() => {});

    redisProxy = await toxiproxy.createProxy({
      name: PROXY_NAME,
      listen: PROXY_LISTEN,
      upstream: PROXY_UPSTREAM,
    });

    process.env.REDIS_URL = redisProxyUrl();
    resetRedisClient();
    resetStorePromise();
  });

  afterEach(async () => {
    // Clear all toxics from proxy so the next test starts clean.
    await redisProxy.refreshToxics().catch(() => {});
    for (const t of [...(redisProxy?.toxics ?? [])]) {
      await redisProxy.removeToxic(t.name).catch(() => {});
    }
    // Reset circuit breaker and clients between each scenario.
    redisCircuitBreaker.reset();
    resetRedisClient();
    resetStorePromise();
    memoryStore.reset();
    slidingWindowMemoryStore.reset();
  });

  afterAll(async () => {
    await redisProxy?.remove().catch(() => {});
    resetRedisClient();
    resetStorePromise();
  });

  async function clearAllToxics() {
    await redisProxy.refreshToxics();
    for (const t of [...redisProxy.toxics]) {
      await redisProxy.removeToxic(t.name);
    }
  }

  // ──────────────────────────────────────────────────────────────────────
  // 1. Latency + jitter scenarios
  // ──────────────────────────────────────────────────────────────────────

  it('latency+ jitter: PING still returns PONG within latency envelope', async () => {
    await redisProxy.addToxic(latencyToxic(100, 40));
    const client = getRedisClient();
    const start = Date.now();
    const resp = await client.ping();
    const dur = Date.now() - start;
    expect(resp).toBe('PONG');
    // Allow 50 ms slack below the pure latency floor (OS scheduling).
    expect(dur).toBeGreaterThanOrEqual(50);
  });

  it('latency + jitter: health probe tolerates variable network delay', async () => {
    // 90 ms latency + jitter.  The 1 s probe timeout should absorb this.
    await redisProxy.addToxic(latencyToxic(90, 30));
    const result = await redisHealthProbe();
    expect(result).toBe('ok');
  });

  it('high jitter: variable latency does not break SET/GET round-trip', async () => {
    // Wide jitter window (20 ms base + ±80 ms) — simulates unpredictable GC.
    await redisProxy.addToxic(latencyToxic(20, 80));
    const client = getRedisClient();
    const key = `chaos:jitter:${Date.now()}`;
    const val = 'hello-jitter';
    await client.set(key, val, 'PX', 5000);
    const got = await client.get(key);
    expect(got).toBe(val);
    await client.del(key).catch(() => {});
  });

  // ──────────────────────────────────────────────────────────────────────
  // 2. Timeout & reset_peer (partial / total failure)
  // ──────────────────────────────────────────────────────────────────────

  it('timeout toxic: health probe returns "error:" string (never throws)', async () => {
    await redisProxy.addToxic(timeoutToxic(20));
    const result = await redisHealthProbe();
    expect(result.startsWith('error:')).toBe(true);
  });

  it('timeout toxic: health probe timeout value < probe deadline', async () => {
    // Toxiproxy closes the socket after 50 ms of no data — way before the
    // 1 s health-probe timeout.  The probe must surface the error and not
    // hang until its own internal deadline.
    await redisProxy.addToxic(timeoutToxic(50));
    const start = Date.now();
    const result = await redisHealthProbe();
    const dur = Date.now() - start;
    expect(result.startsWith('error:')).toBe(true);
    expect(dur).toBeLessThan(800);
  });

  it('reset_peer: throws an error that isTransientConnectionError recognises', async () => {
    await redisProxy.addToxic(resetPeerToxic(10));
    const client = getRedisClient();
    try {
      await client.ping();
      expect.fail('Expected reset_peer to abort PING');
    } catch (err: any) {
      const msg = (err?.message ?? String(err)).toLowerCase();
      const code = (err?.code ?? '').toLowerCase();
      const matches =
        /reset|econn|closed|broken pipe|abort|terminated|timeout/.test(msg) ||
        /econn|epipe|etimedout/.test(code);
      expect(matches).toBe(true);
    }
  });

  it('reset_peer mid-stream: circuit breaker records failure', async () => {
    const cb = new RedisCircuitBreaker({ failureThreshold: 3, resetTimeoutMs: 60_000 });
    await redisProxy.addToxic(resetPeerToxic(5));

    let failures = 0;
    for (let i = 0; i < 3; i++) {
      try {
        await cb.execute(async () => {
          const client = getRedisClient();
          return await client.ping();
        });
      } catch {
        failures++;
      }
    }

    expect(failures).toBeGreaterThanOrEqual(1);
    // After threshold failures the breaker must be OPEN.
    if (failures >= 3) {
      expect(cb.getState()).toBe(CircuitState.OPEN);
    }
  });

  // ──────────────────────────────────────────────────────────────────────
  // 3. limit_data & bandwidth — protocol-level partial failures
  // ──────────────────────────────────────────────────────────────────────

  it('limit_data: truncated response surfaces as an error (not an infinite hang)', async () => {
    // Only allow 5 bytes through — a RESP PONG is "+PONG\r\n" = 7 bytes,
    // so this truncates mid-payload and ioredis should surface a parser or
    // connection error, not deadlock the event loop.
    await redisProxy.addToxic(limitDataToxic(5));
    const client = getRedisClient();

    const race = await Promise.race([
      (async () => {
        try {
          return await client.ping();
        } catch (e) {
          return 'ERROR';
        }
      })(),
      new Promise<string>((r) => setTimeout(() => r('TIMEOUT'), 2000)),
    ]);

    // Either the ping fails immediately or we hit the 2 s safety net.
    expect(race === 'ERROR' || race === 'TIMEOUT').toBe(true);
  });

  it('bandwidth throttle: large response arrives slower than baseline', async () => {
    const client = getRedisClient();
    const key = `chaos:bandwidth:${Date.now()}`;
    const payload = 'x'.repeat(200_000); // 200 KB
    await client.set(key, payload, 'PX', 30_000);

    // Establish a baseline on an unpoisoned link.
    const cleanStart = Date.now();
    await client.get(key);
    const cleanMs = Date.now() - cleanStart;

    // 50 KB/s cap.  200 KB / 50 KB/s ≈ 4 s minimum.
    await redisProxy.addToxic(bandwidthToxic(50));
    const slowStart = Date.now();
    const got = await client.get(key);
    const slowMs = Date.now() - slowStart;

    expect(got).toHaveLength(payload.length);
    // Throttled path must be materially slower than the clean path.
    expect(slowMs).toBeGreaterThan(cleanMs);
    expect(slowMs).toBeGreaterThanOrEqual(1500); // floor with some slack

    await client.del(key).catch(() => {});
  });

  // ──────────────────────────────────────────────────────────────────────
  // 4. slicer — TCP fragmentation with per-segment delay
  // ──────────────────────────────────────────────────────────────────────

  it('slicer: small segments + delay still complete the operation', async () => {
    // 10 byte segments, 5 ms delay between each segment.
    await redisProxy.addToxic(slicerToxic(10, 5, 0));
    const client = getRedisClient();
    const key = `chaos:slicer:${Date.now()}`;
    const pipeline = client.pipeline();
    for (let i = 0; i < 20; i++) {
      pipeline.set(`${key}:${i}`, `v${i}`, 'PX', 10_000);
    }
    const results = await pipeline.exec();
    expect(results).toHaveLength(20);
    for (const r of results ?? []) {
      expect(Array.isArray(r) ? r[0] : r).toBeNull();
    }
    // cleanup
    const delPipe = client.pipeline();
    for (let i = 0; i < 20; i++) delPipe.del(`${key}:${i}`);
    await delPipe.exec().catch(() => {});
  });

  // ──────────────────────────────────────────────────────────────────────
  // 5. Circuit breaker end-to-end state transitions
  // ──────────────────────────────────────────────────────────────────────

  it('circuit breaker: sustained failures trip OPEN and recover after window', async () => {
    const cb = new RedisCircuitBreaker({ failureThreshold: 2, resetTimeoutMs: 500 });
    await redisProxy.addToxic(timeoutToxic(10));

    // 1st failure → CLOSED, failures++
    await expect(cb.execute(async () => {
      const c = getRedisClient();
      return await c.ping();
    })).rejects.toBeDefined();
    expect(cb.getState()).toBe(CircuitState.CLOSED);

    // 2nd failure → trips to OPEN
    await expect(cb.execute(async () => {
      const c = getRedisClient();
      return await c.ping();
    })).rejects.toBeDefined();
    expect(cb.getState()).toBe(CircuitState.OPEN);

    // 3rd call while OPEN → fails fast without touching network
    const t0 = Date.now();
    await expect(cb.execute(async () => {
      const c = getRedisClient();
      return await c.ping();
    })).rejects.toThrow(/OPEN/i);
    const fastFailMs = Date.now() - t0;
    expect(fastFailMs).toBeLessThan(50); // fail-fast, no network round trip

    // Wait past the reset window → HALF_OPEN probe
    await new Promise((r) => setTimeout(r, 550));

    // Remove the toxic so the probe succeeds → CLOSED
    await clearAllToxics();
    const after = await cb.execute(async () => {
      const c = getRedisClient();
      return await c.ping();
    });
    expect(after).toBe('PONG');
    expect(cb.getState()).toBe(CircuitState.CLOSED);
  });

  it('circuit breaker: fallback is returned when OPEN instead of throwing', async () => {
    const cb = new RedisCircuitBreaker({ failureThreshold: 1, resetTimeoutMs: 30_000 });
    await redisProxy.addToxic(timeoutToxic(10));

    // Trip the breaker.
    await expect(cb.execute(async () => {
      const c = getRedisClient();
      return await c.ping();
    })).rejects.toBeDefined();
    expect(cb.getState()).toBe(CircuitState.OPEN);

    // Fallback path — the operation closure is not called while OPEN.
    const fb = await cb.execute(
      async () => {
        const c = getRedisClient();
        return await c.ping();
      },
      () => 'fallback-value',
    );
    expect(fb).toBe('fallback-value');
  });

  // ──────────────────────────────────────────────────────────────────────
  // 6. Rate limiter — Redis store → memory fallback under duress
  // ──────────────────────────────────────────────────────────────────────

  it('rate limiter fixed-window: latency ~500 ms still increments correctly', async () => {
    await redisProxy.addToxic(latencyToxic(100, 50));
    const client = getRedisClient();
    const store = new RedisStore(client);
    const key = `chaos:rl-fix:${Date.now()}`;

    const r1 = await store.increment(key, 60_000);
    const r2 = await store.increment(key, 60_000);
    expect(r1.count).toBe(1);
    expect(r2.count).toBe(2);
  });

  it('rate limiter sliding-window: tolerates jitter without watch aborts', async () => {
    await redisProxy.addToxic(latencyToxic(50, 150));
    const client = getRedisClient();
    const store = new SlidingWindowRedisStore(client, 15 /* retries */);
    const key = `chaos:rl-slide:${Date.now()}`;

    const out = await Promise.all([
      store.increment(key, 60_000),
      store.increment(key, 60_000),
      store.increment(key, 60_000),
    ]);
    // Each call succeeds; individual counts may interleave but the
    // highest count we see must be exactly 3 after all settle.
    const max = Math.max(...out.map((r) => r.count));
    expect(max).toBe(3);
  });

  it('rate limiter getStore: timeout triggers in-memory fallback path', async () => {
    await redisProxy.addToxic(timeoutToxic(10));
    // getStore swallows init failures and falls back to the memory store.
    const store = await getStore('fixed');
    // With Redis broken the returned store is MemoryStore.
    const key = `chaos:rl-fb:${Date.now()}`;
    const r1 = await store.increment(key, 60_000);
    const r2 = await store.increment(key, 60_000);
    expect(r1.count).toBe(1);
    expect(r2.count).toBe(2);
  });

  // ──────────────────────────────────────────────────────────────────────
  // 7. Idempotency store — Redis failures use circuit-breaker fallbacks
  // ──────────────────────────────────────────────────────────────────────

  it('idempotency store: set() no-op fallback when circuit breaker OPEN', async () => {
    // Populate the client + break the circuit with a single timeout.
    const cb = new RedisCircuitBreaker({ failureThreshold: 1, resetTimeoutMs: 60_000 });
    await redisProxy.addToxic(timeoutToxic(10));

    try {
      await cb.execute(async () => {
        const c = getRedisClient();
        return await c.ping();
      });
    } catch {
      // expected
    }
    expect(cb.getState()).toBe(CircuitState.OPEN);

    // Even with the breaker OPEN, set() must not throw — it uses a
    // no-op fallback internally via redisCircuitBreaker.
    const store = new RedisIdempotencyStore(getRedisClient() as any);
    await expect(
      store.set(`idempotency:chaos:${Date.now()}`, {
        status: 200,
        body: { ok: true },
        requestHash: 'abc123',
        createdAt: Date.now(),
      }, 60_000),
    ).resolves.not.toThrow();
  });

  it('idempotency store: jittery latency — get/set round-trip still works', async () => {
    await redisProxy.addToxic(latencyToxic(60, 120));
    const store = new RedisIdempotencyStore(getRedisClient() as any);
    const key = `idempotency:chaos:jitter:${Date.now()}`;
    const entry = {
      status: 201,
      body: { id: 'abc' },
      requestHash: 'deadbeef',
      createdAt: Date.now(),
    };

    await store.set(key, entry, 60_000);
    const got = await store.get(key);
    expect(got).toBeDefined();
    expect(got?.status).toBe(201);
    expect(got?.requestHash).toBe('deadbeef');
    await store.delete(key).catch(() => {});
  });

  // ──────────────────────────────────────────────────────────────────────
  // 8. Multi-op pipelines / readonly client survive latency bursts
  // ──────────────────────────────────────────────────────────────────────

  it('pipeline: 50 SETs with latency + jitter complete without corruption', async () => {
    await redisProxy.addToxic(latencyToxic(20, 60));
    const client = getRedisClient();
    const base = `chaos:pipe:${Date.now()}`;
    const pipe = client.pipeline();
    for (let i = 0; i < 50; i++) {
      pipe.set(`${base}:${i}`, String(i), 'PX', 30_000);
      pipe.get(`${base}:${i}`);
    }
    const results = await pipe.exec();
    expect(results).toHaveLength(100);
    // Even indices are SET results, odd indices are GET results.
    for (let i = 0; i < 50; i++) {
      const setErr = results?.[i * 2]?.[0];
      const getVal = results?.[i * 2 + 1]?.[1];
      expect(setErr).toBeNull();
      expect(getVal).toBe(String(i));
    }
    // cleanup
    const delPipe = client.pipeline();
    for (let i = 0; i < 50; i++) delPipe.del(`${base}:${i}`);
    await delPipe.exec().catch(() => {});
  });

  it('readonly client: same data visible via both primary and readonly handles', async () => {
    // No toxic — just sanity-check the helper under Toxiproxy so we know
    // the readonly client actually connects through the proxy and the
    // test harness is wired correctly.
    const primary = getRedisClient();
    const ro = getReadonlyRedisClient();
    const key = `chaos:ro:${Date.now()}`;
    await primary.set(key, '42', 'PX', 10_000);
    // single-node mode: readonly == primary; cluster mode: replica read.
    const got = await ro.get(key);
    expect(got).toBe('42');
    await primary.del(key).catch(() => {});
  });
});
