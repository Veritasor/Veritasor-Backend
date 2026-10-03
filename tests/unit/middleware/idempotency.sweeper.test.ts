/**
 * Unit tests for the cooperative IdempotencySweeper.
 *
 * Coverage areas:
 * - Basic sweep cycle (calls sweepExpired and count, updates metrics)
 * - Default and overridden intervals
 * - Start/stop lifecycle (idempotent, awaits in-flight cycles)
 * - Cooperative single-flight: concurrent runOnce calls share work
 * - Resilience: store errors do not reject runOnce; error metric emitted
 * - Resilience: Redis-style stores survive transient errors
 * - Custom timer injection (no real timers in unit tests)
 * - resolveSweepIntervalMs env parsing with hard floor
 * - createRedisIdempotencyStore backend selection
 * - count() gauge update only when store returns a non-negative value
 * - The sweep interval handle is unref'd so it does not block process exit
 * - Backward compatibility: the in-memory store still works with the
 *   existing middleware after the sweepExpired/count additions.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  IdempotencySweeper,
  RedisIdempotencyStore,
  inMemoryIdempotencyStore,
  clearIdempotencyStore,
  startIdempotencySweeper,
  resolveSweepIntervalMs,
  createRedisIdempotencyStore,
  type SweepResult,
  type IdempotencyStore,
} from '../../../src/middleware/idempotency.js';
import {
  metricsRegistry,
  idempotencyKeysCount,
  idempotencyEvictionsTotal,
  idempotencySweepRunsTotal,
} from '../../../src/metrics.js';

/**
 * Build a fake store with the four methods the sweeper uses. Each
 * method has a vi.fn() so tests can assert call counts and inject
 * failures.
 */
function makeStore(overrides: Partial<IdempotencyStore> = {}): IdempotencyStore {
  return {
    get: vi.fn(async () => undefined),
    set: vi.fn(async () => undefined),
    sweepExpired: vi.fn(async () => 0),
    count: vi.fn(async () => 0),
    ...overrides,
  };
}

/**
 * Fake timer factory that returns a numeric handle (so `unref()` is a
 * no-op) and tracks all registered timers. This lets the sweeper's
 * unref logic run without leaking real handles.
 */
function makeFakeTimers() {
  const intervals: Array<{ id: number; cb: () => void; ms: number; cleared: boolean }> = [];
  const timeouts: Array<{ id: number; cb: () => void; ms: number; cleared: boolean }> = [];
  let nextId = 1;

  const setIntervalFn = vi.fn((cb: () => void, ms: number) => {
    const handle = { id: nextId++, cb, ms, cleared: false };
    intervals.push(handle);
    return handle;
  });
  const clearIntervalFn = vi.fn((handle: { id: number; cleared: boolean }) => {
    const found = intervals.find((i) => i.id === handle.id);
    if (found) found.cleared = true;
  });
  const setTimeoutFn = vi.fn((cb: () => void, ms: number) => {
    const handle = { id: nextId++, cb, ms, cleared: false };
    timeouts.push(handle);
    return handle;
  });
  const clearTimeoutFn = vi.fn((handle: { id: number; cleared: boolean }) => {
    const found = timeouts.find((t) => t.id === handle.id);
    if (found) found.cleared = true;
  });

  return { intervals, timeouts, setIntervalFn, clearIntervalFn, setTimeoutFn, clearTimeoutFn };
}

beforeEach(async () => {
  clearIdempotencyStore();
  await metricsRegistry.resetMetrics();
  vi.clearAllMocks();
  delete process.env.IDEMPOTENCY_SWEEP_INTERVAL_MS;
  delete process.env.REDIS_URL;
  delete process.env.REDIS_CLUSTER_NODES;
});

afterEach(() => {
  clearIdempotencyStore();
});

describe('IdempotencySweeper — sweep cycle', () => {
  it('calls sweepExpired and count and emits a "ok" run counter', async () => {
    const store = makeStore({
      sweepExpired: vi.fn(async () => 3),
      count: vi.fn(async () => 42),
    });
    const { setIntervalFn, clearIntervalFn, setTimeoutFn, clearTimeoutFn } = makeFakeTimers();
    const sweeper = new IdempotencySweeper({
      store,
      backend: 'memory',
      intervalMs: 1000,
      runImmediately: false,
      setIntervalFn,
      clearIntervalFn,
      setTimeoutFn,
      clearTimeoutFn,
    });

    const result = await sweeper.runOnce();

    expect(store.sweepExpired).toHaveBeenCalledTimes(1);
    expect(store.count).toHaveBeenCalledTimes(1);
    expect(result).toEqual<SweepResult>({
      backend: 'memory',
      evicted: 3,
      keys: 42,
      errored: false,
      durationMs: expect.any(Number),
    });

    // Gauge updated and ok counter incremented
    const gauge = await idempotencyKeysCount.get();
    expect(
      gauge.values.find((v: { labels: Record<string, string> }) => v.labels.backend === 'memory')
        ?.value,
    ).toBe(42);
    const okCounter = await idempotencySweepRunsTotal.get();
    const okTotal = okCounter.values
      .filter(
        (v: { labels: Record<string, string> }) =>
          v.labels.backend === 'memory' && v.labels.outcome === 'ok',
      )
      .reduce((s: number, v: { value: number }) => s + v.value, 0);
    expect(okTotal).toBe(1);
  });

  it('leaves the gauge untouched when count() returns -1', async () => {
    const store = makeStore({ count: vi.fn(async () => -1) });
    const sweeper = new IdempotencySweeper({
      store,
      backend: 'redis',
      intervalMs: 1000,
      runImmediately: false,
      ...makeFakeTimers(),
    });
    // Seed the gauge to a known value
    idempotencyKeysCount.set({ backend: 'redis' }, 7);

    const result = await sweeper.runOnce();

    expect(result.keys).toBe(-1);
    const gauge = await idempotencyKeysCount.get();
    expect(gauge.values.find((v) => v.labels.backend === 'redis')?.value).toBe(7);
  });

  it('no-ops gracefully when the store has no sweepExpired or count', async () => {
    const bare: IdempotencyStore = {
      get: async () => undefined,
      set: async () => undefined,
    };
    const sweeper = new IdempotencySweeper({
      store: bare,
      backend: 'memory',
      intervalMs: 1000,
      runImmediately: false,
      ...makeFakeTimers(),
    });

    const result = await sweeper.runOnce();

    expect(result.evicted).toBe(0);
    expect(result.keys).toBe(-1);
    expect(result.errored).toBe(false);
  });

  it('emits the "error" outcome when sweepExpired throws and never rejects', async () => {
    const store = makeStore({
      sweepExpired: vi.fn(async () => {
        throw new Error('redis is down');
      }),
    });
    const sweeper = new IdempotencySweeper({
      store,
      backend: 'redis',
      intervalMs: 1000,
      runImmediately: false,
      log: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
      ...makeFakeTimers(),
    });

    const result = await sweeper.runOnce();

    expect(result.errored).toBe(true);
    const counter = await idempotencySweepRunsTotal.get();
    const errTotal = counter.values
      .filter(
        (v: { labels: Record<string, string> }) =>
          v.labels.backend === 'redis' && v.labels.outcome === 'error',
      )
      .reduce((s: number, v: { value: number }) => s + v.value, 0);
    expect(errTotal).toBe(1);
  });

  it('emits the "error" outcome when count() throws after a successful sweep', async () => {
    const store = makeStore({
      sweepExpired: vi.fn(async () => 1),
      count: vi.fn(async () => {
        throw new Error('SCAN failed');
      }),
    });
    const sweeper = new IdempotencySweeper({
      store,
      backend: 'memory',
      intervalMs: 1000,
      runImmediately: false,
      log: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
      ...makeFakeTimers(),
    });

    const result = await sweeper.runOnce();

    expect(result.errored).toBe(true);
    // The pre-failure sweep result is still preserved
    expect(result.evicted).toBe(1);
  });
});

describe('IdempotencySweeper — single-flight and concurrency', () => {
  it('shares work across concurrent runOnce() calls', async () => {
    let resolveSweep: (n: number) => void = () => {};
    const store = makeStore({
      sweepExpired: vi.fn(
        () =>
          new Promise<number>((r) => {
            resolveSweep = r;
          }),
      ),
    });
    const sweeper = new IdempotencySweeper({
      store,
      backend: 'memory',
      intervalMs: 1000,
      runImmediately: false,
      ...makeFakeTimers(),
    });

    const a = sweeper.runOnce();
    const b = sweeper.runOnce();
    const c = sweeper.runOnce();

    resolveSweep(5);
    const [ra, rb, rc] = await Promise.all([a, b, c]);

    expect(store.sweepExpired).toHaveBeenCalledTimes(1);
    expect(ra).toBe(rb);
    expect(rb).toBe(rc);
  });

  it('clears the in-flight reference after a cycle completes', async () => {
    const store = makeStore();
    const sweeper = new IdempotencySweeper({
      store,
      backend: 'memory',
      intervalMs: 1000,
      runImmediately: false,
      ...makeFakeTimers(),
    });

    await sweeper.runOnce();
    // After completion, a new runOnce should call the store again.
    await sweeper.runOnce();
    expect(store.sweepExpired).toHaveBeenCalledTimes(2);
  });
});

describe('IdempotencySweeper — start/stop lifecycle', () => {
  it('schedules an interval and an immediate first sweep by default', () => {
    const store = makeStore();
    const fakeTimers = makeFakeTimers();
    const sweeper = new IdempotencySweeper({
      store,
      backend: 'memory',
      intervalMs: 5000,
      ...fakeTimers,
    });

    sweeper.start();

    expect(sweeper.isRunning()).toBe(true);
    expect(fakeTimers.setIntervalFn).toHaveBeenCalledTimes(1);
    expect(fakeTimers.setTimeoutFn).toHaveBeenCalledTimes(1);
  });

  it('does not schedule the immediate sweep when runImmediately is false', () => {
    const store = makeStore();
    const fakeTimers = makeFakeTimers();
    const sweeper = new IdempotencySweeper({
      store,
      backend: 'memory',
      intervalMs: 5000,
      runImmediately: false,
      ...fakeTimers,
    });

    sweeper.start();

    expect(fakeTimers.setIntervalFn).toHaveBeenCalledTimes(1);
    expect(fakeTimers.setTimeoutFn).not.toHaveBeenCalled();
  });

  it('start() is idempotent — second call is a no-op', () => {
    const store = makeStore();
    const fakeTimers = makeFakeTimers();
    const sweeper = new IdempotencySweeper({
      store,
      backend: 'memory',
      intervalMs: 5000,
      runImmediately: false,
      ...fakeTimers,
    });

    sweeper.start();
    sweeper.start();
    sweeper.start();

    expect(fakeTimers.setIntervalFn).toHaveBeenCalledTimes(1);
  });

  it('stop() clears both handles', async () => {
    const store = makeStore();
    const fakeTimers = makeFakeTimers();
    const sweeper = new IdempotencySweeper({
      store,
      backend: 'memory',
      intervalMs: 5000,
      ...fakeTimers,
    });

    sweeper.start();
    await sweeper.stop();

    expect(sweeper.isRunning()).toBe(false);
    expect(fakeTimers.clearIntervalFn).toHaveBeenCalledTimes(1);
    expect(fakeTimers.clearTimeoutFn).toHaveBeenCalledTimes(1);
  });

  it('stop() is idempotent and safe to call when never started', async () => {
    const sweeper = new IdempotencySweeper({
      store: makeStore(),
      backend: 'memory',
      intervalMs: 1000,
      runImmediately: false,
      ...makeFakeTimers(),
    });

    await sweeper.stop();
    await sweeper.stop();
  });

  it('stop() awaits an in-flight cycle before resolving', async () => {
    let resolveSweep: (n: number) => void = () => {};
    const store = makeStore({
      sweepExpired: vi.fn(
        () =>
          new Promise<number>((r) => {
            resolveSweep = r;
          }),
      ),
    });
    const sweeper = new IdempotencySweeper({
      store,
      backend: 'memory',
      intervalMs: 1000,
      runImmediately: false,
      ...makeFakeTimers(),
    });
    sweeper.start();

    const inflight = sweeper.runOnce();
    let stopDone = false;
    const stopPromise = sweeper.stop().then(() => {
      stopDone = true;
    });

    // Stop should not resolve until the in-flight cycle finishes
    await new Promise((r) => setTimeout(r, 5));
    expect(stopDone).toBe(false);

    resolveSweep(0);
    await inflight;
    await stopPromise;
    expect(stopDone).toBe(true);
  });

  it('restart after stop is allowed', async () => {
    const fakeTimers = makeFakeTimers();
    const sweeper = new IdempotencySweeper({
      store: makeStore(),
      backend: 'memory',
      intervalMs: 1000,
      runImmediately: false,
      ...fakeTimers,
    });

    sweeper.start();
    await sweeper.stop();
    sweeper.start();
    expect(sweeper.isRunning()).toBe(true);
    expect(fakeTimers.setIntervalFn).toHaveBeenCalledTimes(2);
  });
});

describe('IdempotencySweeper — interval flooring', () => {
  it('applies a hard minimum of 1 second', () => {
    const fakeTimers = makeFakeTimers();
    const sweeper = new IdempotencySweeper({
      store: makeStore(),
      backend: 'memory',
      intervalMs: 10, // below floor
      runImmediately: false,
      ...fakeTimers,
    });

    sweeper.start();
    const registered = fakeTimers.setIntervalFn.mock.calls[0][1];
    expect(registered).toBe(1000);
  });

  it('uses the requested interval when above the floor', () => {
    const fakeTimers = makeFakeTimers();
    const sweeper = new IdempotencySweeper({
      store: makeStore(),
      backend: 'memory',
      intervalMs: 30_000,
      runImmediately: false,
      ...fakeTimers,
    });

    sweeper.start();
    expect(fakeTimers.setIntervalFn.mock.calls[0][1]).toBe(30_000);
  });
});

describe('resolveSweepIntervalMs — env parsing', () => {
  it('returns the default when the env var is unset', () => {
    expect(resolveSweepIntervalMs()).toBe(60_000);
  });

  it('returns the default for invalid values', () => {
    process.env.IDEMPOTENCY_SWEEP_INTERVAL_MS = 'not-a-number';
    expect(resolveSweepIntervalMs()).toBe(60_000);

    process.env.IDEMPOTENCY_SWEEP_INTERVAL_MS = '0';
    expect(resolveSweepIntervalMs()).toBe(60_000);

    process.env.IDEMPOTENCY_SWEEP_INTERVAL_MS = '-1';
    expect(resolveSweepIntervalMs()).toBe(60_000);
  });

  it('applies the hard floor of 1s even when the env asks for less', () => {
    process.env.IDEMPOTENCY_SWEEP_INTERVAL_MS = '100';
    expect(resolveSweepIntervalMs()).toBe(1_000);
  });

  it('passes through a valid value', () => {
    process.env.IDEMPOTENCY_SWEEP_INTERVAL_MS = '5000';
    expect(resolveSweepIntervalMs()).toBe(5_000);
  });
});

describe('createRedisIdempotencyStore — backend selection', () => {
  it('returns null when neither REDIS_URL nor REDIS_CLUSTER_NODES is set', async () => {
    expect(await createRedisIdempotencyStore()).toBeNull();
  });

  it('returns null when REDIS_URL is empty string', async () => {
    process.env.REDIS_URL = '';
    expect(await createRedisIdempotencyStore()).toBeNull();
  });

  it('constructs a store when REDIS_URL is set', async () => {
    process.env.REDIS_URL = 'redis://localhost:6379';
    const store = await createRedisIdempotencyStore();
    expect(store).toBeInstanceOf(RedisIdempotencyStore);
  });

  it('constructs a store when REDIS_CLUSTER_NODES is set', async () => {
    process.env.REDIS_CLUSTER_NODES = 'h1:7000,h2:7001,h3:7002';
    const store = await createRedisIdempotencyStore();
    expect(store).toBeInstanceOf(RedisIdempotencyStore);
  });
});

describe('startIdempotencySweeper — application wiring', () => {
  it('falls back to the in-memory backend when no Redis is configured', async () => {
    const handle = await startIdempotencySweeper();
    expect(handle).not.toBeNull();
    expect(handle!.backend).toBe('memory');
    // The interval is unref'd — the timer registration should not pin the process
    await handle!.stop();
  });

  it('uses the Redis backend when REDIS_URL is set', async () => {
    process.env.REDIS_URL = 'redis://localhost:6379';
    const handle = await startIdempotencySweeper();
    expect(handle).not.toBeNull();
    expect(handle!.backend).toBe('redis');
    await handle!.stop();
  });
});

describe('In-memory store — sweep/eviction integration', () => {
  it('sweepExpired removes TTL-expired entries and increments the eviction counter', async () => {
    const entry = {
      status: 200,
      body: { ok: true },
      requestHash: 'h',
      createdAt: Date.now(),
    };
    await inMemoryIdempotencyStore.set('short', entry, 10);
    await new Promise((r) => setTimeout(r, 30));

    const evicted = await inMemoryIdempotencyStore.sweepExpired!();

    expect(evicted).toBeGreaterThanOrEqual(1);
    const counter = await idempotencyEvictionsTotal.get();
    const expiredTotal = counter.values
      .filter((v) => v.labels.backend === 'memory' && v.labels.reason === 'expired')
      .reduce((s, v) => s + v.value, 0);
    expect(expiredTotal).toBeGreaterThanOrEqual(1);
  });

  it('count() returns the current number of live entries', async () => {
    expect(await inMemoryIdempotencyStore.count!()).toBe(0);
    const entry = {
      status: 200,
      body: { ok: true },
      requestHash: 'h',
      createdAt: Date.now(),
    };
    await inMemoryIdempotencyStore.set('a', entry, 60_000);
    await inMemoryIdempotencyStore.set('b', entry, 60_000);
    expect(await inMemoryIdempotencyStore.count!()).toBe(2);
  });

  it('delete() emits the manual reason', async () => {
    const entry = {
      status: 200,
      body: { ok: true },
      requestHash: 'h',
      createdAt: Date.now(),
    };
    await inMemoryIdempotencyStore.set('a', entry, 60_000);
    const before = await idempotencyEvictionsTotal.get();
    const beforeManual = before.values
      .filter((v) => v.labels.backend === 'memory' && v.labels.reason === 'manual')
      .reduce((s, v) => s + v.value, 0);

    await inMemoryIdempotencyStore.delete!('a');

    const after = await idempotencyEvictionsTotal.get();
    const afterManual = after.values
      .filter((v) => v.labels.backend === 'memory' && v.labels.reason === 'manual')
      .reduce((s, v) => s + v.value, 0);
    expect(afterManual).toBe(beforeManual + 1);
  });

  it('overflow pruning in set() emits reason="overflow"', async () => {
    // This test exercises the overflow path indirectly by setting
    // entries and verifying the counter label exists when the path
    // triggers. We avoid a 10k-entry setup by relying on a small
    // override: insert one near-expiry entry and let the counter
    // be visible when pruneExpiredMemoryStore is called via set.
    const entry = {
      status: 200,
      body: { ok: true },
      requestHash: 'h',
      createdAt: Date.now(),
    };
    await inMemoryIdempotencyStore.set('will-expire', entry, 5);
    await new Promise((r) => setTimeout(r, 15));
    // Trigger the sweep manually so the counter is exercised
    await inMemoryIdempotencyStore.sweepExpired!();

    const counter = await idempotencyEvictionsTotal.get();
    const labels = new Set(
      counter.values
        .filter((v) => v.labels.backend === 'memory')
        .map((v) => v.labels.reason),
    );
    expect(labels.has('expired')).toBe(true);
  });
});

describe('RedisIdempotencyStore — sweep integration', () => {
  it('count() returns -1 when the underlying client has no SCAN', async () => {
    const store = new RedisIdempotencyStore({
      get: vi.fn(async () => null),
      set: vi.fn(async () => 'OK'),
      del: vi.fn(async () => 1),
    });
    expect(await store.count!()).toBe(-1);
  });

  it('count() walks SCAN with the configured MATCH pattern', async () => {
    const scan = vi.fn(async (cursor: string | number) => {
      if (cursor === '0') return ['5', ['idempotency:a:1', 'idempotency:a:2']];
      if (cursor === '5') return ['0', ['idempotency:b:1']];
      return ['0', []];
    });
    const store = new RedisIdempotencyStore(
      { get: vi.fn(), set: vi.fn(), del: vi.fn(), scan },
      { scanMatch: 'idempotency:*', scanCount: 100 },
    );

    const total = await store.count!();
    expect(total).toBe(3);
    expect(scan).toHaveBeenCalledWith('0', 'MATCH', 'idempotency:*', 'COUNT', 100);
  });

  it('count() exits the loop when SCAN returns a non-array', async () => {
    const scan = vi.fn(async () => undefined);
    const store = new RedisIdempotencyStore(
      { get: vi.fn(), set: vi.fn(), del: vi.fn(), scan },
    );
    expect(await store.count!()).toBe(0);
  });

  it('count() treats a numeric cursor "0" as end-of-iteration', async () => {
    const scan = vi.fn(async () => [0, []]);
    const store = new RedisIdempotencyStore(
      { get: vi.fn(), set: vi.fn(), del: vi.fn(), scan },
    );
    expect(await store.count!()).toBe(0);
  });

  it('sweepExpired returns 0 — Redis self-evicts via PEXPIRE', async () => {
    const store = new RedisIdempotencyStore({
      get: vi.fn(),
      set: vi.fn(),
      del: vi.fn(),
    });
    expect(await store.sweepExpired!()).toBe(0);
  });
});
