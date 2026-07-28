import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { SlidingWindowRedisStore, SlidingWindowMemoryStore } from "./rateLimiter.js";

/**
 * Minimal fake ioredis client sufficient to drive WATCH/MULTI/EXEC logic
 * deterministically, without a real Redis server or ioredis-mock (not a
 * project dependency). Backs a single sorted set in memory.
 */
function makeFakeRedisClient(opts: { abortExecTimes?: number } = {}) {
  let abortsRemaining = opts.abortExecTimes ?? 0;
  const zset = new Map<string, number>(); // member -> score

  return {
    watch: vi.fn(async () => "OK"),
    unwatch: vi.fn(async () => "OK"),
    multi: () => {
      const queued: Array<() => void> = [];
      const multiObj = {
        zremrangebyscore: (_key: string, min: number, max: number) => {
          queued.push(() => {
            for (const [member, score] of zset.entries()) {
              if (score >= min && score <= max) zset.delete(member);
            }
          });
          return multiObj;
        },
        zadd: (_key: string, score: number, member: string) => {
          queued.push(() => zset.set(member, score));
          return multiObj;
        },
        zcard: (_key: string) => {
          queued.push(() => {});
          return multiObj;
        },
        pexpire: (_key: string, _ms: number) => {
          queued.push(() => {});
          return multiObj;
        },
        exec: async () => {
          if (abortsRemaining > 0) {
            abortsRemaining -= 1;
            return null; // simulate a WATCH-aborted transaction
          }
          for (const run of queued) run();
          // Return one [err, value] pair per queued command, in order.
          // Only zcard's value matters to the store's logic.
          return [
            [null, "OK"],
            [null, "OK"],
            [null, zset.size],
            [null, "OK"],
          ];
        },
      };
      return multiObj;
    },
  };
}

describe("SlidingWindowRedisStore", () => {
  it("increments and returns the correct count for sequential requests", async () => {
    const client = makeFakeRedisClient();
    const store = new SlidingWindowRedisStore(client as any);

    const r1 = await store.increment("k", 1000);
    const r2 = await store.increment("k", 1000);
    const r3 = await store.increment("k", 1000);

    expect(r1.count).toBe(1);
    expect(r2.count).toBe(2);
    expect(r3.count).toBe(3);
  });

  it("prunes entries outside the window", async () => {
    vi.useFakeTimers();
    const client = makeFakeRedisClient();
    const store = new SlidingWindowRedisStore(client as any);

    await store.increment("k", 100);
    vi.advanceTimersByTime(150); // now outside a 100ms window
    const r2 = await store.increment("k", 100);

    expect(r2.count).toBe(1); // the first entry should have been pruned
    vi.useRealTimers();
  });

  it("retries on a WATCH-aborted transaction and still returns the correct count", async () => {
    const client = makeFakeRedisClient({ abortExecTimes: 2 });
    const store = new SlidingWindowRedisStore(client as any, 5);

    const record = await store.increment("k", 1000);

    expect(record.count).toBe(1);
    expect(client.watch).toHaveBeenCalledTimes(3); // 2 aborts + 1 success
  });

  it("throws after exceeding the retry cap instead of looping forever", async () => {
    const client = makeFakeRedisClient({ abortExecTimes: 999 });
    const store = new SlidingWindowRedisStore(client as any, 3);

    await expect(store.increment("k", 1000)).rejects.toThrow(/exceeded 3 retries/);
    expect(client.watch).toHaveBeenCalledTimes(4); // initial + 3 retries
  });

  it("under concurrent calls, no increments are lost (simulated race)", async () => {
    // Simulate real contention: the 2nd of three "concurrent" callers
    // aborts once before succeeding, mimicking another client's write
    // landing between this caller's WATCH and EXEC.
    const client = makeFakeRedisClient();
    let callCount = 0;
    const originalMulti = client.multi.bind(client);
    client.multi = () => {
      callCount += 1;
      if (callCount === 2) {
        const m = originalMulti();
        const originalExec = m.exec.bind(m);
        let aborted = false;
        m.exec = async () => {
          if (!aborted) {
            aborted = true;
            return null;
          }
          return originalExec();
        };
        return m;
      }
      return originalMulti();
    };
    const store = new SlidingWindowRedisStore(client as any);

    const results = await Promise.all([
      store.increment("k", 1000),
      store.increment("k", 1000),
      store.increment("k", 1000),
    ]);

    const counts = results.map((r) => r.count).sort((a, b) => a - b);
    expect(counts).toEqual([1, 2, 3]); // every request counted exactly once
  });
});

describe("SlidingWindowMemoryStore", () => {
  let store: SlidingWindowMemoryStore;

  beforeEach(() => {
    store = new SlidingWindowMemoryStore();
  });

  it("counts requests within the window", () => {
    const r1 = store.increment("k", 1000);
    const r2 = store.increment("k", 1000);
    expect(r1.count).toBe(1);
    expect(r2.count).toBe(2);
  });

  it("prunes requests outside the window", () => {
    vi.useFakeTimers();
    store.increment("k", 100);
    vi.advanceTimersByTime(150);
    const r2 = store.increment("k", 100);
    expect(r2.count).toBe(1);
    vi.useRealTimers();
  });

  it("reset() clears all buckets", () => {
    store.increment("k", 1000);
    store.reset();
    const r = store.increment("k", 1000);
    expect(r.count).toBe(1);
  });
});