import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { RedisStore, SlidingWindowRedisStore, SlidingWindowMemoryStore } from "./rateLimiter.js";

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

describe("RedisStore slot migration (MOVED / ASK)", () => {
  it("handles MOVED redirection, updates target node, and increments metric", async () => {
    const targetNode = {
      eval: vi.fn().mockResolvedValue([1, 10000]),
    };
    const primaryClient = {
      eval: vi.fn().mockRejectedValueOnce(new Error("MOVED 12345 127.0.0.1:7001")),
      refreshSlotsCache: vi.fn().mockResolvedValue(undefined),
      nodes: vi.fn().mockReturnValue([targetNode]),
    };
    (targetNode as any).options = { host: "127.0.0.1", port: 7001 };

    const store = new RedisStore(primaryClient as any);
    const record = await store.increment("user:1", 10000);

    expect(record.count).toBe(1);
    expect(primaryClient.refreshSlotsCache).toHaveBeenCalledOnce();
    expect(targetNode.eval).toHaveBeenCalledOnce();
  });

  it("handles ASK redirection by sending ASKING to target node before retrying", async () => {
    const askingMock = vi.fn().mockResolvedValue("OK");
    const targetNode = {
      options: { host: "127.0.0.1", port: 7002 },
      asking: askingMock,
      eval: vi.fn().mockResolvedValue([2, 5000]),
    };
    const primaryClient = {
      eval: vi.fn().mockRejectedValueOnce(new Error("ASK 12345 127.0.0.1:7002")),
      nodes: vi.fn().mockReturnValue([targetNode]),
    };

    const store = new RedisStore(primaryClient as any);
    const record = await store.increment("user:2", 10000);

    expect(record.count).toBe(2);
    expect(askingMock).toHaveBeenCalledOnce();
    expect(targetNode.eval).toHaveBeenCalledOnce();
  });

  it("prevents infinite MOVED redirection loops and throws an error", async () => {
    const loopingClient = {
      eval: vi.fn().mockRejectedValue(new Error("MOVED 12345 127.0.0.1:7001")),
      options: { host: "127.0.0.1", port: 7001 },
      nodes: vi.fn().mockReturnValue([]),
    };

    const store = new RedisStore(loopingClient as any, 5);
    await expect(store.increment("user:loop", 10000)).rejects.toThrow(
      /infinite redirection loop detected/
    );
  });
});

describe("SlidingWindowRedisStore slot migration (MOVED / ASK)", () => {
  it("handles MOVED redirection during WATCH/MULTI/EXEC", async () => {
    const targetMulti = {
      zremrangebyscore: vi.fn().mockReturnThis(),
      zadd: vi.fn().mockReturnThis(),
      zcard: vi.fn().mockReturnThis(),
      pexpire: vi.fn().mockReturnThis(),
      exec: vi.fn().mockResolvedValue([
        [null, "OK"],
        [null, "OK"],
        [null, 1],
        [null, "OK"],
      ]),
    };
    const targetNode = {
      options: { host: "127.0.0.1", port: 7001 },
      watch: vi.fn().mockResolvedValue("OK"),
      unwatch: vi.fn().mockResolvedValue("OK"),
      multi: vi.fn().mockReturnValue(targetMulti),
    };

    const primaryClient = {
      watch: vi.fn().mockRejectedValueOnce(new Error("MOVED 5555 127.0.0.1:7001")),
      unwatch: vi.fn().mockResolvedValue("OK"),
      refreshSlotsCache: vi.fn().mockResolvedValue(undefined),
      nodes: vi.fn().mockReturnValue([targetNode]),
    };

    const store = new SlidingWindowRedisStore(primaryClient as any);
    const record = await store.increment("slide:key", 10000);

    expect(record.count).toBe(1);
    expect(targetNode.watch).toHaveBeenCalledWith("slide:key");
    expect(targetMulti.exec).toHaveBeenCalledOnce();
  });

  it("handles ASK redirection in SlidingWindowRedisStore with ASKING command", async () => {
    const askingMock = vi.fn().mockResolvedValue("OK");
    const targetMulti = {
      zremrangebyscore: vi.fn().mockReturnThis(),
      zadd: vi.fn().mockReturnThis(),
      zcard: vi.fn().mockReturnThis(),
      pexpire: vi.fn().mockReturnThis(),
      exec: vi.fn().mockResolvedValue([
        [null, "OK"],
        [null, "OK"],
        [null, 3],
        [null, "OK"],
      ]),
    };
    const targetNode = {
      options: { host: "127.0.0.1", port: 7003 },
      asking: askingMock,
      watch: vi.fn().mockResolvedValue("OK"),
      unwatch: vi.fn().mockResolvedValue("OK"),
      multi: vi.fn().mockReturnValue(targetMulti),
    };

    const primaryClient = {
      watch: vi.fn().mockResolvedValue("OK"),
      unwatch: vi.fn().mockResolvedValue("OK"),
      multi: vi.fn().mockReturnValue({
        zremrangebyscore: vi.fn().mockReturnThis(),
        zadd: vi.fn().mockReturnThis(),
        zcard: vi.fn().mockReturnThis(),
        pexpire: vi.fn().mockReturnThis(),
        exec: vi.fn().mockRejectedValueOnce(new Error("ASK 5555 127.0.0.1:7003")),
      }),
      nodes: vi.fn().mockReturnValue([targetNode]),
    };

    const store = new SlidingWindowRedisStore(primaryClient as any);
    const record = await store.increment("slide:ask", 10000);

    expect(record.count).toBe(3);
    expect(askingMock).toHaveBeenCalledOnce();
    expect(targetNode.watch).toHaveBeenCalledOnce();
  });
});

describe("cleanupSlidingStore & helper edge cases", () => {
  it("cleans up expired timestamps in sliding store", async () => {
    const { cleanupSlidingStore } = await import("./rateLimiter.js");
    const store = new SlidingWindowMemoryStore();
    store.increment("test:key", 100);

    cleanupSlidingStore(Date.now() + 200, 100);
    const result = store.increment("test:key", 100);
    expect(result.count).toBe(1);
  });

  it("handles null / non-redirection errors in parseClusterRedirectionError", async () => {
    const { parseClusterRedirectionError, isClusterRedirectionError } = await import("../redis.js");
    expect(parseClusterRedirectionError(null)).toBeNull();
    expect(parseClusterRedirectionError(undefined)).toBeNull();
    expect(parseClusterRedirectionError("GENERIC_ERROR")).toBeNull();
    expect(isClusterRedirectionError("MOVED 100 127.0.0.1:7001")).toBe(true);
    expect(isClusterRedirectionError("SOMETHING_ELSE")).toBe(false);
  });

  it("handles error in sync rateLimiter middleware without crashing app", async () => {
    const { rateLimiter, memoryStore } = await import("./rateLimiter.js");
    vi.spyOn(memoryStore, "increment").mockImplementationOnce(() => {
      throw new Error("Sync store explosion");
    });

    const middleware = rateLimiter();
    const req = { method: "GET", path: "/test", headers: {}, socket: {} } as any;
    const res = { setHeader: vi.fn() } as any;
    const next = vi.fn();

    middleware(req, res, next);
    expect(next).toHaveBeenCalledOnce();
  });

  it("handles zcard error inside SlidingWindowRedisStore multi.exec results", async () => {
    const client = {
      watch: vi.fn().mockResolvedValue("OK"),
      unwatch: vi.fn().mockResolvedValue("OK"),
      multi: vi.fn().mockReturnValue({
        zremrangebyscore: vi.fn().mockReturnThis(),
        zadd: vi.fn().mockReturnThis(),
        zcard: vi.fn().mockReturnThis(),
        pexpire: vi.fn().mockReturnThis(),
        exec: vi.fn().mockResolvedValue([
          [null, "OK"],
          [null, "OK"],
          [new Error("zcard failure"), 0],
          [null, "OK"],
        ]),
      }),
    };

    const store = new SlidingWindowRedisStore(client as any, 1);
    await expect(store.increment("test:zcardErr", 1000)).rejects.toThrow("zcard failure");
  });
});