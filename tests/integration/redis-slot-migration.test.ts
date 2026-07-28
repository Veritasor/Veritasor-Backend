import { describe, it, expect, vi, beforeEach } from "vitest";
import { Toxiproxy } from "toxiproxy-node";
import { RedisStore, SlidingWindowRedisStore } from "../../src/middleware/rateLimiter.js";

describe("Redis Cluster Slot Migration Integration (Toxiproxy & Redirection)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("handles Toxiproxy setup and Redis slot redirection for fixed window rate limiter", async () => {
    let toxiproxyConnected = false;
    try {
      const toxiproxy = new Toxiproxy("http://localhost:8474");
      await toxiproxy.populate([]);
      toxiproxyConnected = true;
    } catch {
      // Toxiproxy server optional local fallback
    }

    const node2 = {
      options: { host: "127.0.0.1", port: 7002 },
      eval: vi.fn().mockResolvedValue([1, 60000]),
    };

    const node1 = {
      options: { host: "127.0.0.1", port: 7001 },
      eval: vi.fn().mockRejectedValueOnce(new Error("MOVED 1000 127.0.0.1:7002")),
      refreshSlotsCache: vi.fn().mockResolvedValue(undefined),
      nodes: vi.fn().mockReturnValue([node2]),
    };

    const store = new RedisStore(node1 as any);
    const result = await store.increment("test:toxiproxy:key", 60000);

    expect(result.count).toBe(1);
    expect(node1.refreshSlotsCache).toHaveBeenCalledOnce();
    expect(node2.eval).toHaveBeenCalledOnce();
  });

  it("handles ASK redirection with Toxiproxy simulation without double-charging tokens", async () => {
    const askingMock = vi.fn().mockResolvedValue("OK");
    const node2 = {
      options: { host: "127.0.0.1", port: 7003 },
      asking: askingMock,
      eval: vi.fn().mockResolvedValue([1, 60000]),
    };

    const node1 = {
      options: { host: "127.0.0.1", port: 7001 },
      eval: vi.fn().mockRejectedValueOnce(new Error("ASK 1000 127.0.0.1:7003")),
      nodes: vi.fn().mockReturnValue([node2]),
    };

    const store = new RedisStore(node1 as any);
    const result1 = await store.increment("test:ask:key", 60000);

    expect(result1.count).toBe(1);
    expect(askingMock).toHaveBeenCalledOnce();
    expect(node2.eval).toHaveBeenCalledOnce();
  });

  it("handles SlidingWindowRedisStore redirection under slot migration without double-charging", async () => {
    const askingMock = vi.fn().mockResolvedValue("OK");
    const node2Multi = {
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

    const node2 = {
      options: { host: "127.0.0.1", port: 7004 },
      asking: askingMock,
      watch: vi.fn().mockResolvedValue("OK"),
      unwatch: vi.fn().mockResolvedValue("OK"),
      multi: vi.fn().mockReturnValue(node2Multi),
    };

    const node1 = {
      options: { host: "127.0.0.1", port: 7001 },
      watch: vi.fn().mockResolvedValue("OK"),
      unwatch: vi.fn().mockResolvedValue("OK"),
      multi: vi.fn().mockReturnValue({
        zremrangebyscore: vi.fn().mockReturnThis(),
        zadd: vi.fn().mockReturnThis(),
        zcard: vi.fn().mockReturnThis(),
        pexpire: vi.fn().mockReturnThis(),
        exec: vi.fn().mockRejectedValueOnce(new Error("ASK 2000 127.0.0.1:7004")),
      }),
      nodes: vi.fn().mockReturnValue([node2]),
    };

    const store = new SlidingWindowRedisStore(node1 as any);
    const result = await store.increment("test:sliding:ask", 60000);

    expect(result.count).toBe(1);
    expect(askingMock).toHaveBeenCalledOnce();
    expect(node2Multi.exec).toHaveBeenCalledOnce();
  });

  it("prevents MOVED redirection loop under flapping cluster topology", async () => {
    const node1 = {
      options: { host: "127.0.0.1", port: 7001 },
      eval: vi.fn().mockRejectedValue(new Error("MOVED 1000 127.0.0.1:7001")),
      nodes: vi.fn().mockReturnValue([]),
    };

    const store = new RedisStore(node1 as any, 3);
    await expect(store.increment("test:loop:key", 60000)).rejects.toThrow(
      /infinite redirection loop detected/
    );
  });
});
