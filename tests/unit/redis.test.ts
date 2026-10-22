import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  hashTag,
  redisHealthProbe,
  getRedisClient,
  getReadonlyRedisClient,
  resetRedisClient,
} from "../../src/redis.js";

// ---------------------------------------------------------------------------
// Error contracts for the "No Redis configuration" throw branches in
// src/redis.ts (getRedisClient lines ~62/~96, getReadonlyRedisClient line ~117).
// Asserted verbatim so a silent reword of the contract cannot slip through.
// ---------------------------------------------------------------------------
const NO_CONFIG_ERROR = "No Redis configuration: set REDIS_URL or REDIS_CLUSTER_NODES";
const SENTINEL_CONFIG_ERROR =
  "No Redis configuration: REDIS_MODE is sentinel but REDIS_SENTINELS is not set";

/** Run `fn` and hand back the thrown Error (fails the test if nothing throws). */
function captureThrown(fn: () => unknown): Error {
  try {
    fn();
  } catch (err) {
    return err as Error;
  }
  throw new Error("expected function to throw, but it returned normally");
}

// ---------------------------------------------------------------------------
// ioredis mock — constructors must be real functions (not arrows) for `new`.
// The captured argument lists let tests assert the options the factory passes
// through (sentinel name/role, cluster scaleReads, parsed node lists).
// ---------------------------------------------------------------------------
const mockPing = vi.fn();
const mockOn = vi.fn();
const redisConstructorCalls: unknown[][] = [];
const clusterConstructorCalls: unknown[][] = [];

vi.mock("ioredis", () => {
  // Use a shared external reference so mockPing/mockOn mutations are visible
  // to instances created after the mock is established.
  const proto = { ping: (...args: any[]) => mockPing(...args), on: (...args: any[]) => mockOn(...args) };
  function RedisMock(this: any, ...args: any[]) {
    redisConstructorCalls.push(args);
    Object.setPrototypeOf(this, proto);
  }
  function ClusterMock(this: any, ...args: any[]) {
    clusterConstructorCalls.push(args);
    Object.setPrototypeOf(this, proto);
  }
  return { default: RedisMock, Cluster: ClusterMock };
});

/** Remove every Redis-related env var so each test starts from a clean slate. */
function clearRedisEnv(): void {
  delete process.env.REDIS_URL;
  delete process.env.REDIS_CLUSTER_NODES;
  delete process.env.REDIS_MODE;
  delete process.env.REDIS_SENTINELS;
  delete process.env.REDIS_SENTINEL_NAME;
  delete process.env.REDIS_TLS;
  delete process.env.REDIS_FORCE_SINGLE_NODE;
}

function resetCtorCapture(): void {
  redisConstructorCalls.length = 0;
  clusterConstructorCalls.length = 0;
}

// ---------------------------------------------------------------------------
// hashTag
// ---------------------------------------------------------------------------
describe("hashTag", () => {
  it("wraps businessId in curly braces", () => {
    expect(hashTag("biz-123")).toBe("{biz-123}");
  });

  it("produces keys that differ only in suffix", () => {
    const tag = hashTag("acme");
    expect(`rate-limit:${tag}:ip:1.2.3.4`).toBe("rate-limit:{acme}:ip:1.2.3.4");
    expect(`idempotency:attestations:${tag}:key-abc`).toBe("idempotency:attestations:{acme}:key-abc");
  });
});

// ---------------------------------------------------------------------------
// getRedisClient
// ---------------------------------------------------------------------------
describe("getRedisClient", () => {
  beforeEach(() => {
    resetRedisClient();
    clearRedisEnv();
    resetCtorCapture();
    vi.clearAllMocks();
  });

  afterEach(() => {
    resetRedisClient();
    clearRedisEnv();
  });

  it("throws the exact no-configuration error when no Redis env vars are set", () => {
    const err = captureThrown(() => getRedisClient());
    expect(err).toBeInstanceOf(Error);
    expect(err.message).toBe(NO_CONFIG_ERROR);
    expect(redisConstructorCalls).toHaveLength(0);
    expect(clusterConstructorCalls).toHaveLength(0);
  });

  it("does not cache a client after a failed construction (cache is not poisoned)", () => {
    expect(() => getRedisClient()).toThrow(NO_CONFIG_ERROR);

    process.env.REDIS_URL = "redis://localhost:6379";
    const client = getRedisClient();
    expect(typeof client.ping).toBe("function");
    expect(redisConstructorCalls).toHaveLength(1);
  });

  it("throws the exact no-configuration error when cluster nodes are forced to single-node without a URL", () => {
    process.env.REDIS_CLUSTER_NODES = "127.0.0.1:7000";
    process.env.REDIS_FORCE_SINGLE_NODE = "true";
    const err = captureThrown(() => getRedisClient());
    expect(err.message).toBe(NO_CONFIG_ERROR);
    expect(clusterConstructorCalls).toHaveLength(0);
  });

  it("returns a Redis instance when REDIS_URL is set", () => {
    process.env.REDIS_URL = "redis://localhost:6379";
    const client = getRedisClient();
    // ioredis Redis was constructed — instance has ping and on from mockInstance
    expect(typeof client.ping).toBe("function");
    expect(typeof client.on).toBe("function");
  });

  it("returns a Cluster instance when REDIS_CLUSTER_NODES is set", () => {
    process.env.REDIS_CLUSTER_NODES = "127.0.0.1:7000,127.0.0.1:7001,127.0.0.1:7002";
    const client = getRedisClient();
    expect(typeof client.ping).toBe("function");
    expect(clusterConstructorCalls).toHaveLength(1);
    expect(clusterConstructorCalls[0][0]).toEqual([
      { host: "127.0.0.1", port: 7000 },
      { host: "127.0.0.1", port: 7001 },
      { host: "127.0.0.1", port: 7002 },
    ]);
  });

  it("prefers Cluster over single-node when both vars are set", () => {
    process.env.REDIS_URL = "redis://localhost:6379";
    process.env.REDIS_CLUSTER_NODES = "127.0.0.1:7000";
    // Should not throw — Cluster path taken
    expect(() => getRedisClient()).not.toThrow();
    expect(clusterConstructorCalls).toHaveLength(1);
    expect(redisConstructorCalls).toHaveLength(0);
  });

  it("returns the same instance on subsequent calls (singleton)", () => {
    process.env.REDIS_URL = "redis://localhost:6379";
    const a = getRedisClient();
    const b = getRedisClient();
    expect(a).toBe(b);
    expect(redisConstructorCalls).toHaveLength(1);
  });

  describe("Sentinel Mode", () => {
    it("throws the exact sentinel-configuration error when REDIS_SENTINELS is not set", () => {
      process.env.REDIS_MODE = "sentinel";
      const err = captureThrown(() => getRedisClient());
      expect(err).toBeInstanceOf(Error);
      expect(err.message).toBe(SENTINEL_CONFIG_ERROR);
    });

    it("treats an empty REDIS_SENTINELS value as missing", () => {
      process.env.REDIS_MODE = "sentinel";
      process.env.REDIS_SENTINELS = "";
      expect(captureThrown(() => getRedisClient()).message).toBe(SENTINEL_CONFIG_ERROR);
    });

    it("does not silently fall back to REDIS_URL when sentinel mode is misconfigured", () => {
      process.env.REDIS_MODE = "sentinel";
      process.env.REDIS_URL = "redis://localhost:6379";

      const err = captureThrown(() => getRedisClient());
      expect(err.message).toBe(SENTINEL_CONFIG_ERROR);
      // The failed branch must not have constructed any client.
      expect(redisConstructorCalls).toHaveLength(0);
      expect(clusterConstructorCalls).toHaveLength(0);
    });

    it("returns a Redis instance configured for Sentinel when REDIS_MODE is sentinel", () => {
      process.env.REDIS_MODE = "sentinel";
      process.env.REDIS_SENTINELS = "127.0.0.1:26379,127.0.0.1:26380";
      process.env.REDIS_SENTINEL_NAME = "mymaster";

      const client = getRedisClient();
      expect(typeof client.ping).toBe("function");
      expect(typeof client.on).toBe("function");
      expect(redisConstructorCalls).toHaveLength(1);
      const opts = redisConstructorCalls[0][0] as Record<string, unknown>;
      expect(opts.name).toBe("mymaster");
      expect(opts.sentinels).toEqual([
        { host: "127.0.0.1", port: 26379 },
        { host: "127.0.0.1", port: 26380 },
      ]);
    });
  });
});

// ---------------------------------------------------------------------------
// getReadonlyRedisClient — previously untested; owns the throw branch at
// src/redis.ts:117 plus the replica-routing happy paths.
// ---------------------------------------------------------------------------
describe("getReadonlyRedisClient", () => {
  beforeEach(() => {
    resetRedisClient();
    clearRedisEnv();
    resetCtorCapture();
    vi.clearAllMocks();
  });

  afterEach(() => {
    resetRedisClient();
    clearRedisEnv();
  });

  it("throws the exact no-configuration error when no Redis env vars are set", () => {
    const err = captureThrown(() => getReadonlyRedisClient());
    expect(err).toBeInstanceOf(Error);
    expect(err.message).toBe(NO_CONFIG_ERROR);
    expect(redisConstructorCalls).toHaveLength(0);
    expect(clusterConstructorCalls).toHaveLength(0);
  });

  it("throws the exact sentinel-configuration error when REDIS_MODE is sentinel but REDIS_SENTINELS is not set", () => {
    process.env.REDIS_MODE = "sentinel";
    const err = captureThrown(() => getReadonlyRedisClient());
    expect(err).toBeInstanceOf(Error);
    expect(err.message).toBe(SENTINEL_CONFIG_ERROR);
  });

  it("does not silently fall back to REDIS_URL when sentinel mode is misconfigured", () => {
    process.env.REDIS_MODE = "sentinel";
    process.env.REDIS_URL = "redis://localhost:6379";

    const err = captureThrown(() => getReadonlyRedisClient());
    expect(err.message).toBe(SENTINEL_CONFIG_ERROR);
    expect(redisConstructorCalls).toHaveLength(0);
    expect(clusterConstructorCalls).toHaveLength(0);
  });

  it("builds a separate Sentinel client with role: slave when sentinels are configured", () => {
    process.env.REDIS_MODE = "sentinel";
    process.env.REDIS_SENTINELS = "127.0.0.1:26379";
    process.env.REDIS_SENTINEL_NAME = "mymaster";

    const readonly = getReadonlyRedisClient();
    expect(typeof readonly.ping).toBe("function");
    expect(redisConstructorCalls).toHaveLength(1);
    const opts = redisConstructorCalls[0][0] as Record<string, unknown>;
    expect(opts.name).toBe("mymaster");
    expect(opts.role).toBe("slave");
    expect(mockOn).toHaveBeenCalledWith("error", expect.any(Function));

    // Readonly sentinel client is distinct from the primary writer client.
    const primary = getRedisClient();
    expect(readonly).not.toBe(primary);
    expect(redisConstructorCalls).toHaveLength(2);
  });

  it("routes reads to replicas (scaleReads: slave) when cluster nodes are configured", () => {
    process.env.REDIS_CLUSTER_NODES = "127.0.0.1:7000,127.0.0.1:7001";

    const client = getReadonlyRedisClient();
    expect(typeof client.ping).toBe("function");
    expect(clusterConstructorCalls).toHaveLength(1);
    const opts = clusterConstructorCalls[0][1] as Record<string, unknown>;
    expect(opts.scaleReads).toBe("slave");
    expect(mockOn).toHaveBeenCalledWith("error", expect.any(Function));
  });

  it("falls back to the primary client when only REDIS_URL is set", () => {
    process.env.REDIS_URL = "redis://localhost:6379";

    const primary = getRedisClient();
    const readonly = getReadonlyRedisClient();
    expect(readonly).toBe(primary);
    // A single node has no replicas to route to, so only the primary is built.
    expect(redisConstructorCalls).toHaveLength(1);
    expect(clusterConstructorCalls).toHaveLength(0);
  });

  it("caches the readonly client across calls (singleton)", () => {
    process.env.REDIS_CLUSTER_NODES = "127.0.0.1:7000";

    const a = getReadonlyRedisClient();
    const b = getReadonlyRedisClient();
    expect(a).toBe(b);
    expect(clusterConstructorCalls).toHaveLength(1);
  });

  it("resetRedisClient() drops the cached readonly client so a fresh one is built", () => {
    process.env.REDIS_CLUSTER_NODES = "127.0.0.1:7000";

    const first = getReadonlyRedisClient();
    resetRedisClient();
    const second = getReadonlyRedisClient();
    expect(second).not.toBe(first);
    expect(clusterConstructorCalls).toHaveLength(2);
  });

  it("does not cache a readonly client after a failed construction", () => {
    expect(() => getReadonlyRedisClient()).toThrow(NO_CONFIG_ERROR);

    process.env.REDIS_URL = "redis://localhost:6379";
    const client = getReadonlyRedisClient();
    expect(typeof client.ping).toBe("function");
  });
});

// ---------------------------------------------------------------------------
// redisHealthProbe
// ---------------------------------------------------------------------------
describe("redisHealthProbe", () => {
  beforeEach(() => {
    resetRedisClient();
    clearRedisEnv();
    process.env.REDIS_URL = "redis://localhost:6379";
    vi.clearAllMocks();
  });

  afterEach(() => {
    resetRedisClient();
    clearRedisEnv();
  });

  it("returns 'ok' when ping responds with PONG", async () => {
    mockPing.mockResolvedValue("PONG");
    const result = await redisHealthProbe();
    expect(result).toBe("ok");
  });

  it("returns error string when ping returns unexpected value", async () => {
    mockPing.mockResolvedValue("NOPE");
    const result = await redisHealthProbe();
    expect(result).toMatch(/^error:/);
    expect(result).toContain("unexpected ping response");
  });

  it("returns error string when ping rejects", async () => {
    mockPing.mockRejectedValue(new Error("ECONNREFUSED"));
    const result = await redisHealthProbe();
    expect(result).toBe("error:ECONNREFUSED");
  });

  it("returns error string on ping timeout (1 s)", async () => {
    vi.useFakeTimers();
    mockPing.mockImplementation(() => new Promise(() => {})); // hangs forever

    const probePromise = redisHealthProbe();
    vi.advanceTimersByTime(1001);
    const result = await probePromise;

    expect(result).toBe("error:ping timeout");
    vi.useRealTimers();
  });

  it("never throws even when getRedisClient fails", async () => {
    resetRedisClient();
    clearRedisEnv();

    const result = await redisHealthProbe();
    expect(result).toMatch(/^error:/);
    expect(result).toContain(NO_CONFIG_ERROR);
  });
});
