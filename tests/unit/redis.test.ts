import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { hashTag, redisHealthProbe, getRedisClient, resetRedisClient } from "../../src/redis.js";

// ---------------------------------------------------------------------------
// ioredis mock — constructors must be real functions (not arrows) for `new`
// ---------------------------------------------------------------------------
const mockPing = vi.fn();
const mockOn = vi.fn();

vi.mock("ioredis", () => {
  // Use a shared external reference so mockPing/mockOn mutations are visible
  // to instances created after the mock is established.
  const proto = { ping: (...args: any[]) => mockPing(...args), on: (...args: any[]) => mockOn(...args) };
  function RedisMock(this: any) { Object.setPrototypeOf(this, proto); }
  function ClusterMock(this: any) { Object.setPrototypeOf(this, proto); }
  return { default: RedisMock, Cluster: ClusterMock };
});

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
    delete process.env.REDIS_URL;
    delete process.env.REDIS_CLUSTER_NODES;
    delete process.env.REDIS_TLS;
    vi.clearAllMocks();
  });

  afterEach(() => {
    resetRedisClient();
    delete process.env.REDIS_URL;
    delete process.env.REDIS_CLUSTER_NODES;
  });

  it("throws when no Redis env vars are set", () => {
    expect(() => getRedisClient()).toThrow(/No Redis configuration/);
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
  });

  it("prefers Cluster over single-node when both vars are set", () => {
    process.env.REDIS_URL = "redis://localhost:6379";
    process.env.REDIS_CLUSTER_NODES = "127.0.0.1:7000";
    // Should not throw — Cluster path taken
    expect(() => getRedisClient()).not.toThrow();
  });

  it("returns the same instance on subsequent calls (singleton)", () => {
    process.env.REDIS_URL = "redis://localhost:6379";
    const a = getRedisClient();
    const b = getRedisClient();
    expect(a).toBe(b);
  });
});

// ---------------------------------------------------------------------------
// redisHealthProbe
// ---------------------------------------------------------------------------
describe("redisHealthProbe", () => {
  beforeEach(() => {
    resetRedisClient();
    process.env.REDIS_URL = "redis://localhost:6379";
    vi.clearAllMocks();
  });

  afterEach(() => {
    resetRedisClient();
    delete process.env.REDIS_URL;
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
    delete process.env.REDIS_URL;
    delete process.env.REDIS_CLUSTER_NODES;

    const result = await redisHealthProbe();
    expect(result).toMatch(/^error:/);
  });
});
