import { describe, it, expect, beforeEach, afterEach, vi, beforeAll } from "vitest";
import type { Request, Response, NextFunction } from "express";
import {
  cleanupRateLimiterStore,
  rateLimiter,
  resetRateLimiterStore,
  getStore,
  resetStorePromise,
  memoryStore,
  RedisStore,
} from "../../../src/middleware/rateLimiter.js";
import { logger } from "../../../src/utils/logger";

// ---------------------------------------------------------------------------
// ioredis mock — covers both Redis (single) and Cluster paths
// ---------------------------------------------------------------------------
const mockRedisClient = {
  status: "ready",
  eval: vi.fn(),
  on: vi.fn(),
  once: vi.fn((event: string, cb: (...args: any[]) => void) => {
    if (event === "ready") cb();
  }),
  ping: vi.fn().mockResolvedValue("PONG"),
};

vi.mock("ioredis", () => ({
  default: vi.fn(() => mockRedisClient),
  Cluster: vi.fn(() => mockRedisClient),
}));

vi.mock("../../../src/redis.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../../src/redis.js")>();
  return {
    ...actual,
    getRedisClient: vi.fn(() => mockRedisClient),
    resetRedisClient: vi.fn(),
  };
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function createResponse(): Response {
  const headers = new Map<string, string>();
  const response = {
    statusCode: 200,
    body: undefined as unknown,
    setHeader(name: string, value: string) {
      headers.set(name.toLowerCase(), value);
      return this;
    },
    getHeader(name: string) {
      return headers.get(name.toLowerCase());
    },
    status(code: number) {
      this.statusCode = code;
      return this;
    },
    json(payload: unknown) {
      this.body = payload;
      return this;
    },
  };
  return response as unknown as Response;
}

function createRequest(overrides: Partial<Request> = {}): Request {
  return {
    method: "POST",
    baseUrl: "/api/auth",
    path: "/login",
    originalUrl: "/api/auth/login",
    ip: "127.0.0.1",
    socket: { remoteAddress: "127.0.0.1" },
    headers: {},
    ...overrides,
  } as Request;
}

// ---------------------------------------------------------------------------
// Fixed-window (memory store) tests
// ---------------------------------------------------------------------------
describe("rateLimiter (fixed window — memory store)", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    resetRateLimiterStore();
    delete process.env.REDIS_URL;
    delete process.env.REDIS_CLUSTER_NODES;
  });

  afterEach(() => {
    vi.useRealTimers();
    resetRateLimiterStore();
    delete process.env.RATE_LIMIT_WINDOW_MS;
    delete process.env.RATE_LIMIT_MAX;
  });

  it("allows requests within the limit and sets headers", () => {
    const middleware = rateLimiter({ bucket: "auth:login", max: 2, windowMs: 30_000 });
    const req = createRequest();
    const res = createResponse();
    const next = vi.fn() as NextFunction;

    middleware(req, res, next);

    expect(next).toHaveBeenCalledOnce();
    expect((res as any).statusCode).toBe(200);
    expect(res.getHeader("x-ratelimit-bucket")).toBe("auth:login");
    expect(res.getHeader("x-ratelimit-limit")).toBe("2");
    expect(res.getHeader("x-ratelimit-remaining")).toBe("1");
    expect(res.getHeader("retry-after")).toBe("30");
  });

  it("rejects requests that exceed the limit", () => {
    const middleware = rateLimiter({ bucket: "auth:login", max: 1, windowMs: 30_000 });
    const req = createRequest();
    const res = createResponse();
    const next = vi.fn() as NextFunction;

    middleware(req, res, next);
    middleware(req, res, next);

    expect(next).toHaveBeenCalledOnce();
    expect((res as any).statusCode).toBe(429);
    expect((res as any).body.error).toMatch(/too many requests/i);
    expect(res.getHeader("x-ratelimit-remaining")).toBe("0");
  });

  it("isolates counters across buckets", () => {
    const loginLimiter = rateLimiter({ bucket: "auth:login", max: 1, windowMs: 30_000 });
    const refreshLimiter = rateLimiter({ bucket: "auth:refresh", max: 1, windowMs: 30_000 });
    const req = createRequest();
    const loginRes = createResponse();
    const refreshRes = createResponse();
    const next = vi.fn() as NextFunction;

    loginLimiter(req, loginRes, next);
    loginLimiter(req, loginRes, next);
    refreshLimiter(req, refreshRes, next);

    expect((loginRes as any).statusCode).toBe(429);
    expect((refreshRes as any).statusCode).toBe(200);
  });

  it("keys authenticated requests by userId, not IP", () => {
    const middleware = rateLimiter({ bucket: "auth:me", max: 1, windowMs: 30_000 });
    const req = createRequest({ user: { id: "u1", userId: "u1", email: "a@b.com" }, ip: "10.0.0.1" });
    const res = createResponse();
    const otherReq = createRequest({ user: { id: "u2", userId: "u2", email: "b@b.com" }, ip: "10.0.0.1" });
    const otherRes = createResponse();
    const next = vi.fn() as NextFunction;

    middleware(req, res, next);
    middleware(req, res, next);
    middleware(otherReq, otherRes, next);

    expect((res as any).statusCode).toBe(429);
    expect((otherRes as any).statusCode).toBe(200);
  });

  it("uses x-forwarded-for for unauthenticated clients", () => {
    const middleware = rateLimiter({ bucket: "auth:login", max: 1, windowMs: 30_000 });
    const r1 = createRequest({ headers: { "x-forwarded-for": "1.2.3.4, 10.0.0.1" } });
    const r2 = createRequest({ headers: { "x-forwarded-for": "1.2.3.4, 10.0.0.2" } });
    const r3 = createRequest({ headers: { "x-forwarded-for": "5.6.7.8, 10.0.0.3" } });
    const res1 = createResponse(), res2 = createResponse(), res3 = createResponse();
    const next = vi.fn() as NextFunction;

    middleware(r1, res1, next);
    middleware(r2, res2, next);
    middleware(r3, res3, next);

    expect((res1 as any).statusCode).toBe(200);
    expect((res2 as any).statusCode).toBe(429);
    expect((res3 as any).statusCode).toBe(200);
  });

  it("resets the window after windowMs elapses", () => {
    const middleware = rateLimiter({ max: 1, windowMs: 1_000 });
    const req = createRequest({ route: { path: "/login" } as any });
    const res = createResponse();
    const next = vi.fn() as NextFunction;

    middleware(req, res, next);
    middleware(req, res, next);
    vi.advanceTimersByTime(1_001);
    middleware(req, res, next);

    expect(next).toHaveBeenCalledTimes(2);
    expect((res as any).statusCode).toBe(429);
  });

  it("removes expired records during cleanup", () => {
    const middleware = rateLimiter({ bucket: "auth:login", max: 1, windowMs: 1_000 });
    const req = createRequest();
    const res1 = createResponse(), res2 = createResponse();
    const next = vi.fn() as NextFunction;

    middleware(req, res1, next);
    vi.advanceTimersByTime(1_001);
    cleanupRateLimiterStore(Date.now());
    middleware(req, res2, next);

    expect((res1 as any).statusCode).toBe(200);
    expect((res2 as any).statusCode).toBe(200);
  });

  it("falls back to safe defaults for invalid env vars", () => {
    process.env.RATE_LIMIT_WINDOW_MS = "invalid";
    process.env.RATE_LIMIT_MAX = "0";

    const middleware = rateLimiter({ bucket: "test" });
    const req = createRequest();
    const res = createResponse();
    const next = vi.fn() as NextFunction;

    middleware(req, res, next);

    expect(next).toHaveBeenCalledOnce();
    expect(res.getHeader("x-ratelimit-limit")).toBe("100");
  });

  it("allows a burst of exactly max requests", () => {
    const middleware = rateLimiter({ bucket: "burst", max: 3, windowMs: 1000 });
    const req = createRequest();
    const next = vi.fn() as NextFunction;

    for (let i = 0; i < 3; i++) {
      const res = createResponse();
      middleware(req, res, next);
      expect(next).toHaveBeenCalledTimes(i + 1);
      expect((res as any).statusCode).toBe(200);
    }

    const res = createResponse();
    middleware(req, res, next);
    expect(next).toHaveBeenCalledTimes(3);
    expect((res as any).statusCode).toBe(429);
  });
});

// ---------------------------------------------------------------------------
// Redis-backed store (single-node and cluster)
// ---------------------------------------------------------------------------
describe("rateLimiter — Redis store (ioredis)", () => {
  beforeEach(() => {
    vi.useRealTimers();
    delete process.env.REDIS_URL;
    delete process.env.REDIS_CLUSTER_NODES;
    resetStorePromise();
    vi.clearAllMocks();
    mockRedisClient.eval.mockReset();
    mockRedisClient.once.mockImplementation((event: string, cb: (...args: any[]) => void) => {
      if (event === "ready") cb();
    });
  });

  afterEach(() => {
    resetStorePromise();
  });

  it("returns memoryStore when no Redis env vars are set", async () => {
    const store = await getStore();
    expect(store).toBe(memoryStore);
  });

  it("returns RedisStore when REDIS_URL is set", async () => {
    process.env.REDIS_URL = "redis://127.0.0.1:6379";
    mockRedisClient.eval.mockResolvedValue([1, 30000]);

    const store = await getStore();
    expect(store).not.toBe(memoryStore);
    expect(store).toBeInstanceOf(RedisStore);
  });

  it("returns RedisStore (Cluster) when REDIS_CLUSTER_NODES is set", async () => {
    process.env.REDIS_CLUSTER_NODES = "127.0.0.1:7000,127.0.0.1:7001,127.0.0.1:7002";
    mockRedisClient.eval.mockResolvedValue([1, 30000]);

    const store = await getStore();
    expect(store).toBeInstanceOf(RedisStore);
  });

  it("uses ioredis eval signature (numkeys, key, arg) and returns correct record", async () => {
    process.env.REDIS_URL = "redis://127.0.0.1:6379";
    mockRedisClient.eval.mockResolvedValue([1, 30000]);

    const store = await getStore();
    const record = await store.increment("test-key", 30000);

    expect(record.count).toBe(1);
    expect(record.resetTime).toBeGreaterThanOrEqual(Date.now() + 29000);
    expect(mockRedisClient.eval).toHaveBeenCalledWith(
      expect.stringContaining("INCR"),
      1,          // numkeys
      "test-key", // KEYS[1]
      30000       // ARGV[1]
    );
  });

  it("falls back to memoryStore when Redis connection fails", async () => {
    process.env.REDIS_URL = "redis://127.0.0.1:6379";
    mockRedisClient.once.mockImplementation((event: string, _cb: any, reject: any) => {
      // simulate error immediately
    });
    // Make getRedisClient throw
    const { getRedisClient: mockGet } = await import("../../../src/redis.js");
    (mockGet as ReturnType<typeof vi.fn>).mockImplementationOnce(() => {
      throw new Error("Connection refused");
    });

    const store = await getStore();
    expect(store).toBe(memoryStore);
  });

  it("falls back to memoryStore at middleware level when eval throws", async () => {
    process.env.REDIS_URL = "redis://127.0.0.1:6379";
    mockRedisClient.eval.mockRejectedValue(new Error("Redis timeout"));

    const middleware = rateLimiter({ bucket: "auth:login", max: 5, windowMs: 30000 });
    const req = createRequest();
    const res = createResponse();
    const next = vi.fn();

    await new Promise<void>((resolve) => {
      next.mockImplementation(resolve);
      middleware(req, res, next);
      setTimeout(resolve, 50);
    });

    expect((res as any).statusCode).toBe(200);
  });

  it("returns 429 via RedisStore when count exceeds max", async () => {
    process.env.REDIS_URL = "redis://127.0.0.1:6379";
    mockRedisClient.eval.mockResolvedValue([3, 30000]);

    const middleware = rateLimiter({ bucket: "auth:login", max: 2, windowMs: 30000 });
    const req = createRequest();
    const res = createResponse();
    const next = vi.fn();

    await new Promise<void>((resolve) => {
      middleware(req, res, next);
      setTimeout(resolve, 50);
    });

    expect(next).not.toHaveBeenCalled();
    expect((res as any).statusCode).toBe(429);
  });

  it("REDIS_CLUSTER_NODES takes precedence over REDIS_URL", async () => {
    process.env.REDIS_URL = "redis://127.0.0.1:6379";
    process.env.REDIS_CLUSTER_NODES = "127.0.0.1:7000,127.0.0.1:7001";
    mockRedisClient.eval.mockResolvedValue([1, 30000]);

    const store = await getStore();
    expect(store).toBeInstanceOf(RedisStore);
    // getRedisClient should have been called — it picks Cluster when nodes are set
    const { getRedisClient: mockGet } = await import("../../../src/redis.js");
    expect(mockGet).toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// RedisStore unit (direct)
// ---------------------------------------------------------------------------
describe("RedisStore.increment", () => {
  it("maps [count, pttl] result to RateLimitRecord", async () => {
    const fakeClient = { eval: vi.fn().mockResolvedValue([5, 15000]) } as any;
    const store = new RedisStore(fakeClient);
    const record = await store.increment("some-key", 30000);

    expect(record.count).toBe(5);
    expect(record.resetTime).toBeGreaterThan(Date.now());
  });

  it("uses windowMs as TTL fallback when pttl is -1", async () => {
    const fakeClient = { eval: vi.fn().mockResolvedValue([1, -1]) } as any;
    const store = new RedisStore(fakeClient);
    const before = Date.now();
    const record = await store.increment("k", 5000);

    expect(record.resetTime).toBeGreaterThanOrEqual(before + 5000);
  });
});
