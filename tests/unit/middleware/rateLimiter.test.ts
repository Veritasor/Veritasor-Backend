import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import type { Request, Response, NextFunction } from "express";
import {
  cleanupRateLimiterStore,
  cleanupSlidingStore,
  rateLimiter,
  resetRateLimiterStore,
} from "../../../src/middleware/rateLimiter.js";
import { logger } from "../../../src/utils/logger";

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

// ─── Fixed-window tests (existing behaviour) ──────────────────────────────────

describe("rateLimiter (fixed window — default)", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    resetRateLimiterStore();
  });

  afterEach(() => {
    vi.useRealTimers();
    resetRateLimiterStore();
    delete process.env.RATE_LIMIT_WINDOW_MS;
    delete process.env.RATE_LIMIT_MAX;
  });

  it("should allow requests within the configured limit and set headers", () => {
    const middleware = rateLimiter({ bucket: "auth:login", max: 2, windowMs: 30_000 });
    const req = createRequest();
    const res = createResponse();
    const next = vi.fn() as NextFunction;

    middleware(req, res, next);

    expect(next).toHaveBeenCalledOnce();
    expect((res as unknown as { statusCode: number }).statusCode).toBe(200);
    expect(res.getHeader("x-ratelimit-bucket")).toBe("auth:login");
    expect(res.getHeader("x-ratelimit-limit")).toBe("2");
    expect(res.getHeader("x-ratelimit-remaining")).toBe("1");
    expect(res.getHeader("retry-after")).toBe("30");
  });

  it("should reject requests that exceed the configured limit", () => {
    const middleware = rateLimiter({ bucket: "auth:login", max: 1, windowMs: 30_000 });
    const req = createRequest();
    const res = createResponse();
    const next = vi.fn() as NextFunction;

    middleware(req, res, next);
    middleware(req, res, next);

    expect(next).toHaveBeenCalledOnce();
    expect((res as unknown as { statusCode: number; body: { error: string } }).statusCode).toBe(429);
    expect((res as unknown as { body: { error: string } }).body.error).toMatch(/too many requests/i);
    expect(res.getHeader("x-ratelimit-remaining")).toBe("0");
  });

  it("should isolate counters across route-level buckets", () => {
    const loginLimiter = rateLimiter({ bucket: "auth:login", max: 1, windowMs: 30_000 });
    const refreshLimiter = rateLimiter({ bucket: "auth:refresh", max: 1, windowMs: 30_000 });
    const req = createRequest();
    const loginRes = createResponse();
    const refreshRes = createResponse();
    const next = vi.fn() as NextFunction;

    loginLimiter(req, loginRes, next);
    loginLimiter(req, loginRes, next);
    refreshLimiter(req, refreshRes, next);

    expect((loginRes as unknown as { statusCode: number }).statusCode).toBe(429);
    expect((refreshRes as unknown as { statusCode: number }).statusCode).toBe(200);
    expect(refreshRes.getHeader("x-ratelimit-bucket")).toBe("auth:refresh");
  });

  it("should key authenticated requests by user instead of IP address", () => {
    const middleware = rateLimiter({ bucket: "auth:me", max: 1, windowMs: 30_000 });
    const req = createRequest({
      user: { id: "user-1", userId: "user-1", email: "user@example.com" },
      ip: "10.0.0.8",
      headers: { "x-forwarded-for": "203.0.113.5" },
    });
    const res = createResponse();
    const otherUserReq = createRequest({
      user: { id: "user-2", userId: "user-2", email: "other@example.com" },
      ip: "10.0.0.8",
      headers: { "x-forwarded-for": "203.0.113.5" },
    });
    const otherUserRes = createResponse();
    const next = vi.fn() as NextFunction;

    middleware(req, res, next);
    middleware(req, res, next);
    middleware(otherUserReq, otherUserRes, next);

    expect((res as unknown as { statusCode: number }).statusCode).toBe(429);
    expect((otherUserRes as unknown as { statusCode: number }).statusCode).toBe(200);
  });

  it("should use x-forwarded-for for unauthenticated client bucketing", () => {
    const middleware = rateLimiter({ bucket: "auth:login", max: 1, windowMs: 30_000 });
    const proxiedRequest = createRequest({
      ip: "10.0.0.1",
      headers: { "x-forwarded-for": "198.51.100.42, 10.0.0.1" },
    });
    const sameForwardedRequest = createRequest({
      ip: "10.0.0.2",
      headers: { "x-forwarded-for": "198.51.100.42, 10.0.0.2" },
    });
    const differentForwardedRequest = createRequest({
      ip: "10.0.0.3",
      headers: { "x-forwarded-for": "198.51.100.43, 10.0.0.3" },
    });
    const firstResponse = createResponse();
    const secondResponse = createResponse();
    const thirdResponse = createResponse();
    const next = vi.fn() as NextFunction;

    middleware(proxiedRequest, firstResponse, next);
    middleware(sameForwardedRequest, secondResponse, next);
    middleware(differentForwardedRequest, thirdResponse, next);

    expect((firstResponse as unknown as { statusCode: number }).statusCode).toBe(200);
    expect((secondResponse as unknown as { statusCode: number }).statusCode).toBe(429);
    expect((thirdResponse as unknown as { statusCode: number }).statusCode).toBe(200);
  });

  it("should reset an expired bucket window", () => {
    const middleware = rateLimiter({ max: 1, windowMs: 1_000 });
    const req = createRequest({ route: { path: "/login" } as Request["route"] });
    const res = createResponse();
    const next = vi.fn() as NextFunction;

    middleware(req, res, next);
    middleware(req, res, next);
    vi.advanceTimersByTime(1_001);
    middleware(req, res, next);

    expect(next).toHaveBeenCalledTimes(2);
    expect((res as unknown as { statusCode: number }).statusCode).toBe(429);
    expect(res.getHeader("x-ratelimit-bucket")).toBe("POST:/api/auth/login");
  });

  it("should remove expired records during cleanup", () => {
    const middleware = rateLimiter({ bucket: "auth:login", max: 1, windowMs: 1_000 });
    const req = createRequest();
    const firstResponse = createResponse();
    const secondResponse = createResponse();
    const next = vi.fn() as NextFunction;

    middleware(req, firstResponse, next);
    vi.advanceTimersByTime(1_001);
    cleanupRateLimiterStore(Date.now());
    middleware(req, secondResponse, next);

    expect((firstResponse as unknown as { statusCode: number }).statusCode).toBe(200);
    expect((secondResponse as unknown as { statusCode: number }).statusCode).toBe(200);
  });

  it("should fall back to safe defaults when environment variables are invalid", () => {
    process.env.RATE_LIMIT_WINDOW_MS = "invalid";
    process.env.RATE_LIMIT_MAX = "0";

    const middleware = rateLimiter({
      bucket: (req) => (req.headers["x-bucket"] as string) || "",
    });
    const req = createRequest({ headers: { "x-bucket": "" } });
    const res = createResponse();
    const next = vi.fn() as NextFunction;

    middleware(req, res, next);

    expect(next).toHaveBeenCalledOnce();
    expect(res.getHeader("x-ratelimit-limit")).toBe("100");
    expect(res.getHeader("x-ratelimit-bucket")).toBe("POST:/api/auth/login");
  });

  it("should allow burst of up to max requests in fixed window", () => {
    const middleware = rateLimiter({ bucket: "burst-test", max: 3, windowMs: 1000 });
    const req = createRequest();
    const next = vi.fn() as NextFunction;

    for (let i = 0; i < 3; i++) {
      const res = createResponse();
      middleware(req, res, next);
      expect(next).toHaveBeenCalledTimes(i + 1);
      expect((res as unknown as { statusCode: number }).statusCode).toBe(200);
      expect(res.getHeader("x-ratelimit-remaining")).toBe((2 - i).toString());
    }

    const res = createResponse();
    middleware(req, res, next);
    expect(next).toHaveBeenCalledTimes(3);
    expect((res as unknown as { statusCode: number }).statusCode).toBe(429);
    expect(res.getHeader("x-ratelimit-remaining")).toBe("0");
  });

  it("fixed window allows boundary burst of up to 2*max requests", () => {
    // Documents the known fixed-window weakness — use sliding for sensitive routes.
    const middleware = rateLimiter({ bucket: "fixed-burst", max: 3, windowMs: 1_000 });
    const req = createRequest();
    const next = vi.fn() as NextFunction;

    for (let i = 0; i < 3; i++) {
      middleware(req, createResponse(), next);
    }
    expect(next).toHaveBeenCalledTimes(3);

    vi.advanceTimersByTime(1_001);

    for (let i = 0; i < 3; i++) {
      middleware(req, createResponse(), next);
    }
    expect(next).toHaveBeenCalledTimes(6);
  });
});

// ─── Sliding-window tests ─────────────────────────────────────────────────────

describe("rateLimiter (sliding window)", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    resetRateLimiterStore();
  });

  afterEach(() => {
    vi.useRealTimers();
    resetRateLimiterStore();
  });

  it("should allow requests within the configured limit and set correct headers", () => {
    const middleware = rateLimiter({ bucket: "auth:login", max: 3, windowMs: 10_000, algorithm: "sliding" });
    const req = createRequest();
    const res = createResponse();
    const next = vi.fn() as NextFunction;

    middleware(req, res, next);

    expect(next).toHaveBeenCalledOnce();
    expect(res.getHeader("x-ratelimit-bucket")).toBe("auth:login");
    expect(res.getHeader("x-ratelimit-limit")).toBe("3");
    expect(res.getHeader("x-ratelimit-remaining")).toBe("2");
  });

  it("should block the request that exceeds max", () => {
    const middleware = rateLimiter({ bucket: "auth:login", max: 2, windowMs: 10_000, algorithm: "sliding" });
    const req = createRequest();
    const next = vi.fn() as NextFunction;

    middleware(req, createResponse(), next); // 1 — ok
    middleware(req, createResponse(), next); // 2 — ok

    const blockedRes = createResponse();
    middleware(req, blockedRes, next);       // 3 — blocked

    expect(next).toHaveBeenCalledTimes(2);
    expect((blockedRes as unknown as { statusCode: number }).statusCode).toBe(429);
    expect((blockedRes as unknown as { body: { error: string } }).body.error).toMatch(/too many requests/i);
    expect(blockedRes.getHeader("x-ratelimit-remaining")).toBe("0");
  });

  it("should eliminate boundary burst — cannot exceed max across a window edge", () => {
    // Core security property that fixed-window lacks.
    const middleware = rateLimiter({ bucket: "auth:login", max: 3, windowMs: 1_000, algorithm: "sliding" });
    const req = createRequest();
    const next = vi.fn() as NextFunction;

    // Send 3 requests at t=900ms
    vi.advanceTimersByTime(900);
    for (let i = 0; i < 3; i++) {
      middleware(req, createResponse(), next);
    }
    expect(next).toHaveBeenCalledTimes(3);

    // Advance to t=1100ms — the 3 requests from t=900 are only 200ms ago,
    // still inside the 1000ms rolling window. 4th must be blocked.
    vi.advanceTimersByTime(200);
    const blockedRes = createResponse();
    middleware(req, blockedRes, next);

    expect(next).toHaveBeenCalledTimes(3);
    expect((blockedRes as unknown as { statusCode: number }).statusCode).toBe(429);
  });

  it("should allow new requests once old ones slide out of the window", () => {
    const middleware = rateLimiter({ bucket: "auth:login", max: 2, windowMs: 1_000, algorithm: "sliding" });
    const req = createRequest();
    const next = vi.fn() as NextFunction;

    // Fill the window at t=0
    middleware(req, createResponse(), next); // 1 ok
    middleware(req, createResponse(), next); // 2 ok
    middleware(req, createResponse(), next); // 3 blocked (timestamp still recorded)
    expect(next).toHaveBeenCalledTimes(2);

    // Advance 1001ms — all timestamps (including the blocked one) have expired
    vi.advanceTimersByTime(1_001);

    middleware(req, createResponse(), next); // should pass — fresh window
    expect(next).toHaveBeenCalledTimes(3);
  });

  it("should allow partial recovery as individual timestamps expire", () => {
    // max=2, windowMs=1000
    // t=0:    req1 → timestamps=[0],     count=1 ✓
    // t=500:  req2 → timestamps=[0,500], count=2 ✓
    // t=500:  req3 → timestamps=[0,500,500], count=3 ✗ (blocked, but timestamp recorded)
    // t=1002: cutoff=2, timestamps=[500,500] still in window → count=2, still full
    //         need to wait until t=1501 for t=500 timestamps to expire
    const middleware = rateLimiter({ bucket: "auth:login", max: 2, windowMs: 1_000, algorithm: "sliding" });
    const req = createRequest();
    const next = vi.fn() as NextFunction;

    // t=0
    middleware(req, createResponse(), next); // count=1 ✓
    vi.advanceTimersByTime(500);
    // t=500
    middleware(req, createResponse(), next); // count=2 ✓
    middleware(req, createResponse(), next); // count=3 ✗ blocked (timestamp still stored)
    expect(next).toHaveBeenCalledTimes(2);

    // t=1501: all three timestamps (0, 500, 500) are now outside the window
    vi.advanceTimersByTime(1_001);
    middleware(req, createResponse(), next); // fresh window — should pass
    expect(next).toHaveBeenCalledTimes(3);
  });

  it("should isolate sliding counters across different buckets", () => {
    const loginLimiter = rateLimiter({ bucket: "auth:login", max: 1, windowMs: 10_000, algorithm: "sliding" });
    const forgotLimiter = rateLimiter({ bucket: "auth:forgot-password", max: 1, windowMs: 10_000, algorithm: "sliding" });
    const req = createRequest();
    const next = vi.fn() as NextFunction;

    loginLimiter(req, createResponse(), next); // ok
    loginLimiter(req, createResponse(), next); // blocked

    const forgotRes = createResponse();
    forgotLimiter(req, forgotRes, next);       // independent bucket — must pass

    expect(next).toHaveBeenCalledTimes(2);
    expect((forgotRes as unknown as { statusCode: number }).statusCode).toBe(200);
    expect(forgotRes.getHeader("x-ratelimit-bucket")).toBe("auth:forgot-password");
  });

  it("should isolate sliding counters across different client identifiers", () => {
    const middleware = rateLimiter({ bucket: "auth:login", max: 1, windowMs: 10_000, algorithm: "sliding" });
    const req1 = createRequest({ ip: "1.1.1.1" });
    const req2 = createRequest({ ip: "2.2.2.2" });
    const next = vi.fn() as NextFunction;

    middleware(req1, createResponse(), next); // ok
    middleware(req1, createResponse(), next); // blocked

    const res2 = createResponse();
    middleware(req2, res2, next);             // different IP — must pass

    expect(next).toHaveBeenCalledTimes(2);
    expect((res2 as unknown as { statusCode: number }).statusCode).toBe(200);
  });

  it("should set Retry-After to when the oldest request will slide out", () => {
    const middleware = rateLimiter({ bucket: "auth:login", max: 1, windowMs: 10_000, algorithm: "sliding" });
    const req = createRequest();
    const next = vi.fn() as NextFunction;

    middleware(req, createResponse(), next);
    const blockedRes = createResponse();
    middleware(req, blockedRes, next);

    const retryAfter = Number(blockedRes.getHeader("retry-after"));
    expect(retryAfter).toBeGreaterThanOrEqual(1);
    expect(retryAfter).toBeLessThanOrEqual(10);
  });

  it("should use user identity for keying when authenticated", () => {
    const middleware = rateLimiter({ bucket: "auth:login", max: 1, windowMs: 10_000, algorithm: "sliding" });
    const reqA = createRequest({ user: { id: "u1", userId: "u1", email: "a@test.com" } });
    const reqB = createRequest({ user: { id: "u2", userId: "u2", email: "b@test.com" } });
    const next = vi.fn() as NextFunction;

    middleware(reqA, createResponse(), next);
    middleware(reqA, createResponse(), next); // blocked for u1

    const resB = createResponse();
    middleware(reqB, resB, next);             // u2 unaffected

    expect(next).toHaveBeenCalledTimes(2);
    expect((resB as unknown as { statusCode: number }).statusCode).toBe(200);
  });

  it("should clean up sliding store entries after window expiry", () => {
    const windowMs = 1_000;
    const middleware = rateLimiter({ bucket: "auth:login", max: 2, windowMs, algorithm: "sliding" });
    const req = createRequest();
    const next = vi.fn() as NextFunction;

    middleware(req, createResponse(), next);
    middleware(req, createResponse(), next);

    vi.advanceTimersByTime(1_001);
    cleanupSlidingStore(Date.now(), windowMs);

    middleware(req, createResponse(), next);
    expect(next).toHaveBeenCalledTimes(3);
  });

  it("mixed buckets: sliding and fixed window limiters coexist without interference", () => {
    const slidingMiddleware = rateLimiter({ bucket: "auth:login", max: 2, windowMs: 1_000, algorithm: "sliding" });
    const fixedMiddleware  = rateLimiter({ bucket: "auth:refresh", max: 2, windowMs: 1_000, algorithm: "fixed" });
    const req = createRequest();
    const next = vi.fn() as NextFunction;

    slidingMiddleware(req, createResponse(), next);
    slidingMiddleware(req, createResponse(), next);
    slidingMiddleware(req, createResponse(), next); // blocked

    fixedMiddleware(req, createResponse(), next);
    fixedMiddleware(req, createResponse(), next);
    fixedMiddleware(req, createResponse(), next); // blocked

    // 2 sliding + 2 fixed = 4
    expect(next).toHaveBeenCalledTimes(4);
  });
});
