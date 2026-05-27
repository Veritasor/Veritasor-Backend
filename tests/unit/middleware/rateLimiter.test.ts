import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import type { Request, Response, NextFunction } from "express";
import {
  cleanupRateLimiterStore,
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

describe("rateLimiter", () => {
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

     // Make 3 requests (should all be allowed)
     for (let i = 0; i < 3; i++) {
       const res = createResponse();
       middleware(req, res, next);
       expect(next).toHaveBeenCalledTimes(i + 1);
       expect((res as unknown as { statusCode: number }).statusCode).toBe(200);
       expect(res.getHeader("x-ratelimit-remaining")).toBe((2 - i).toString());
     }

     // 4th request should be rate limited
     const res = createResponse();
     middleware(req, res, next);
     expect(next).toHaveBeenCalledTimes(3); // next not called for 4th request
     expect((res as unknown as { statusCode: number }).statusCode).toBe(429);
     expect(res.getHeader("x-ratelimit-remaining")).toBe("0");
   });
 });

describe("auth route rate-limit bucket isolation", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    resetRateLimiterStore();
  });

  afterEach(() => {
    vi.useRealTimers();
    resetRateLimiterStore();
  });

  it("should isolate all five auth buckets from each other", () => {
    const buckets = [
      { name: "auth:login", limiter: rateLimiter({ bucket: "auth:login", max: 2, windowMs: 30_000 }) },
      { name: "auth:refresh", limiter: rateLimiter({ bucket: "auth:refresh", max: 2, windowMs: 30_000 }) },
      { name: "auth:forgot-password", limiter: rateLimiter({ bucket: "auth:forgot-password", max: 2, windowMs: 30_000 }) },
      { name: "auth:reset-password", limiter: rateLimiter({ bucket: "auth:reset-password", max: 2, windowMs: 30_000 }) },
      { name: "auth:me", limiter: rateLimiter({ bucket: "auth:me", max: 2, windowMs: 30_000 }) },
    ];
    const req = createRequest();
    const next = vi.fn() as NextFunction;

    for (const { name, limiter } of buckets) {
      const r1 = createResponse();
      limiter(req, r1, next);
      expect((r1 as unknown as { statusCode: number }).statusCode).toBe(200);
      expect(r1.getHeader("x-ratelimit-bucket")).toBe(name);
      expect(r1.getHeader("x-ratelimit-remaining")).toBe("1");

      const r2 = createResponse();
      limiter(req, r2, next);
      expect((r2 as unknown as { statusCode: number }).statusCode).toBe(200);
      expect(r2.getHeader("x-ratelimit-remaining")).toBe("0");

      const r3 = createResponse();
      limiter(req, r3, next);
      expect((r3 as unknown as { statusCode: number }).statusCode).toBe(429);
    }
  });

  it("should enforce per-identifier separation between authenticated users on auth:me", () => {
    const meLimiter = rateLimiter({ bucket: "auth:me", max: 1, windowMs: 30_000 });
    const next = vi.fn() as NextFunction;

    const user1Req = createRequest({
      user: { id: "user-1", userId: "user-1", email: "alice@example.com" },
    });
    const user2Req = createRequest({
      user: { id: "user-2", userId: "user-2", email: "bob@example.com" },
    });

    const u1r1 = createResponse();
    meLimiter(user1Req, u1r1, next);
    expect((u1r1 as unknown as { statusCode: number }).statusCode).toBe(200);

    const u1r2 = createResponse();
    meLimiter(user1Req, u1r2, next);
    expect((u1r2 as unknown as { statusCode: number }).statusCode).toBe(429);

    const u2r1 = createResponse();
    meLimiter(user2Req, u2r1, next);
    expect((u2r1 as unknown as { statusCode: number }).statusCode).toBe(200);
  });

  it("should enforce per-identifier separation between different IPs on the same bucket", () => {
    const loginLimiter = rateLimiter({ bucket: "auth:login", max: 1, windowMs: 30_000 });
    const next = vi.fn() as NextFunction;

    const ip1Req = createRequest({ ip: "192.168.1.1", headers: {} });
    const ip2Req = createRequest({ ip: "192.168.1.2", headers: {} });

    const r1 = createResponse();
    loginLimiter(ip1Req, r1, next);
    expect((r1 as unknown as { statusCode: number }).statusCode).toBe(200);

    const r2 = createResponse();
    loginLimiter(ip1Req, r2, next);
    expect((r2 as unknown as { statusCode: number }).statusCode).toBe(429);

    const r3 = createResponse();
    loginLimiter(ip2Req, r3, next);
    expect((r3 as unknown as { statusCode: number }).statusCode).toBe(200);
  });

  it("should reset an exhausted bucket independently when its window expires while other buckets remain exhausted", () => {
    const loginLimiter = rateLimiter({ bucket: "auth:login", max: 1, windowMs: 30_000 });
    const refreshLimiter = rateLimiter({ bucket: "auth:refresh", max: 1, windowMs: 60_000 });
    const req = createRequest();
    const next = vi.fn() as NextFunction;

    const l1 = createResponse();
    loginLimiter(req, l1, next);
    expect((l1 as unknown as { statusCode: number }).statusCode).toBe(200);

    const r1 = createResponse();
    refreshLimiter(req, r1, next);
    expect((r1 as unknown as { statusCode: number }).statusCode).toBe(200);

    const l2 = createResponse();
    loginLimiter(req, l2, next);
    expect((l2 as unknown as { statusCode: number }).statusCode).toBe(429);

    const r2 = createResponse();
    refreshLimiter(req, r2, next);
    expect((r2 as unknown as { statusCode: number }).statusCode).toBe(429);

    vi.advanceTimersByTime(31_000);

    const l3 = createResponse();
    loginLimiter(req, l3, next);
    expect((l3 as unknown as { statusCode: number }).statusCode).toBe(200);
    expect(l3.getHeader("x-ratelimit-bucket")).toBe("auth:login");

    const r3 = createResponse();
    refreshLimiter(req, r3, next);
    expect((r3 as unknown as { statusCode: number }).statusCode).toBe(429);
    expect(r3.getHeader("x-ratelimit-bucket")).toBe("auth:refresh");
  });
});