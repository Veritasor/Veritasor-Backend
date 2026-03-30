import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import type { Request, Response, NextFunction } from "express";
import {
  cleanupRateLimiterStore,
  rateLimiter,
  resetRateLimiterStore,
} from "../../../src/middleware/rateLimiter.js";

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
});