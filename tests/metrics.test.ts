import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import express from "express";
import request from "supertest";
import crypto from "node:crypto";
import { metricsRegistry, httpRequestDuration, rateLimitRejections } from "../src/metrics.js";
import { requestLogger } from "../src/middleware/requestLogger.js";
import { rateLimiter, resetRateLimiterStore } from "../src/middleware/rateLimiter.js";
import { createApp, timingSafeCompare } from "../src/app.js";
import { logger } from "../src/utils/logger.js";

beforeEach(async () => {
  // Reset all metrics between tests to avoid cross-test pollution
  await metricsRegistry.resetMetrics();
  resetRateLimiterStore();
});

describe("metrics registry", () => {
  it("exposes http_request_duration_seconds histogram", async () => {
    const output = await metricsRegistry.metrics();
    expect(output).toContain("http_request_duration_seconds");
  });

  it("exposes http_rate_limit_rejections_total counter", async () => {
    rateLimitRejections.inc({ bucket: "auth:login" });
    const output = await metricsRegistry.metrics();
    expect(output).toContain("http_rate_limit_rejections");
  });

  it("output is valid Prometheus text format (starts with # HELP)", async () => {
    const output = await metricsRegistry.metrics();
    expect(output).toMatch(/^# HELP /m);
  });
});

describe("httpRequestDuration histogram", () => {
  it("records an observation with correct labels", async () => {
    httpRequestDuration.observe({ labels: { method: "GET", route: "/api/health", status_code: "200" }, value: 0.05 });
    const output = await metricsRegistry.metrics();
    expect(output).toContain('method="GET"');
    expect(output).toContain('route="/api/health"');
    expect(output).toContain('status_code="200"');
  });

  it("records distinct route labels without cross-contamination", async () => {
    httpRequestDuration.observe({ labels: { method: "GET", route: "/api/health", status_code: "200" }, value: 0.01 });
    httpRequestDuration.observe({ labels: { method: "POST", route: "/api/attestations", status_code: "201" }, value: 0.1 });
    const output = await metricsRegistry.metrics();
    expect(output).toContain('route="/api/health"');
    expect(output).toContain('route="/api/attestations"');
  });
});

describe("rateLimitRejections counter", () => {
  it("increments on each call", async () => {
    rateLimitRejections.inc({ bucket: "auth:login" });
    rateLimitRejections.inc({ bucket: "auth:login" });
    const metrics = await metricsRegistry.getMetricsAsJSON();
    const counter = metrics.find((m) => m.name === "http_rate_limit_rejections" || m.name === "http_rate_limit_rejections_total");
    expect(counter).toBeDefined();
    const value = (counter!.values as Array<{ labels: Record<string, string>; value: number }>).find(
      (v) => v.labels.bucket === "auth:login",
    );
    expect(value?.value).toBe(2);
  });

  it("tracks separate buckets independently", async () => {
    rateLimitRejections.inc({ bucket: "auth:login" });
    rateLimitRejections.inc({ bucket: "auth:signup" });
    rateLimitRejections.inc({ bucket: "auth:signup" });
    const metrics = await metricsRegistry.getMetricsAsJSON();
    const counter = metrics.find((m) => m.name === "http_rate_limit_rejections" || m.name === "http_rate_limit_rejections_total");
    const values = counter!.values as Array<{ labels: Record<string, string>; value: number }>;
    expect(values.find((v) => v.labels.bucket === "auth:login")?.value).toBe(1);
    expect(values.find((v) => v.labels.bucket === "auth:signup")?.value).toBe(2);
  });
});

describe("requestLogger middleware wires histogram", () => {
  it("records a histogram observation after a request completes", async () => {
    const app = express();
    app.use(requestLogger);
    app.get("/test-route", (_req, res) => res.status(200).json({ ok: true }));

    await request(app).get("/test-route");

    const metrics = await metricsRegistry.getMetricsAsJSON();
    const hist = metrics.find((m) => m.name === "http_request_duration_seconds");
    expect(hist).toBeDefined();
    // At least one bucket count should be > 0
    const hasObservation = (hist!.values as Array<{ value: number }>).some((v) => v.value > 0);
    expect(hasObservation).toBe(true);
  });
});

describe("rateLimiter middleware increments counter on 429", () => {
  it("increments rateLimitRejections when limit is exceeded (sync path)", async () => {
    const app = express();
    app.use(rateLimiter({ max: 1, windowMs: 60_000 }));
    app.get("/limited", (_req, res) => res.status(200).json({ ok: true }));

    await request(app).get("/limited"); // allowed
    await request(app).get("/limited"); // rejected → 429

    const metrics = await metricsRegistry.getMetricsAsJSON();
    const counter = metrics.find((m) => m.name === "http_rate_limit_rejections" || m.name === "http_rate_limit_rejections_total");
    expect(counter).toBeDefined();
    const total = (counter!.values as Array<{ value: number }>).reduce((s, v) => s + v.value, 0);
    expect(total).toBeGreaterThanOrEqual(1);
  });
});

describe("/metrics route", () => {
  it("returns 404 when METRICS_ENABLED is not set", async () => {
    delete process.env.METRICS_ENABLED;
    const app = createApp({ ready: true, checks: [] });
    const res = await request(app).get("/metrics");
    expect(res.status).toBe(404);
  });

  it("returns 200 with Prometheus text when METRICS_ENABLED=true", async () => {
    process.env.METRICS_ENABLED = "true";
    delete process.env.METRICS_AUTH_TOKEN;
    const app = createApp({ ready: true, checks: [] });
    const res = await request(app).get("/metrics");
    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toBe(metricsRegistry.contentType);
    expect(res.text).toContain("http_request_duration_seconds");
    delete process.env.METRICS_ENABLED;
  });
});

describe("/metrics authentication and security", () => {
  const TEST_TOKEN = "super-secret-metrics-token-12345";

  beforeEach(() => {
    process.env.METRICS_ENABLED = "true";
    process.env.METRICS_AUTH_TOKEN = TEST_TOKEN;
  });

  afterEach(() => {
    delete process.env.METRICS_ENABLED;
    delete process.env.METRICS_AUTH_TOKEN;
    vi.restoreAllMocks();
  });

  it("returns 401 with WWW-Authenticate header when no Authorization header is provided", async () => {
    const app = createApp({ ready: true, checks: [] });
    const res = await request(app).get("/metrics");

    expect(res.status).toBe(401);
    expect(res.headers["www-authenticate"]).toBe('Bearer realm="metrics"');
    expect(res.body).toEqual({ error: "Unauthorized" });
  });

  it("returns 401 with WWW-Authenticate header when Authorization scheme is not Bearer", async () => {
    const app = createApp({ ready: true, checks: [] });
    const res = await request(app)
      .get("/metrics")
      .set("Authorization", "Basic dXNlcjpwYXNz");

    expect(res.status).toBe(401);
    expect(res.headers["www-authenticate"]).toBe('Bearer realm="metrics"');
    expect(res.body).toEqual({ error: "Unauthorized" });
  });

  it("returns 401 with WWW-Authenticate header when Bearer token is empty", async () => {
    const app = createApp({ ready: true, checks: [] });
    const res = await request(app)
      .get("/metrics")
      .set("Authorization", "Bearer ");

    expect(res.status).toBe(401);
    expect(res.headers["www-authenticate"]).toBe('Bearer realm="metrics"');
    expect(res.body).toEqual({ error: "Unauthorized" });
  });

  it("returns 401 with WWW-Authenticate header when token is wrong", async () => {
    const app = createApp({ ready: true, checks: [] });
    const res = await request(app)
      .get("/metrics")
      .set("Authorization", "Bearer wrong-token");

    expect(res.status).toBe(401);
    expect(res.headers["www-authenticate"]).toBe('Bearer realm="metrics"');
    expect(res.body).toEqual({ error: "Unauthorized" });
  });

  it("returns 401 when token has matching prefix but wrong length", async () => {
    const app = createApp({ ready: true, checks: [] });
    const res = await request(app)
      .get("/metrics")
      .set("Authorization", `Bearer ${TEST_TOKEN.slice(0, 10)}`);

    expect(res.status).toBe(401);
    expect(res.headers["www-authenticate"]).toBe('Bearer realm="metrics"');
  });

  it("returns 200 with metrics text when correct token is provided", async () => {
    const app = createApp({ ready: true, checks: [] });
    const res = await request(app)
      .get("/metrics")
      .set("Authorization", `Bearer ${TEST_TOKEN}`);

    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toBe(metricsRegistry.contentType);
    expect(res.text).toContain("http_request_duration_seconds");
  });

  it("uses timing-safe comparison to verify token (invoking crypto.timingSafeEqual)", async () => {
    const timingSpy = vi.spyOn(crypto, "timingSafeEqual");
    const app = createApp({ ready: true, checks: [] });

    await request(app)
      .get("/metrics")
      .set("Authorization", `Bearer ${TEST_TOKEN}`);

    expect(timingSpy).toHaveBeenCalled();
  });

  it("maintains open behavior when METRICS_AUTH_TOKEN is not configured", async () => {
    delete process.env.METRICS_AUTH_TOKEN;
    const app = createApp({ ready: true, checks: [] });
    const res = await request(app).get("/metrics");

    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toBe(metricsRegistry.contentType);
    expect(res.text).toContain("http_request_duration_seconds");
  });

  it("logs a startup warning in production when METRICS_AUTH_TOKEN is unset", () => {
    delete process.env.METRICS_AUTH_TOKEN;
    const originalNodeEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = "production";

    const warnSpy = vi.spyOn(logger, "warn").mockImplementation(() => {});

    try {
      createApp({ ready: true, checks: [] });
      expect(warnSpy).toHaveBeenCalledWith(
        expect.stringContaining("METRICS_AUTH_TOKEN is not configured in production"),
      );
    } finally {
      process.env.NODE_ENV = originalNodeEnv;
    }
  });

  it("does not log a startup warning in production when METRICS_AUTH_TOKEN is configured", () => {
    process.env.METRICS_AUTH_TOKEN = TEST_TOKEN;
    const originalNodeEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = "production";

    const warnSpy = vi.spyOn(logger, "warn").mockImplementation(() => {});

    try {
      createApp({ ready: true, checks: [] });
      expect(warnSpy).not.toHaveBeenCalledWith(
        expect.stringContaining("METRICS_AUTH_TOKEN is not configured in production"),
      );
    } finally {
      process.env.NODE_ENV = originalNodeEnv;
    }
  });
});

describe("timingSafeCompare utility", () => {
  it("returns true for identical strings", () => {
    expect(timingSafeCompare("my-secret-token", "my-secret-token")).toBe(true);
  });

  it("returns false for different strings of same length", () => {
    expect(timingSafeCompare("my-secret-token-a", "my-secret-token-b")).toBe(false);
  });

  it("returns false for different strings of different lengths", () => {
    expect(timingSafeCompare("short", "much-longer-token-value")).toBe(false);
  });

  it("returns false when inputs are non-strings", () => {
    expect(timingSafeCompare(null as any, "token")).toBe(false);
    expect(timingSafeCompare("token", undefined as any)).toBe(false);
    expect(timingSafeCompare(123 as any, 123 as any)).toBe(false);
  });

  it("executes in constant time using crypto.timingSafeEqual on 32-byte digests", () => {
    const timingSpy = vi.spyOn(crypto, "timingSafeEqual");
    const result = timingSafeCompare("a", "b");
    expect(result).toBe(false);
    expect(timingSpy).toHaveBeenCalledTimes(1);
    const [bufA, bufB] = timingSpy.mock.calls[0];
    expect(bufA.length).toBe(32);
    expect(bufB.length).toBe(32);
  });
});
