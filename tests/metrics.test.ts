import { describe, it, expect, beforeEach } from "vitest";
import express from "express";
import request from "supertest";
import { metricsRegistry, httpRequestDuration, rateLimitRejections } from "../src/metrics.js";
import { requestLogger } from "../src/middleware/requestLogger.js";
import { rateLimiter, resetRateLimiterStore } from "../src/middleware/rateLimiter.js";
import { createApp } from "../src/app.js";

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
    const output = await metricsRegistry.metrics();
    expect(output).toContain("http_rate_limit_rejections_total");
  });

  it("output is valid Prometheus text format (starts with # HELP)", async () => {
    const output = await metricsRegistry.metrics();
    expect(output).toMatch(/^# HELP /m);
  });
});

describe("httpRequestDuration histogram", () => {
  it("records an observation with correct labels", async () => {
    httpRequestDuration.observe({ method: "GET", route: "/api/health", status_code: "200" }, 0.05);
    const output = await metricsRegistry.metrics();
    expect(output).toContain('method="GET"');
    expect(output).toContain('route="/api/health"');
    expect(output).toContain('status_code="200"');
  });

  it("records distinct route labels without cross-contamination", async () => {
    httpRequestDuration.observe({ method: "GET", route: "/api/health", status_code: "200" }, 0.01);
    httpRequestDuration.observe({ method: "POST", route: "/api/attestations", status_code: "201" }, 0.1);
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
    const counter = metrics.find((m) => m.name === "http_rate_limit_rejections_total");
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
    const counter = metrics.find((m) => m.name === "http_rate_limit_rejections_total");
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
    const counter = metrics.find((m) => m.name === "http_rate_limit_rejections_total");
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
    const app = createApp({ ready: true, checks: [] });
    const res = await request(app).get("/metrics");
    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toMatch(/text\/plain/);
    expect(res.text).toContain("http_request_duration_seconds");
    delete process.env.METRICS_ENABLED;
  });
});
