import express from "express";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { trace } from "@opentelemetry/api";
import { tracing } from "@opentelemetry/sdk-node";
import { metricsRegistry } from "../../metrics.js";
import {
  requestLogger,
  getNormalizedRoute,
  UNMATCHED_ROUTE,
} from "../requestLogger.js";

const memoryExporter = new tracing.InMemorySpanExporter();
const tracerProvider = new tracing.BasicTracerProvider({
  spanProcessors: [new tracing.SimpleSpanProcessor(memoryExporter)],
});
trace.setGlobalTracerProvider(tracerProvider);

function createTestApp() {
  const app = express();
  app.use(requestLogger);

  const attestationsRouter = express.Router();
  attestationsRouter.get("/:id", (req, res) => {
    res.status(200).json({ id: req.params.id });
  });
  app.use("/api/attestations", attestationsRouter);

  const businessesRouter = express.Router();
  businessesRouter.get("/:id", (req, res) => {
    res.status(200).json({ id: req.params.id });
  });
  app.use("/api/businesses", businessesRouter);

  app.get("/health", (_req, res) => {
    res.status(200).json({ status: "ok" });
  });

  return app;
}

describe("requestLogger route label and span normalization", () => {
  const originalEndpoint = process.env.OTEL_EXPORTER_OTLP_ENDPOINT;

  beforeEach(async () => {
    process.env.OTEL_EXPORTER_OTLP_ENDPOINT = "http://localhost:4318/v1/traces";
    memoryExporter.reset();
    await metricsRegistry.resetMetrics();
  });

  afterEach(() => {
    if (originalEndpoint !== undefined) {
      process.env.OTEL_EXPORTER_OTLP_ENDPOINT = originalEndpoint;
    } else {
      delete process.env.OTEL_EXPORTER_OTLP_ENDPOINT;
    }
  });

  it("produces different route labels for distinct mounted routers with same relative path", async () => {
    const app = createTestApp();

    await request(app).get("/api/attestations/abc").expect(200);
    await request(app).get("/api/businesses/abc").expect(200);

    const metrics = await metricsRegistry.getMetricsAsJSON();
    const durationMetric = metrics.find(
      (m) => m.name === "http_request_duration_seconds",
    );
    expect(durationMetric).toBeDefined();

    const routeLabels = new Set(
      durationMetric!.values
        .map((v) => v.labels.route)
        .filter((r): r is string => Boolean(r)),
    );

    expect(routeLabels).toContain("/api/attestations/:id");
    expect(routeLabels).toContain("/api/businesses/:id");
    expect(routeLabels).not.toContain("/:id");
    expect(routeLabels).not.toContain("/api/attestations/abc");
    expect(routeLabels).not.toContain("/api/businesses/abc");
  });

  it("adds at most one new route label value for 100 requests to random unmatched paths", async () => {
    const app = createTestApp();

    for (let i = 0; i < 100; i++) {
      await request(app).get(`/api/does-not-exist/${i}-${Math.random().toString(36).slice(2)}`);
    }

    const metrics = await metricsRegistry.getMetricsAsJSON();
    const durationMetric = metrics.find(
      (m) => m.name === "http_request_duration_seconds",
    );
    expect(durationMetric).toBeDefined();

    const distinctRoutes = new Set(
      durationMetric!.values
        .map((v) => v.labels.route)
        .filter((r): r is string => Boolean(r)),
    );

    expect(distinctRoutes.size).toBeLessThanOrEqual(1);
    expect(distinctRoutes).toContain(UNMATCHED_ROUTE);
  });

  it("records http.route equal to the templated route on the span for a matched request", async () => {
    const app = createTestApp();

    await request(app).get("/api/attestations/abc").expect(200);

    const spans = memoryExporter.getFinishedSpans();
    const matchedSpan = spans.find(
      (s) => s.attributes["url.path"] === "/api/attestations/abc",
    );

    expect(matchedSpan).toBeDefined();
    expect(matchedSpan!.attributes["http.route"]).toBe("/api/attestations/:id");
    expect(matchedSpan!.attributes["url.path"]).toBe("/api/attestations/abc");
    expect(matchedSpan!.name).toBe("HTTP GET /api/attestations/:id");
  });

  it("records http.route equal to __unmatched__ on the span for an unmatched request", async () => {
    const app = createTestApp();

    await request(app).get("/api/does-not-exist/scanners-xyz").expect(404);

    const spans = memoryExporter.getFinishedSpans();
    const unmatchedSpan = spans.find(
      (s) => s.attributes["url.path"] === "/api/does-not-exist/scanners-xyz",
    );

    expect(unmatchedSpan).toBeDefined();
    expect(unmatchedSpan!.attributes["http.route"]).toBe(UNMATCHED_ROUTE);
    expect(unmatchedSpan!.attributes["url.path"]).toBe("/api/does-not-exist/scanners-xyz");
    expect(unmatchedSpan!.name).toBe(`HTTP GET ${UNMATCHED_ROUTE}`);
  });

  it("handles top-level routes without baseUrl", async () => {
    const app = createTestApp();

    await request(app).get("/health").expect(200);

    const metrics = await metricsRegistry.getMetricsAsJSON();
    const durationMetric = metrics.find(
      (m) => m.name === "http_request_duration_seconds",
    );
    const routes = durationMetric!.values.map((v) => v.labels.route);
    expect(routes).toContain("/health");

    const spans = memoryExporter.getFinishedSpans();
    const healthSpan = spans.find((s) => s.attributes["url.path"] === "/health");
    expect(healthSpan).toBeDefined();
    expect(healthSpan!.attributes["http.route"]).toBe("/health");
    expect(healthSpan!.name).toBe("HTTP GET /health");
  });

  it("getNormalizedRoute helper returns baseUrl + route.path when matched and __unmatched__ when not", () => {
    expect(
      getNormalizedRoute({
        baseUrl: "/api/attestations",
        route: { path: "/:id" },
      } as any),
    ).toBe("/api/attestations/:id");

    expect(
      getNormalizedRoute({
        baseUrl: "",
        route: { path: "/health" },
      } as any),
    ).toBe("/health");

    expect(
      getNormalizedRoute({
        route: undefined,
      } as any),
    ).toBe(UNMATCHED_ROUTE);
  });
});
