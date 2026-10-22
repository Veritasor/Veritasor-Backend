import { afterEach, describe, expect, it, vi } from "vitest";
import express from "express";
import request from "supertest";
import { createMetricsRouter } from "../routes/metrics.js";
import { metricsRegistry } from "../metrics.js";

afterEach(() => {
  vi.restoreAllMocks();
});

describe("GET /metrics", () => {
  it("requires the configured bearer token", async () => {
    const app = express().use("/metrics", createMetricsRouter("test-metrics-token"));

    await request(app).get("/metrics").expect(401);
    await request(app).get("/metrics").set("Authorization", "Bearer wrong-token").expect(401);
    await request(app).get("/metrics").set("Authorization", "Bearer test-metrics-token").expect(200);
  }, 30_000);

  it("returns 500 if the registry fails", async () => {
    const app = express().use("/metrics", createMetricsRouter("test-metrics-token"));
    vi.spyOn(metricsRegistry, "metrics").mockRejectedValue(new Error("registry failed"));

    await request(app)
      .get("/metrics")
      .set("Authorization", "Bearer test-metrics-token")
      .expect(500);
  }, 30_000);
});
