import express from "express";
import request from "supertest";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  requestLogger,
  sanitizeCorrelationId,
} from "../../../src/middleware/requestLogger.js";

function createProbeApp() {
  const app = express();
  app.use(requestLogger);
  app.get("/probe", (req, res) => {
    res.json({ correlationId: (req as express.Request & { correlationId: string }).correlationId });
  });
  return app;
}

function parseJsonLogs(spy: ReturnType<typeof vi.spyOn>) {
  return spy.mock.calls.map(([line]) => JSON.parse(String(line)) as Record<string, unknown>);
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("requestLogger correlation id propagation", () => {
  it("reuses inbound x-correlation-id, attaches it to req, and echoes response headers", async () => {
    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const response = await request(createProbeApp())
      .get("/probe")
      .set("x-correlation-id", "corr-inbound-123")
      .expect(200);

    expect(response.body.correlationId).toBe("corr-inbound-123");
    expect(response.headers["x-correlation-id"]).toBe("corr-inbound-123");
    expect(response.headers["x-request-id"]).toBe("corr-inbound-123");

    const logs = parseJsonLogs(consoleSpy);
    expect(logs).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ type: "request", correlationId: "corr-inbound-123" }),
        expect.objectContaining({ type: "response", correlationId: "corr-inbound-123" }),
      ]),
    );
  });

  it("generates a safe correlation id when the inbound value is missing", async () => {
    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const response = await request(createProbeApp()).get("/probe").expect(200);

    expect(response.headers["x-correlation-id"]).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    );
    expect(response.body.correlationId).toBe(response.headers["x-correlation-id"]);

    const logs = parseJsonLogs(consoleSpy);
    expect(logs[0].correlationId).toBe(response.headers["x-correlation-id"]);
  });

  it("rejects malformed inbound ids instead of reflecting them into logs or headers", async () => {
    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const response = await request(createProbeApp())
      .get("/probe")
      .set("x-correlation-id", "bad id 123")
      .expect(200);

    expect(response.headers["x-correlation-id"]).not.toBe("bad id 123");
    expect(response.headers["x-correlation-id"]).toMatch(/^[a-f0-9-]{36}$/i);

    const serializedLogs = JSON.stringify(parseJsonLogs(consoleSpy));
    expect(serializedLogs).not.toContain("bad id 123");
  });

  it("sanitizes acceptable ids and rejects unsafe ones", () => {
    expect(sanitizeCorrelationId(" trace-123456 ")).toBe("trace-123456");
    expect(sanitizeCorrelationId("short")).toBeUndefined();
    expect(sanitizeCorrelationId("bad\r\nheader")).toBeUndefined();
  });
});
