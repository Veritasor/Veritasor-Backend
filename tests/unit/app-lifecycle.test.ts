/**
 * Focused behavior coverage for the application lifecycle surface in
 * `src/app.ts`: `stopSpiffeSvidProviderIfNeeded`, `telemetryReady` and
 * `createApp`.
 *
 * These are the module-level entry points used by the process bootstrap
 * (`startServer`) and by every integration test that imports `app`.  The suite
 * pins:
 *
 * - idempotent, no-throw SVID provider shutdown when nothing was started
 * - the telemetry bootstrap promise contract (always settles, no unhandled
 *   rejection)
 * - `createApp()` producing an independent Express instance per call
 * - the liveness probe responding 200 through the full middleware stack
 * - readiness reports (ready and failed) not affecting app construction
 * - the prototype-pollution guard rejecting unsafe query keys before routing
 */
import { describe, it, expect } from "vitest";
import request from "supertest";
import type { Express } from "express";
import {
  createApp,
  stopSpiffeSvidProviderIfNeeded,
  telemetryReady,
} from "../../src/app.js";
import type { StartupReadinessReport } from "../../src/startup/readiness.js";

const READY_REPORT: StartupReadinessReport = { ready: true, checks: [] };

const FAILED_REPORT: StartupReadinessReport = {
  ready: false,
  checks: [
    { dependency: "database", ready: false, reason: "connection refused" },
  ],
};

/** Resolves with "settled" when the promise settles, or "pending" after `ms`. */
function settlementOf(promise: Promise<unknown>, ms = 5_000) {
  return Promise.race([
    promise.then(
      () => "settled" as const,
      () => "settled" as const,
    ),
    new Promise<"pending">((resolve) => {
      const timer = setTimeout(() => resolve("pending"), ms);
      timer.unref?.();
    }),
  ]);
}

describe("app lifecycle — stopSpiffeSvidProviderIfNeeded", () => {
  it("is a safe no-op when no SVID provider was started", () => {
    expect(() => stopSpiffeSvidProviderIfNeeded()).not.toThrow();
    expect(stopSpiffeSvidProviderIfNeeded()).toBeUndefined();
  });

  it("is idempotent across repeated shutdown calls", () => {
    expect(() => {
      stopSpiffeSvidProviderIfNeeded();
      stopSpiffeSvidProviderIfNeeded();
      stopSpiffeSvidProviderIfNeeded();
    }).not.toThrow();
  });

  it("keeps the application serving traffic after shutdown was requested", async () => {
    stopSpiffeSvidProviderIfNeeded();

    const res = await request(createApp(READY_REPORT)).get("/api/health/live");

    expect(res.status).toBe(200);
    expect(res.body.status).toBe("ok");
  });
});

describe("app lifecycle — telemetryReady", () => {
  it("exposes the bootstrap promise for startup sequencing", () => {
    expect(telemetryReady).toBeInstanceOf(Promise);
  });

  it("settles without leaving an unhandled rejection behind", async () => {
    expect(await settlementOf(telemetryReady)).toBe("settled");
  });
});

describe("app lifecycle — createApp", () => {
  it("returns a fresh Express application per call", () => {
    const first = createApp(READY_REPORT);
    const second = createApp(READY_REPORT);

    expect(first).not.toBe(second);
    for (const app of [first, second]) {
      expect(typeof app).toBe("function");
      expect(typeof (app as Express).listen).toBe("function");
      expect(typeof (app as Express).use).toBe("function");
    }
  });

  it("builds a usable app even when the readiness report is not ready", () => {
    const app = createApp(FAILED_REPORT);

    expect(typeof app.listen).toBe("function");
  });

  it("serves the liveness probe through the full middleware stack", async () => {
    const res = await request(createApp(READY_REPORT)).get("/api/health/live");

    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      status: "ok",
      service: "veritasor-backend",
      timestamp: expect.any(String),
    });
    expect(Number.isNaN(Date.parse(res.body.timestamp))).toBe(false);
  });

  it("advertises the negotiated API version on every response", async () => {
    const res = await request(createApp(READY_REPORT)).get("/api/health/live");

    expect(res.headers["api-version"]).toBe("v1");
    expect(res.headers["vary"]).toContain("Accept");
  });

  it("rejects query-string prototype pollution before routing", async () => {
    const res = await request(createApp(READY_REPORT)).get(
      "/api/health/live?prototype=1",
    );

    expect(res.status).toBe(400);
    expect(res.body).toEqual({
      status: "error",
      code: "VALIDATION_ERROR",
      message: "Invalid query parameters",
    });
  });

  it("does not fail a request carrying a __proto__ query key", async () => {
    const res = await request(createApp(READY_REPORT)).get(
      "/api/health/live?__proto__=polluted",
    );

    expect(res.status).not.toBe(500);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });
});
