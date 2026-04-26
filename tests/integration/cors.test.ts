import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import express from "express";
import request from "supertest";

/**
 * CORS integration tests.
 *
 * These tests validate the full CORS middleware behaviour against a real
 * Express stack without requiring a database or external services.
 *
 * Coverage targets:
 * - Allowed origins receive correct CORS headers
 * - Disallowed origins are rejected (no CORS headers)
 * - Preflight (OPTIONS) requests are handled correctly
 * - Same-origin / no-Origin requests pass through
 * - Credentials header behaviour in allowlist vs wildcard mode
 * - Exposed headers and allowed methods
 */

// ---------------------------------------------------------------------------
// Helpers – build a tiny Express app with the CORS middleware under test
// ---------------------------------------------------------------------------

async function buildApp() {
  // Dynamic import *after* env vars are set — config reads process.env at
  // import time, and vi.resetModules() clears the module cache each test.
  const { createCorsMiddleware } = await import(
    "../../src/middleware/cors.ts"
  );

  const app = express();
  app.use(createCorsMiddleware());
  app.use(express.json());

  // Minimal test endpoint
  app.get("/api/test", (_req, res) => {
    res.json({ ok: true });
  });

  return app;
}

// ---------------------------------------------------------------------------
// Allowlist mode (production-like)
// ---------------------------------------------------------------------------

describe("CORS — allowlist mode", () => {
  const ALLOWED = "https://app.veritasor.com";
  const ALSO_ALLOWED = "https://admin.veritasor.com";
  const BLOCKED = "https://evil.example.com";

  let app: express.Express;

  beforeEach(async () => {
    // Reset module cache so config is re-evaluated with new env vars
    vi.resetModules();
    process.env.NODE_ENV = "production";
    process.env.ALLOWED_ORIGINS = `${ALLOWED},${ALSO_ALLOWED}`;
    app = await buildApp();
  });

  afterEach(() => {
    delete process.env.ALLOWED_ORIGINS;
    delete process.env.NODE_ENV;
  });

  it("should return CORS headers for an allowed origin", async () => {
    const res = await request(app)
      .get("/api/test")
      .set("Origin", ALLOWED);

    expect(res.status).toBe(200);
    expect(res.headers["access-control-allow-origin"]).toBe(ALLOWED);
    expect(res.headers["access-control-allow-credentials"]).toBe("true");
  });

  it("should return CORS headers for a second allowed origin", async () => {
    const res = await request(app)
      .get("/api/test")
      .set("Origin", ALSO_ALLOWED);

    expect(res.status).toBe(200);
    expect(res.headers["access-control-allow-origin"]).toBe(ALSO_ALLOWED);
  });

  it("should NOT return CORS headers for a blocked origin", async () => {
    const res = await request(app)
      .get("/api/test")
      .set("Origin", BLOCKED);

    expect(res.status).toBe(200);
    // The cors package sets origin to "false" string when not allowed
    expect(
      res.headers["access-control-allow-origin"] === undefined ||
      res.headers["access-control-allow-origin"] === "false",
    ).toBe(true);
  });

  it("should handle preflight (OPTIONS) for an allowed origin", async () => {
    const res = await request(app)
      .options("/api/test")
      .set("Origin", ALLOWED)
      .set("Access-Control-Request-Method", "POST")
      .set("Access-Control-Request-Headers", "Content-Type, Authorization");

    expect(res.status).toBe(204);
    expect(res.headers["access-control-allow-origin"]).toBe(ALLOWED);
    expect(res.headers["access-control-allow-methods"]).toContain("POST");
    expect(res.headers["access-control-max-age"]).toBe("86400");
    expect(res.headers["access-control-allow-credentials"]).toBe("true");
  });

  it("should NOT set CORS headers on preflight for a blocked origin", async () => {
    const res = await request(app)
      .options("/api/test")
      .set("Origin", BLOCKED)
      .set("Access-Control-Request-Method", "POST");

    // The cors package still responds 204 but does not set allow-origin
    expect(
      res.headers["access-control-allow-origin"] === undefined ||
      res.headers["access-control-allow-origin"] === "false",
    ).toBe(true);
  });

  it("should allow requests with no Origin header (same-origin)", async () => {
    const res = await request(app).get("/api/test");

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ ok: true });
  });

  it("should expose X-Request-ID in Access-Control-Expose-Headers", async () => {
    const res = await request(app)
      .get("/api/test")
      .set("Origin", ALLOWED);

    expect(res.headers["access-control-expose-headers"]).toContain(
      "X-Request-ID",
    );
  });

  it("should include all expected methods in Access-Control-Allow-Methods on preflight", async () => {
    const res = await request(app)
      .options("/api/test")
      .set("Origin", ALLOWED)
      .set("Access-Control-Request-Method", "DELETE");

    const methods = res.headers["access-control-allow-methods"];
    for (const m of ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]) {
      expect(methods).toContain(m);
    }
  });
});

// ---------------------------------------------------------------------------
// Wildcard mode (development)
// ---------------------------------------------------------------------------

describe("CORS — wildcard mode (dev)", () => {
  let app: express.Express;

  beforeEach(async () => {
    vi.resetModules();
    delete process.env.ALLOWED_ORIGINS;
    process.env.NODE_ENV = "development";
    app = await buildApp();
  });

  afterEach(() => {
    delete process.env.NODE_ENV;
  });

  it("should reflect the request origin for any origin", async () => {
    const res = await request(app)
      .get("/api/test")
      .set("Origin", "http://localhost:5173");

    expect(res.status).toBe(200);
    // In wildcard mode with origin callback returning true,
    // the cors package reflects the request origin
    expect(res.headers["access-control-allow-origin"]).toBeDefined();
  });

  it("should NOT include Access-Control-Allow-Credentials in wildcard mode", async () => {
    const res = await request(app)
      .get("/api/test")
      .set("Origin", "http://localhost:5173");

    // credentials should be absent or not "true"
    expect(res.headers["access-control-allow-credentials"]).toBeUndefined();
  });

  it("should still work for requests without an Origin header", async () => {
    const res = await request(app).get("/api/test");

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ ok: true });
  });
});

// ---------------------------------------------------------------------------
// Structured logging for rejected origins
// ---------------------------------------------------------------------------

describe("CORS — structured logging", () => {
  let app: express.Express;
  let warnSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(async () => {
    vi.resetModules();
    process.env.NODE_ENV = "production";
    process.env.ALLOWED_ORIGINS = "https://app.veritasor.com";
    warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    app = await buildApp();
  });

  afterEach(() => {
    warnSpy.mockRestore();
    delete process.env.ALLOWED_ORIGINS;
    delete process.env.NODE_ENV;
  });

  it("should log a structured warning when an origin is rejected", async () => {
    await request(app)
      .get("/api/test")
      .set("Origin", "https://evil.example.com");

    expect(warnSpy).toHaveBeenCalled();
    const logCall = warnSpy.mock.calls.find((call) =>
      call.some(
        (arg) => typeof arg === "string" && arg.includes("cors_rejected"),
      ),
    );
    expect(logCall).toBeDefined();
  });

  it("should NOT log a warning for an allowed origin", async () => {
    await request(app)
      .get("/api/test")
      .set("Origin", "https://app.veritasor.com");

    const logCall = warnSpy.mock.calls.find((call) =>
      call.some(
        (arg) => typeof arg === "string" && arg.includes("cors_rejected"),
      ),
    );
    expect(logCall).toBeUndefined();
  });
});
