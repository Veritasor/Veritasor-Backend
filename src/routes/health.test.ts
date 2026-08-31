/**
 * Tests for the health check endpoints.
 *
 * Covers:
 *   GET /api/health/live   — liveness probe (no dependency checks)
 *   GET /api/health/ready  — readiness probe (DB check)
 *   GET /api/health        — full health check (shallow + deep modes)
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import request from "supertest";
import express from "express";
import { healthRouter } from "./health.js";

// ---------------------------------------------------------------------------
// Test app setup
// ---------------------------------------------------------------------------
function buildApp() {
  const app = express();
  app.use(express.json());
  app.use("/api/health", healthRouter);
  return app;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Stub the shared db client so DB checks don't need a real database.
 * `checkDatabase()` (src/startup/readiness.ts) queries via `db` from
 * `../db/client.js`, so that is the boundary to mock here rather than `pg`
 * directly — `db` wraps a `pg.Pool`, not a `pg.Client`.
 */
function mockDbClient(behaviour: "ok" | "down") {
  vi.doMock("../db/client.js", () => ({
    db: {
      query:
        behaviour === "ok"
          ? vi.fn().mockResolvedValue({ rows: [{ "?column?": 1 }] })
          : vi.fn().mockRejectedValue(new Error("ECONNREFUSED")),
    },
  }));
}

// ---------------------------------------------------------------------------
// GET /api/health/live — liveness probe
// ---------------------------------------------------------------------------
describe("GET /api/health/live", () => {
  it("returns 200 with status ok", async () => {
    const res = await request(buildApp()).get("/api/health/live");

    expect(res.status).toBe(200);
    expect(res.body.status).toBe("ok");
    expect(res.body.service).toBe("veritasor-backend");
    expect(res.body.timestamp).toBeDefined();
  });

  it("returns a valid ISO 8601 timestamp", async () => {
    const res = await request(buildApp()).get("/api/health/live");

    expect(() => new Date(res.body.timestamp)).not.toThrow();
    expect(new Date(res.body.timestamp).toISOString()).toBe(res.body.timestamp);
  });

  it("does NOT include db, redis, or mode fields", async () => {
    const res = await request(buildApp()).get("/api/health/live");

    expect(res.body.db).toBeUndefined();
    expect(res.body.redis).toBeUndefined();
    expect(res.body.mode).toBeUndefined();
  });

  it("responds even when DATABASE_URL is not set", async () => {
    const original = process.env.DATABASE_URL;
    delete process.env.DATABASE_URL;

    const res = await request(buildApp()).get("/api/health/live");
    expect(res.status).toBe(200);

    process.env.DATABASE_URL = original;
  });
});

// ---------------------------------------------------------------------------
// GET /api/health/ready — readiness probe
// ---------------------------------------------------------------------------
describe("GET /api/health/ready", () => {
  beforeEach(() => {
    vi.resetModules();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("returns 200 when DATABASE_URL is not set (no DB check)", async () => {
    const original = process.env.DATABASE_URL;
    delete process.env.DATABASE_URL;

    const res = await request(buildApp()).get("/api/health/ready");
    expect(res.status).toBe(200);
    expect(res.body.status).toBe("ok");
    expect(res.body.db).toBeUndefined();

    process.env.DATABASE_URL = original;
  });

  it("returns 200 and db:ok when DB is reachable", async () => {
    // Mock pg to simulate a healthy DB
    mockDbClient("ok");

    const { healthRouter: freshRouter } = await import("./health.js");
    const app = express();
    app.use("/api/health", freshRouter);

    const res = await request(app).get("/api/health/ready");
    expect(res.status).toBe(200);
    expect(res.body.status).toBe("ok");
    expect(res.body.db).toBe("ok");
  });

  it("returns 503 and db:down when DB is unreachable", async () => {
    mockDbClient("down");

    const { healthRouter: freshRouter } = await import("./health.js");
    const app = express();
    app.use("/api/health", freshRouter);

    const res = await request(app).get("/api/health/ready");
    expect(res.status).toBe(503);
    expect(res.body.status).toBe("unhealthy");
    expect(res.body.db).toBe("down");
  });

  it("includes service and timestamp fields", async () => {
    const original = process.env.DATABASE_URL;
    delete process.env.DATABASE_URL;

    const res = await request(buildApp()).get("/api/health/ready");
    expect(res.body.service).toBe("veritasor-backend");
    expect(res.body.timestamp).toBeDefined();

    process.env.DATABASE_URL = original;
  });
});

// ---------------------------------------------------------------------------
// GET /api/health — full health check
// ---------------------------------------------------------------------------
describe("GET /api/health", () => {
  beforeEach(() => {
    vi.resetModules();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("returns 200 with status ok when no dependencies are configured", async () => {
    const original = process.env.DATABASE_URL;
    delete process.env.DATABASE_URL;

    const res = await request(buildApp()).get("/api/health");
    expect(res.status).toBe(200);
    expect(res.body.status).toBe("ok");
    expect(res.body.service).toBe("veritasor-backend");
    expect(res.body.mode).toBe("shallow");

    process.env.DATABASE_URL = original;
  });

  it("returns 200 with db:ok when DB is healthy (shallow mode)", async () => {
    mockDbClient("ok");

    const { healthRouter: freshRouter } = await import("./health.js");
    const app = express();
    app.use("/api/health", freshRouter);

    const res = await request(app).get("/api/health");
    expect(res.status).toBe(200);
    expect(res.body.db).toBe("ok");
    expect(res.body.mode).toBe("shallow");
  });

  it("returns 200 with status degraded when DB is down (shallow mode)", async () => {
    mockDbClient("down");

    const { healthRouter: freshRouter } = await import("./health.js");
    const app = express();
    app.use("/api/health", freshRouter);

    const res = await request(app).get("/api/health");
    // Shallow mode: DB down = degraded (200), not 503
    expect(res.status).toBe(200);
    expect(res.body.status).toBe("degraded");
    expect(res.body.db).toBe("down");
  });

  it("returns mode:deep when ?mode=deep is passed", async () => {
    const original = process.env.DATABASE_URL;
    delete process.env.DATABASE_URL;

    const res = await request(buildApp()).get("/api/health?mode=deep");
    expect(res.body.mode).toBe("deep");

    process.env.DATABASE_URL = original;
  });

  it("returns 503 in deep mode when DB is down", async () => {
    mockDbClient("down");

    const { healthRouter: freshRouter } = await import("./health.js");
    const app = express();
    app.use("/api/health", freshRouter);

    const res = await request(app).get("/api/health?mode=deep");
    expect(res.status).toBe(503);
    expect(res.body.status).toBe("unhealthy");
  });

  it("does not include redis field when REDIS_URL is not set", async () => {
    const original = process.env.REDIS_URL;
    delete process.env.REDIS_URL;

    const res = await request(buildApp()).get("/api/health");
    expect(res.body.redis).toBeUndefined();

    if (original !== undefined) process.env.REDIS_URL = original;
  });

  it("does not include soroban/email fields in shallow mode", async () => {
    const original = process.env.DATABASE_URL;
    delete process.env.DATABASE_URL;

    const res = await request(buildApp()).get("/api/health");
    expect(res.body.soroban).toBeUndefined();
    expect(res.body.email).toBeUndefined();

    process.env.DATABASE_URL = original;
  });

  it("returns a valid ISO 8601 timestamp", async () => {
    const original = process.env.DATABASE_URL;
    delete process.env.DATABASE_URL;

    const res = await request(buildApp()).get("/api/health");
    expect(new Date(res.body.timestamp).toISOString()).toBe(res.body.timestamp);

    process.env.DATABASE_URL = original;
  });
});

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------
describe("Health endpoints — edge cases", () => {
  it("GET /api/health/live is not affected by a missing PORT env var", async () => {
    const original = process.env.PORT;
    delete process.env.PORT;

    const res = await request(buildApp()).get("/api/health/live");
    expect(res.status).toBe(200);

    if (original !== undefined) process.env.PORT = original;
  });

  it("GET /api/health/live returns JSON content-type", async () => {
    const res = await request(buildApp()).get("/api/health/live");
    expect(res.headers["content-type"]).toMatch(/application\/json/);
  });

  it("GET /api/health/ready returns JSON content-type", async () => {
    const original = process.env.DATABASE_URL;
    delete process.env.DATABASE_URL;

    const res = await request(buildApp()).get("/api/health/ready");
    expect(res.headers["content-type"]).toMatch(/application\/json/);

    process.env.DATABASE_URL = original;
  });

  it("GET /api/health returns JSON content-type", async () => {
    const original = process.env.DATABASE_URL;
    delete process.env.DATABASE_URL;

    const res = await request(buildApp()).get("/api/health");
    expect(res.headers["content-type"]).toMatch(/application\/json/);

    process.env.DATABASE_URL = original;
  });
});
