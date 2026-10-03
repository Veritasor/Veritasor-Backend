import { beforeEach, describe, expect, it, vi } from "vitest";
import request from "supertest";
import express from "express";

// Mock checkDatabase so the health route never touches a real DB
const mockCheckDatabase = vi.fn();
vi.mock("../../../src/startup/readiness.js", () => ({
  checkDatabase: mockCheckDatabase,
}));

// Import router after mocks
const { healthRouter } = await import("../../../src/routes/health.js");

const app = express();
app.use("/health", healthRouter);

describe("GET /health — database probe via checkDatabase", () => {
  beforeEach(() => {
    mockCheckDatabase.mockReset();
    process.env.DATABASE_URL = "postgres://localhost/test";
  });

  it("returns status ok and dependencies.database=ok when DB is healthy", async () => {
    mockCheckDatabase.mockResolvedValueOnce({ dependency: "database", ready: true });

    const res = await request(app).get("/health");

    expect(res.status).toBe(200);
    expect(res.body.status).toBe("ok");
    expect(res.body.db).toBe("ok");
    expect(res.body.dependencies).toMatchObject({ database: "ok" });
  });

  it("returns status degraded and dependencies.database=down when DB is down", async () => {
    mockCheckDatabase.mockResolvedValueOnce({
      dependency: "database",
      ready: false,
      reason: "database connection failed: ECONNREFUSED",
    });

    const res = await request(app).get("/health");

    expect(res.status).toBe(200);
    expect(res.body.status).toBe("degraded");
    expect(res.body.db).toBe("down");
    expect(res.body.dependencies).toMatchObject({ database: "down" });
  });

  it("omits db and dependencies when DATABASE_URL is not set", async () => {
    delete process.env.DATABASE_URL;

    const res = await request(app).get("/health");

    expect(res.status).toBe(200);
    expect(res.body.db).toBeUndefined();
    expect(res.body.dependencies).toBeUndefined();
    expect(mockCheckDatabase).not.toHaveBeenCalled();
  });

  it("calls checkDatabase exactly once per request", async () => {
    mockCheckDatabase.mockResolvedValueOnce({ dependency: "database", ready: true });

    await request(app).get("/health");

    expect(mockCheckDatabase).toHaveBeenCalledTimes(1);
  });
});
