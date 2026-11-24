import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import request from "supertest";
import express from "express";

// Mock checkDatabase so the health route never touches a real DB
const mockCheckDatabase = vi.fn();
vi.mock("../../../src/startup/readiness.js", () => ({
  checkDatabase: mockCheckDatabase,
}));

const mockPing = vi.fn();
const mockGetRedisClient = vi.fn(() => ({ ping: mockPing }));
vi.mock("../../../src/redis.js", () => ({
  getRedisClient: mockGetRedisClient,
}));

const mockSorobanGetHealth = vi.fn();
vi.mock("@stellar/stellar-sdk", () => ({
  rpc: {
    Server: class MockSorobanServer {
      constructor(public url: string, public opts: unknown) {}
      getHealth() {
        return mockSorobanGetHealth();
      }
    },
  },
}));

// Import router after mocks
const { healthRouter, HealthResponseSchema } = await import("../../../src/routes/health.js");

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

describe("GET /health — Redis and Soroban checks via project clients", () => {
  const originalRedisUrl = process.env.REDIS_URL;
  const originalClusterNodes = process.env.REDIS_CLUSTER_NODES;
  const originalSorobanUrl = process.env.SOROBAN_RPC_URL;

  beforeEach(() => {
    mockCheckDatabase.mockReset();
    mockPing.mockReset();
    mockGetRedisClient.mockClear();
    mockSorobanGetHealth.mockReset();
    delete process.env.DATABASE_URL;
    delete process.env.REDIS_URL;
    delete process.env.REDIS_CLUSTER_NODES;
    delete process.env.SOROBAN_RPC_URL;
  });

  afterEach(() => {
    vi.useRealTimers();
    if (originalRedisUrl === undefined) delete process.env.REDIS_URL;
    else process.env.REDIS_URL = originalRedisUrl;
    if (originalClusterNodes === undefined) delete process.env.REDIS_CLUSTER_NODES;
    else process.env.REDIS_CLUSTER_NODES = originalClusterNodes;
    if (originalSorobanUrl === undefined) delete process.env.SOROBAN_RPC_URL;
    else process.env.SOROBAN_RPC_URL = originalSorobanUrl;
  });

  it("returns redis=ok when getRedisClient().ping() succeeds", async () => {
    process.env.REDIS_URL = "redis://localhost:6379";
    mockPing.mockResolvedValueOnce("PONG");

    const res = await request(app).get("/health");

    expect(res.status).toBe(200);
    expect(res.body.redis).toBe("ok");
    expect(mockGetRedisClient).toHaveBeenCalledTimes(1);
    expect(mockPing).toHaveBeenCalledTimes(1);
    expect(HealthResponseSchema.safeParse(res.body).success).toBe(true);
  });

  it("returns redis=down when getRedisClient().ping() rejects", async () => {
    process.env.REDIS_URL = "redis://localhost:6379";
    mockPing.mockRejectedValueOnce(new Error("ECONNREFUSED"));

    const res = await request(app).get("/health");

    expect(res.status).toBe(200);
    expect(res.body.redis).toBe("down");
    expect(HealthResponseSchema.safeParse(res.body).success).toBe(true);
  });

  it("returns redis=down when getRedisClient().ping() times out", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    process.env.REDIS_URL = "redis://localhost:6379";
    mockPing.mockImplementationOnce(() => {
      setImmediate(() => {
        vi.advanceTimersByTime(2001);
      });
      return new Promise(() => {});
    });

    const res = await request(app).get("/health");

    expect(res.status).toBe(200);
    expect(res.body.redis).toBe("down");
    expect(HealthResponseSchema.safeParse(res.body).success).toBe(true);
  });

  it("returns soroban=ok in deep mode when @stellar/stellar-sdk rpc.Server.getHealth succeeds", async () => {
    process.env.SOROBAN_RPC_URL = "https://soroban-testnet.stellar.org";
    mockSorobanGetHealth.mockResolvedValueOnce({ status: "healthy" });

    const res = await request(app).get("/health?mode=deep");

    expect(res.status).toBe(200);
    expect(res.body.soroban).toBe("ok");
    expect(HealthResponseSchema.safeParse(res.body).success).toBe(true);
  });

  it("returns soroban=down and 503 in deep mode when rpc.Server.getHealth fails", async () => {
    process.env.SOROBAN_RPC_URL = "https://soroban-testnet.stellar.org";
    mockSorobanGetHealth.mockRejectedValueOnce(new Error("RPC unavailable"));

    const res = await request(app).get("/health?mode=deep");

    expect(res.status).toBe(503);
    expect(res.body.soroban).toBe("down");
    expect(res.body.status).toBe("unhealthy");
    expect(HealthResponseSchema.safeParse(res.body).success).toBe(true);
  });
});
