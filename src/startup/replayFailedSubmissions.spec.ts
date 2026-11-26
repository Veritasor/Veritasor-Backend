import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  queryAuditLogs: vi.fn(),
  submitAttestation: vi.fn(),
  canRetry: vi.fn(),
  recordRetry: vi.fn(),
}));

vi.mock("../repositories/auditLogRepository.js", () => ({
  queryAuditLogs: mocks.queryAuditLogs,
}));
vi.mock("../services/soroban/submitAttestation.js", () => ({
  submitAttestation: mocks.submitAttestation,
}));
vi.mock("../services/soroban/retry-budget.js", () => ({
  sorobanRetryBudget: {
    canRetry: mocks.canRetry,
    recordRetry: mocks.recordRetry,
  },
}));
vi.mock("../metrics.js", () => ({
  submissionReplayProgress: { set: vi.fn() },
}));
vi.mock("../config/index.js", () => ({
  config: { soroban: { replayMaxAgeDays: 7, replayLockTtlMs: 60000 } },
}));
vi.mock("../utils/logger.js", () => ({
  logger: { info: vi.fn(), warn: vi.fn() },
}));

import { replayFailedSubmissions } from "./replayFailedSubmissions.js";

const validParams = {
  business: "business-1",
  period: "2026-09",
  merkleRoot: "root-1",
  timestamp: 0,
  version: "1",
};

function auditEntry(metadata: unknown, timestamp = new Date()) {
  return { metadata, timestamp };
}

describe("replayFailedSubmissions", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.queryAuditLogs.mockResolvedValue({
      data: [],
      nextCursor: null,
      hasMore: false,
    });
    mocks.canRetry.mockReturnValue(true);
    vi.stubEnv("SOROBAN_SOURCE_PUBLIC_KEY", "source-public-key");
    vi.stubEnv("SOROBAN_SOURCE_SECRET", "source-secret");
    // Clear Redis env to test without lock by default
    delete process.env.REDIS_URL;
    delete process.env.REDIS_CLUSTER_NODES;
    delete process.env.REDIS_MODE;
  });

  it("skips empty, non-object, and invalid replay parameters deterministically", async () => {
    const malformedMetadata = [
      null,
      {},
      { params: null },
      { params: "not-an-object" },
      { params: [] },
      { params: { ...validParams, timestamp: -1 } },
      { params: { ...validParams, timestamp: Number.NaN } },
      { params: { ...validParams, timestamp: Number.POSITIVE_INFINITY } },
    ];
    mocks.queryAuditLogs.mockResolvedValueOnce({
      data: malformedMetadata.map((metadata) => auditEntry(metadata)),
      nextCursor: null,
      hasMore: false,
    });

    await expect(replayFailedSubmissions()).resolves.toEqual({
      scanned: malformedMetadata.length,
      attempted: 0,
      succeeded: 0,
      failed: 0,
      skippedExpired: 0,
      skippedBudget: 0,
    });
    expect(mocks.submitAttestation).not.toHaveBeenCalled();
  });

  it("replays valid parameters with the zero timestamp boundary", async () => {
    mocks.queryAuditLogs.mockResolvedValueOnce({
      data: [auditEntry({ params: validParams })],
      nextCursor: null,
      hasMore: false,
    });

    await expect(replayFailedSubmissions()).resolves.toEqual({
      scanned: 1,
      attempted: 1,
      succeeded: 1,
      failed: 0,
      skippedExpired: 0,
      skippedBudget: 0,
    });
    expect(mocks.submitAttestation).toHaveBeenCalledWith({
      business: "business-1",
      period: "2026-09",
      merkleRoot: "root-1",
      timestamp: 0,
      version: "1",
      sourcePublicKey: "source-public-key",
      signerSecret: "source-secret",
    });
  });

  it("returns a failed summary when an attestation submission rejects", async () => {
    mocks.queryAuditLogs.mockResolvedValueOnce({
      data: [auditEntry({ params: validParams })],
      nextCursor: null,
      hasMore: false,
    });
    mocks.submitAttestation.mockRejectedValueOnce(new Error("submission failed"));

    await expect(replayFailedSubmissions()).resolves.toEqual({
      scanned: 1,
      attempted: 1,
      succeeded: 0,
      failed: 1,
      skippedExpired: 0,
      skippedBudget: 0,
    });
    expect(mocks.recordRetry).toHaveBeenCalledWith("replay");
  });

  describe("Distributed lock behavior", () => {
    it("runs without lock when Redis is not configured", async () => {
      mocks.queryAuditLogs.mockResolvedValueOnce({
        data: [auditEntry({ params: validParams })],
        nextCursor: null,
        hasMore: false,
      });

      const result = await replayFailedSubmissions();

      expect(result.attempted).toBe(1);
      expect(result.succeeded).toBe(1);
    });

    it("skips replay when lock is held by another instance", async () => {
      // Mock Redis as configured
      process.env.REDIS_URL = "redis://localhost:6379";

      // Mock distributed lock to simulate lock held by another instance
      vi.doMock("../utils/distributedLock.js", () => ({
        withLock: vi.fn().mockResolvedValue(undefined),
      }));

      const { replayFailedSubmissions: replayWithMockedLock } = await import("./replayFailedSubmissions.js");

      const result = await replayWithMockedLock();

      expect(result).toEqual({
        scanned: 0,
        attempted: 0,
        succeeded: 0,
        failed: 0,
        skippedExpired: 0,
        skippedBudget: 0,
      });

      delete process.env.REDIS_URL;
    });

    it("replays when lock is acquired", async () => {
      // Mock Redis as configured
      process.env.REDIS_URL = "redis://localhost:6379";

      const mockSummary = {
        scanned: 1,
        attempted: 1,
        succeeded: 1,
        failed: 0,
        skippedExpired: 0,
        skippedBudget: 0,
      };

      // Mock distributed lock to simulate successful acquisition
      vi.doMock("../utils/distributedLock.js", () => ({
        withLock: vi.fn().mockResolvedValue(mockSummary),
      }));

      const { replayFailedSubmissions: replayWithMockedLock } = await import("./replayFailedSubmissions.js");

      const result = await replayWithMockedLock();

      expect(result).toEqual(mockSummary);

      delete process.env.REDIS_URL;
    });
  });
});