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
  config: { soroban: { replayMaxAgeDays: 7 } },
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
});