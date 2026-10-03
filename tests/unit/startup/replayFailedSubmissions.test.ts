import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const {
  mockQueryAuditLogs,
  mockSubmitAttestation,
  mockCanRetry,
  mockRecordRetry,
  mockGaugeSet,
} = vi.hoisted(() => ({
  mockQueryAuditLogs: vi.fn(),
  mockSubmitAttestation: vi.fn(),
  mockCanRetry: vi.fn(),
  mockRecordRetry: vi.fn(),
  mockGaugeSet: vi.fn(),
}));

vi.mock("../../../src/repositories/auditLogRepository.js", () => ({
  queryAuditLogs: mockQueryAuditLogs,
}));

vi.mock("../../../src/services/soroban/submitAttestation.js", () => ({
  submitAttestation: mockSubmitAttestation,
}));

vi.mock("../../../src/services/soroban/retry-budget.js", () => ({
  sorobanRetryBudget: {
    canRetry: () => mockCanRetry(),
    recordRetry: mockRecordRetry,
  },
}));

vi.mock("../../../src/metrics.js", () => ({
  submissionReplayProgress: {
    set: mockGaugeSet,
  },
}));

vi.mock("../../../src/utils/logger.js", () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

vi.mock("../../../src/config/index.js", () => ({
  config: {
    soroban: {
      replayMaxAgeDays: 7,
      retryBudgetMaxRetries: 20,
    },
  },
}));

import { replayFailedSubmissions } from "../../../src/startup/replayFailedSubmissions.js";

function makeLogEntry(overrides: Record<string, unknown> = {}) {
  const isDateTimestamp = overrides.timestamp instanceof Date;
  return {
    id: overrides.id as string ?? "log-1",
    userId: overrides.userId as string ?? "user-1",
    action: "ATTESTATION_SUBMIT_FAILED",
    resource: "attestation",
    resourceId: (overrides.resourceId ?? "biz-1") as string,
    metadata: {
      outcome: "submit_failed",
      errorCode: (overrides.errorCode ?? "SUBMIT_FAILED") as string,
      params: {
        business: (overrides.business ?? "biz-1") as string,
        period: (overrides.period ?? "2025-06") as string,
        merkleRoot: (overrides.merkleRoot ?? "0xabc123") as string,
        timestamp: isDateTimestamp ? 1700000000 : (overrides.timestamp ?? 1700000000) as number,
        version: (overrides.version ?? "1.0.0") as string,
      },
    },
    timestamp: isDateTimestamp
      ? overrides.timestamp as Date
      : new Date(Date.now() - 60_000),
  };
}

describe("replayFailedSubmissions", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockCanRetry.mockReset().mockReturnValue(true);
    mockSubmitAttestation.mockReset().mockResolvedValue({ status: "confirmed", txHash: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789" });
    mockGaugeSet.mockReset().mockReturnValue(undefined);
    mockRecordRetry.mockReset().mockReturnValue(undefined);
    process.env.SOROBAN_SOURCE_PUBLIC_KEY = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    process.env.SOROBAN_SOURCE_SECRET = "SAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  });

  afterEach(() => {
    delete process.env.SOROBAN_SOURCE_PUBLIC_KEY;
    delete process.env.SOROBAN_SOURCE_SECRET;
  });

  it("returns empty summary when no audit logs exist", async () => {
    mockQueryAuditLogs.mockResolvedValue({ data: [], nextCursor: null, hasMore: false });

    const result = await replayFailedSubmissions(7);

    expect(result).toEqual({
      scanned: 0,
      attempted: 0,
      succeeded: 0,
      failed: 0,
      skippedExpired: 0,
      skippedBudget: 0,
    });
    expect(mockQueryAuditLogs).toHaveBeenCalledTimes(1);
    expect(mockSubmitAttestation).not.toHaveBeenCalled();
  });

  it("replays a single failed submission successfully", async () => {
    const entry = makeLogEntry();
    mockQueryAuditLogs.mockResolvedValue({ data: [entry], nextCursor: null, hasMore: false });

    const result = await replayFailedSubmissions(7);

    expect(result.scanned).toBe(1);
    expect(result.attempted).toBe(1);
    expect(result.succeeded).toBe(1);
    expect(result.failed).toBe(0);
    expect(mockSubmitAttestation).toHaveBeenCalledTimes(1);
    expect(mockSubmitAttestation).toHaveBeenCalledWith(
      expect.objectContaining({
        business: "biz-1",
        period: "2025-06",
        merkleRoot: "0xabc123",
        version: "1.0.0",
        sourcePublicKey: "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        signerSecret: "SAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      }),
    );
  });

  it("records replay progress gauge at each phase", async () => {
    const entry = makeLogEntry();
    mockQueryAuditLogs.mockResolvedValue({ data: [entry], nextCursor: null, hasMore: false });

    await replayFailedSubmissions(7);

    expect(mockGaugeSet).toHaveBeenCalledWith({ phase: "scanning" }, 0);
    expect(mockGaugeSet).toHaveBeenCalledWith({ phase: "scanning" }, 0.5);
    expect(mockGaugeSet).toHaveBeenCalledWith({ phase: "replaying" }, 0);
    expect(mockGaugeSet).toHaveBeenCalledWith({ phase: "replaying" }, 1);
    expect(mockGaugeSet).toHaveBeenCalledWith({ phase: "done" }, 1);
  });

  it("skips expired entries older than maxAgeDays", async () => {
    const oldDate = new Date(Date.now() - 10 * 24 * 60 * 60 * 1000);
    const recentDate = new Date();
    const old = makeLogEntry({ id: "old", timestamp: oldDate });
    const recent = makeLogEntry({ id: "recent", timestamp: recentDate, business: "biz-2", merkleRoot: "0xdef456" });
    mockQueryAuditLogs.mockResolvedValue({ data: [old, recent], nextCursor: null, hasMore: false });

    const result = await replayFailedSubmissions(7);

    expect(result.scanned).toBe(2);
    expect(result.skippedExpired).toBe(1);
    expect(result.attempted).toBe(1);
    expect(result.succeeded).toBe(1);
    expect(mockSubmitAttestation).toHaveBeenCalledTimes(1);
    expect(mockSubmitAttestation).toHaveBeenCalledWith(
      expect.objectContaining({ business: "biz-2" }),
    );
  });

  it("deduplicates entries with same business, period, and merkleRoot", async () => {
    const e1 = makeLogEntry({ id: "log-1" });
    const e2 = makeLogEntry({ id: "log-2" });
    mockQueryAuditLogs.mockResolvedValue({ data: [e1, e2], nextCursor: null, hasMore: false });

    const result = await replayFailedSubmissions(7);

    expect(result.scanned).toBe(2);
    expect(result.attempted).toBe(1);
    expect(result.succeeded).toBe(1);
    expect(mockSubmitAttestation).toHaveBeenCalledTimes(1);
  });

  it("handles submission failures", async () => {
    const entry = makeLogEntry();
    mockQueryAuditLogs.mockResolvedValue({ data: [entry], nextCursor: null, hasMore: false });
    mockSubmitAttestation.mockRejectedValue(new Error("RPC timeout"));

    const result = await replayFailedSubmissions(7);

    expect(result.attempted).toBe(1);
    expect(result.failed).toBe(1);
    expect(result.succeeded).toBe(0);
  });

  it("stops replaying when retry budget is exhausted", async () => {
    const entries = [
      makeLogEntry({ id: "a", business: "b1", merkleRoot: "0xa" }),
      makeLogEntry({ id: "b", business: "b2", merkleRoot: "0xb" }),
      makeLogEntry({ id: "c", business: "b3", merkleRoot: "0xc" }),
    ];
    mockQueryAuditLogs.mockResolvedValue({ data: entries, nextCursor: null, hasMore: false });

    mockCanRetry.mockReturnValueOnce(true).mockReturnValueOnce(false);

    const result = await replayFailedSubmissions(7);

    expect(result.attempted).toBe(1);
    expect(result.succeeded).toBe(1);
    expect(result.skippedBudget).toBe(2);
    expect(mockSubmitAttestation).toHaveBeenCalledTimes(1);
  });

  it("skips all remaining entries when SOROBAN_SOURCE_PUBLIC_KEY is missing", async () => {
    delete process.env.SOROBAN_SOURCE_PUBLIC_KEY;
    process.env.SOROBAN_SOURCE_SECRET = "";
    const entry = makeLogEntry();
    mockQueryAuditLogs.mockResolvedValue({ data: [entry], nextCursor: null, hasMore: false });

    const result = await replayFailedSubmissions(7);

    expect(result.attempted).toBe(0);
    expect(result.skippedBudget).toBe(1);
    expect(mockSubmitAttestation).not.toHaveBeenCalled();
  });

  it("skips entries with invalid or missing metadata params", async () => {
    const valid = makeLogEntry({ id: "valid" });
    const missingParams = { ...makeLogEntry({ id: "no-params" }), metadata: { outcome: "submit_failed" } };
    const missingBusiness = makeLogEntry({ id: "no-biz", business: undefined });
    const invalidTimestamp = makeLogEntry({ id: "bad-ts", timestamp: -1 });
    mockQueryAuditLogs.mockResolvedValue({
      data: [valid, missingParams, missingBusiness, invalidTimestamp],
      nextCursor: null,
      hasMore: false,
    });

    const result = await replayFailedSubmissions(7);

    expect(result.scanned).toBe(4);
    expect(result.attempted).toBe(1);
    expect(result.succeeded).toBe(1);
  });

  it("paginates through multiple pages of audit log entries", async () => {
    const page1 = makeLogEntry({ id: "page1-1", business: "b1", merkleRoot: "0x1" });
    const page2 = makeLogEntry({ id: "page2-1", business: "b2", merkleRoot: "0x2" });
    const page3 = makeLogEntry({ id: "page3-1", business: "b3", merkleRoot: "0x3" });

    mockQueryAuditLogs
      .mockResolvedValueOnce({ data: [page1], nextCursor: "cursor-page2", hasMore: true })
      .mockResolvedValueOnce({ data: [page2], nextCursor: "cursor-page3", hasMore: true })
      .mockResolvedValueOnce({ data: [page3], nextCursor: null, hasMore: false });

    const result = await replayFailedSubmissions(7);

    expect(result.scanned).toBe(3);
    expect(result.attempted).toBe(3);
    expect(result.succeeded).toBe(3);
    expect(mockQueryAuditLogs).toHaveBeenCalledTimes(3);
    expect(mockQueryAuditLogs).toHaveBeenNthCalledWith(2, expect.objectContaining({
      action: "ATTESTATION_SUBMIT_FAILED",
      cursor: "cursor-page2",
    }));
  });

  it("respects custom maxAgeDays parameter", async () => {
    const fourDaysOld = new Date(Date.now() - 4 * 24 * 60 * 60 * 1000);
    const eightDaysOld = new Date(Date.now() - 8 * 24 * 60 * 60 * 1000);
    const recent = makeLogEntry({ id: "r", timestamp: fourDaysOld, business: "b-recent", merkleRoot: "0xr" });
    const ancient = makeLogEntry({ id: "a", timestamp: eightDaysOld, business: "b-ancient", merkleRoot: "0xa" });
    mockQueryAuditLogs.mockResolvedValue({ data: [recent, ancient], nextCursor: null, hasMore: false });

    const result = await replayFailedSubmissions(5);

    expect(result.scanned).toBe(2);
    expect(result.skippedExpired).toBe(1);
    expect(result.attempted).toBe(1);
    expect(mockSubmitAttestation).toHaveBeenCalledWith(
      expect.objectContaining({ business: "b-recent" }),
    );
  });

  it("handles entries with bigint timestamp metadata", async () => {
    const entry = makeLogEntry();
    entry.metadata.params.timestamp = BigInt(1700000000) as unknown as number;
    mockQueryAuditLogs.mockResolvedValue({ data: [entry], nextCursor: null, hasMore: false });

    const result = await replayFailedSubmissions(7);

    expect(result.attempted).toBe(1);
    expect(result.succeeded).toBe(1);
    expect(mockSubmitAttestation).toHaveBeenCalledWith(
      expect.objectContaining({ timestamp: BigInt(1700000000) }),
    );
  });

  it("handles mixed results: some succeed, some fail, some skipped", async () => {
    const fresh = new Date();
    const ancient = new Date(Date.now() - 10 * 24 * 60 * 60 * 1000);
    const entries = [
      makeLogEntry({ id: "1", business: "b1", merkleRoot: "0xa", timestamp: fresh }),
      makeLogEntry({ id: "2", business: "b2", merkleRoot: "0xb", timestamp: fresh }),
      makeLogEntry({ id: "3", business: "b3", merkleRoot: "0xc", timestamp: ancient }),
      makeLogEntry({ id: "4", business: "b4", merkleRoot: "0xd", timestamp: fresh }),
    ];
    mockQueryAuditLogs.mockResolvedValue({ data: entries, nextCursor: null, hasMore: false });

    mockSubmitAttestation
      .mockResolvedValueOnce({ status: "confirmed" })
      .mockRejectedValueOnce(new Error("timeout"))
      .mockResolvedValueOnce({ status: "confirmed" });

    const result = await replayFailedSubmissions(7);

    expect(result.scanned).toBe(4);
    expect(result.skippedExpired).toBe(1);
    expect(result.attempted).toBe(3);
    expect(result.succeeded).toBe(2);
    expect(result.failed).toBe(1);
  });

  it("handles metadata being null", async () => {
    const entry = { ...makeLogEntry({ id: "nullMeta" }), metadata: null };
    mockQueryAuditLogs.mockResolvedValue({ data: [entry], nextCursor: null, hasMore: false });

    const result = await replayFailedSubmissions(7);

    expect(result.scanned).toBe(1);
    expect(result.attempted).toBe(0);
  });

  it("handles metadata being a non-object", async () => {
    const entry = { ...makeLogEntry({ id: "strMeta" }), metadata: "invalid" };
    mockQueryAuditLogs.mockResolvedValue({ data: [entry], nextCursor: null, hasMore: false });

    const result = await replayFailedSubmissions(7);

    expect(result.scanned).toBe(1);
    expect(result.attempted).toBe(0);
  });

  it("records retry budget after each submission", async () => {
    const entries = [
      makeLogEntry({ id: "a", business: "b1", merkleRoot: "0xa" }),
      makeLogEntry({ id: "b", business: "b2", merkleRoot: "0xb" }),
    ];
    mockQueryAuditLogs.mockResolvedValue({ data: entries, nextCursor: null, hasMore: false });
    mockCanRetry.mockReturnValue(true);

    await replayFailedSubmissions(7);

    expect(mockRecordRetry).toHaveBeenCalledWith("replay");
    expect(mockRecordRetry).toHaveBeenCalledTimes(2);
  });

  it("uses default maxAgeDays from config.soroban when not specified", async () => {
    mockQueryAuditLogs.mockResolvedValue({ data: [], nextCursor: null, hasMore: false });

    const result = await replayFailedSubmissions();

    expect(result.scanned).toBe(0);
  });

  it("returns summary with aggregated counts when all entries are expired", async () => {
    const ancient = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    const entries = [
      makeLogEntry({ id: "1", timestamp: ancient }),
      makeLogEntry({ id: "2", timestamp: ancient }),
      makeLogEntry({ id: "3", timestamp: ancient }),
    ];
    mockQueryAuditLogs.mockResolvedValue({ data: entries, nextCursor: null, hasMore: false });

    const result = await replayFailedSubmissions(7);

    expect(result.scanned).toBe(3);
    expect(result.skippedExpired).toBe(3);
    expect(result.attempted).toBe(0);
    expect(mockSubmitAttestation).not.toHaveBeenCalled();
  });
});
