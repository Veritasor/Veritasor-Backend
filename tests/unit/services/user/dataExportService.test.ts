/**
 * Tests for src/services/user/dataExportService.ts
 *
 * Coverage targets:
 *  - ExportResponse: public response contract (required fields, ISO date strings)
 *  - initiateDataExport: job creation, response shape, failure propagation
 *  - getExportStatus: null for unknown id, download token for completed exports,
 *    Date-vs-string date normalisation, failure propagation
 *  - getExportArchive: base64 decode, missing / malformed archive handling
 *  - State transitions (via the async processing pipeline):
 *    pending -> processing -> completed, and pending -> processing -> failed
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// ---------------------------------------------------------------------------
// Mocks — must come before subject imports
// ---------------------------------------------------------------------------

vi.mock("../../../../src/utils/logger.js", () => ({
  logger: {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

vi.mock("../../../../src/repositories/dataExportRepository.js", () => ({
  createDataExport: vi.fn(),
  updateDataExportStatus: vi.fn(),
  createDownloadToken: vi.fn(),
  getDataExport: vi.fn(),
  consumeDownloadToken: vi.fn(),
  getUserDataExports: vi.fn(),
  deleteDataExport: vi.fn(),
}));

vi.mock("../../../../src/services/user/createGdprExport.js", () => ({
  createGdprExport: vi.fn(),
}));

const mockRedisClient = {
  get: vi.fn(),
  set: vi.fn(),
  setex: vi.fn(),
  del: vi.fn(),
};

vi.mock("../../../../src/redis.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../../../src/redis.js")>();
  return {
    ...actual,
    getRedisClient: vi.fn(() => mockRedisClient),
    // Pass the operation straight through so Redis interactions are observable
    redisCircuitBreaker: {
      ...actual.redisCircuitBreaker,
      execute: vi.fn(<T>(operation: () => Promise<T>) => operation()),
    },
  };
});

import { logger } from "../../../../src/utils/logger.js";
import {
  createDataExport,
  updateDataExportStatus,
  createDownloadToken,
  getDataExport,
} from "../../../../src/repositories/dataExportRepository.js";
import { createGdprExport } from "../../../../src/services/user/createGdprExport.js";
import {
  initiateDataExport,
  getExportStatus,
  getExportArchive,
  type ExportResponse,
} from "../../../../src/services/user/dataExportService.js";
import type { DataExport } from "../../../../src/repositories/dataExportRepository.js";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const FIXED_NOW = new Date("2026-07-28T12:00:00.000Z");
const FIXED_EXPIRY = new Date("2026-08-04T12:00:00.000Z"); // + 7 days

function makeExportJob(overrides: Partial<DataExport> = {}): DataExport {
  return {
    id: "abc123def456",
    userId: "user-abc",
    status: "pending",
    createdAt: FIXED_NOW,
    expiresAt: FIXED_EXPIRY,
    ...overrides,
  };
}

function makeExportResult() {
  return {
    encryptedData: Buffer.from("encrypted-payload-bytes", "utf8"),
    iv: Buffer.alloc(12, 7),
    salt: Buffer.alloc(16, 3),
    signature: "f".repeat(64),
    metadata: {
      algorithm: "aes-256-gcm",
      keyDerivation: "pbkdf2-sha256",
      compressionFormat: "gzip",
    },
  };
}

/**
 * Resolves once the async export pipeline has performed both status updates
 * (processing -> terminal state). Keeps background job assertions
 * deterministic without arbitrary sleeps.
 */
async function waitForProcessingSteps(): Promise<void> {
  await vi.waitFor(
    () => {
      expect(updateDataExportStatus).toHaveBeenCalledTimes(2);
    },
    { timeout: 2000, interval: 10 }
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  mockRedisClient.get.mockResolvedValue(null);
  mockRedisClient.set.mockResolvedValue("OK");
  mockRedisClient.setex.mockResolvedValue("OK");
  mockRedisClient.del.mockResolvedValue(1);
  createDataExport.mockResolvedValue(makeExportJob());
  getDataExport.mockResolvedValue(null);
  updateDataExportStatus.mockImplementation(
    async (_id: string, status: DataExport["status"], updates?: Partial<DataExport>) =>
      makeExportJob({ status, ...updates })
  );
  createDownloadToken.mockResolvedValue("download-token-1");
  createGdprExport.mockResolvedValue(makeExportResult());
});

afterEach(() => {
  // Surface unexpected unhandled rejections from the fire-and-forget pipeline
  vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// ExportResponse contract
// ---------------------------------------------------------------------------

describe("ExportResponse contract", () => {
  it("initiateDataExport returns every required ExportResponse field", async () => {
    const response = await initiateDataExport("user-abc");

    expect(response).toHaveProperty("exportId");
    expect(response).toHaveProperty("status");
    expect(response).toHaveProperty("expiresAt");
    expect(response).toHaveProperty("createdAt");
    // downloadToken is absent for a fresh (pending) export
    expect(response.downloadToken).toBeUndefined();
  });

  it("initiateDataExport serialises dates as ISO strings", async () => {
    const response = await initiateDataExport("user-abc");

    expect(response.createdAt).toBe("2026-07-28T12:00:00.000Z");
    expect(response.expiresAt).toBe("2026-08-04T12:00:00.000Z");
    expect(() => new Date(response.createdAt).toISOString()).not.toThrow();
    expect(() => new Date(response.expiresAt).toISOString()).not.toThrow();
  });

  it("initiateDataExport echoes the repository job id and status", async () => {
    createDataExport.mockResolvedValue(
      makeExportJob({ id: "job-xyz", status: "pending" })
    );

    const response = await initiateDataExport("user-abc");

    expect(response.exportId).toBe("job-xyz");
    expect(response.status).toBe("pending");
  });

  it("initiateDataExport passes the userId through to the repository verbatim", async () => {
    await initiateDataExport("user-abc");

    expect(createDataExport).toHaveBeenCalledExactlyOnceWith("user-abc");
  });

  it("getExportStatus responses satisfy the ExportResponse shape", async () => {
    getDataExport.mockResolvedValue(
      makeExportJob({ status: "completed" })
    );

    const response: ExportResponse | null = await getExportStatus("abc123def456");

    expect(response).toMatchObject({
      exportId: "abc123def456",
      status: "completed",
      expiresAt: "2026-08-04T12:00:00.000Z",
      createdAt: "2026-07-28T12:00:00.000Z",
      downloadToken: expect.any(String),
    });
  });
});

// ---------------------------------------------------------------------------
// initiateDataExport — success and failure paths
// ---------------------------------------------------------------------------

describe("initiateDataExport", () => {
  it("creates the export job and returns a pending ExportResponse", async () => {
    const response = await initiateDataExport("user-abc");

    expect(createDataExport).toHaveBeenCalledExactlyOnceWith("user-abc");
    expect(response.status).toBe("pending");
    expect(response.exportId).toBe("abc123def456");
  });

  it("queues the export for async processing (pipeline started)", async () => {
    await initiateDataExport("user-abc");

    await vi.waitFor(
      () => {
        expect(updateDataExportStatus).toHaveBeenCalled();
      },
      { timeout: 2000, interval: 10 }
    );
  });

  it("re-throws when the repository fails to create the job", async () => {
    const boom = new Error("redis unavailable");
    createDataExport.mockRejectedValue(boom);

    await expect(initiateDataExport("user-abc")).rejects.toThrow(boom);

    // No pipeline was started for a failed initiation
    expect(updateDataExportStatus).not.toHaveBeenCalled();
    expect(createGdprExport).not.toHaveBeenCalled();
  });

  it("logs the initiation failure with the userId", async () => {
    createDataExport.mockRejectedValue(new Error("redis unavailable"));

    await expect(initiateDataExport("user-abc")).rejects.toThrow();

    expect(logger.error).toHaveBeenCalledWith(
      "Failed to initiate data export",
      expect.objectContaining({ userId: "user-abc" })
    );
  });
});

// ---------------------------------------------------------------------------
// getExportStatus
// ---------------------------------------------------------------------------

describe("getExportStatus", () => {
  it("returns null when the export does not exist", async () => {
    getDataExport.mockResolvedValue(null);

    const response = await getExportStatus("does-not-exist");

    expect(response).toBeNull();
  });

  it("returns no downloadToken for a pending export", async () => {
    getDataExport.mockResolvedValue(makeExportJob({ status: "pending" }));

    const response = await getExportStatus("abc123def456");

    expect(response?.status).toBe("pending");
    expect(response?.downloadToken).toBeUndefined();
    expect(createDownloadToken).not.toHaveBeenCalled();
  });

  it("returns no downloadToken for a processing export", async () => {
    getDataExport.mockResolvedValue(makeExportJob({ status: "processing" }));

    const response = await getExportStatus("abc123def456");

    expect(response?.status).toBe("processing");
    expect(response?.downloadToken).toBeUndefined();
    expect(createDownloadToken).not.toHaveBeenCalled();
  });

  it("returns no downloadToken for a failed export", async () => {
    getDataExport.mockResolvedValue(
      makeExportJob({ status: "failed", error: "boom" })
    );

    const response = await getExportStatus("abc123def456");

    expect(response?.status).toBe("failed");
    expect(response?.downloadToken).toBeUndefined();
    expect(createDownloadToken).not.toHaveBeenCalled();
  });

  it("issues a download token for a completed export", async () => {
    getDataExport.mockResolvedValue(makeExportJob({ status: "completed" }));
    createDownloadToken.mockResolvedValue("one-time-token-42");

    const response = await getExportStatus("abc123def456");

    expect(createDownloadToken).toHaveBeenCalledExactlyOnceWith("abc123def456");
    expect(response?.downloadToken).toBe("one-time-token-42");
  });

  it("normalises Date objects from the repository into ISO strings", async () => {
    getDataExport.mockResolvedValue(
      makeExportJob({
        createdAt: new Date("2026-07-01T00:00:00.000Z"),
        expiresAt: new Date("2026-07-08T00:00:00.000Z"),
      })
    );

    const response = await getExportStatus("abc123def456");

    expect(response?.createdAt).toBe("2026-07-01T00:00:00.000Z");
    expect(response?.expiresAt).toBe("2026-07-08T00:00:00.000Z");
    expect(typeof response?.createdAt).toBe("string");
    expect(typeof response?.expiresAt).toBe("string");
  });

  it("passes pre-serialised string dates through unchanged (Redis round-trip)", async () => {
    // getDataExport JSON.parses Redis payloads, so dates arrive as strings
    getDataExport.mockResolvedValue({
      ...makeExportJob(),
      createdAt: "2026-07-28T12:00:00.000Z",
      expiresAt: "2026-08-04T12:00:00.000Z",
    } as unknown as DataExport);

    const response = await getExportStatus("abc123def456");

    expect(response?.createdAt).toBe("2026-07-28T12:00:00.000Z");
    expect(response?.expiresAt).toBe("2026-08-04T12:00:00.000Z");
  });

  it("re-throws when the repository lookup fails", async () => {
    const boom = new Error("lookup failed");
    getDataExport.mockRejectedValue(boom);

    await expect(getExportStatus("abc123def456")).rejects.toThrow(boom);
    expect(logger.error).toHaveBeenCalledWith(
      "Failed to get export status",
      expect.objectContaining({ exportId: "abc123def456" })
    );
  });

  it("propagates a download-token failure for a completed export", async () => {
    getDataExport.mockResolvedValue(makeExportJob({ status: "completed" }));
    createDownloadToken.mockRejectedValue(new Error("token store down"));

    await expect(getExportStatus("abc123def456")).rejects.toThrow(
      "token store down"
    );
  });
});

// ---------------------------------------------------------------------------
// getExportArchive
// ---------------------------------------------------------------------------

describe("getExportArchive", () => {
  it("returns null when no archive is stored", async () => {
    const archive = await getExportArchive("abc123def456");

    expect(archive).toBeNull();
  });

  it("reads the archive under the expected Redis key", async () => {
    mockRedisClient.get.mockResolvedValue(
      JSON.stringify({ buffer: Buffer.from("hello").toString("base64") })
    );

    await getExportArchive("abc123def456");

    expect(mockRedisClient.get).toHaveBeenCalledWith(
      "data-export-archive:abc123def456"
    );
  });

  it("decodes the stored base64 payload into the original buffer", async () => {
    const payload = Buffer.from("binary-archive-content", "utf8");
    mockRedisClient.get.mockResolvedValue(
      JSON.stringify({ buffer: payload.toString("base64") })
    );

    const archive = await getExportArchive("abc123def456");

    expect(archive).toBeInstanceOf(Buffer);
    expect(archive?.toString("utf8")).toBe("binary-archive-content");
  });

  it("returns null (not throw) for a malformed stored archive", async () => {
    mockRedisClient.get.mockResolvedValue("not-json{{");

    const archive = await getExportArchive("abc123def456");

    expect(archive).toBeNull();
    expect(logger.error).toHaveBeenCalledWith(
      "Failed to get export archive",
      expect.objectContaining({ exportId: "abc123def456" })
    );
  });
});

// ---------------------------------------------------------------------------
// State transitions — pending -> processing -> completed / failed
// (exercised through initiateDataExport's fire-and-forget pipeline)
// ---------------------------------------------------------------------------

describe("export state transitions", () => {
  it("transitions pending -> processing -> completed on success", async () => {
    const response = await initiateDataExport("user-abc");
    await waitForProcessingSteps();

    expect(createGdprExport).toHaveBeenCalledExactlyOnceWith("user-abc");
    expect(updateDataExportStatus).toHaveBeenNthCalledWith(
      1,
      response.exportId,
      "processing"
    );
    expect(updateDataExportStatus).toHaveBeenNthCalledWith(
      2,
      response.exportId,
      "completed",
      { archiveSize: expect.any(Number) }
    );
  });

  it("stores the encrypted archive in Redis with a 7-day TTL", async () => {
    const response = await initiateDataExport("user-abc");
    await waitForProcessingSteps();

    const result = makeExportResult();
    expect(mockRedisClient.setex).toHaveBeenCalledWith(
      `data-export-archive:${response.exportId}`,
      7 * 24 * 60 * 60,
      expect.any(String)
    );

    const [, , storedJson] = mockRedisClient.setex.mock.lastCall as [
      string,
      number,
      string
    ];
    const stored = JSON.parse(storedJson);
    expect(stored.buffer).toBe(result.encryptedData.toString("base64"));
    expect(stored.iv).toBe(result.iv.toString("hex"));
    expect(stored.salt).toBe(result.salt.toString("hex"));
    expect(stored.signature).toBe(result.signature);
    expect(stored.metadata).toEqual(result.metadata);
  });

  it("reports the archive size from the encrypted payload", async () => {
    const result = makeExportResult();
    createGdprExport.mockResolvedValue(result);

    await initiateDataExport("user-abc");
    await waitForProcessingSteps();

    expect(updateDataExportStatus).toHaveBeenCalledWith(
      expect.any(String),
      "completed",
      { archiveSize: result.encryptedData.length }
    );
  });

  it("transitions pending -> processing -> failed when export creation throws", async () => {
    createGdprExport.mockRejectedValue(new Error("encryption blew up"));

    const response = await initiateDataExport("user-abc");
    await waitForProcessingSteps();

    expect(updateDataExportStatus).toHaveBeenNthCalledWith(
      1,
      response.exportId,
      "processing"
    );
    expect(updateDataExportStatus).toHaveBeenNthCalledWith(
      2,
      response.exportId,
      "failed",
      { error: "encryption blew up" }
    );
    // A failed export never stores an archive
    expect(mockRedisClient.setex).not.toHaveBeenCalled();
  });

  it("stringifies non-Error failure causes for the failed status", async () => {
    createGdprExport.mockRejectedValue("plain-string-failure");

    await initiateDataExport("user-abc");
    await waitForProcessingSteps();

    expect(updateDataExportStatus).toHaveBeenCalledWith(
      expect.any(String),
      "failed",
      { error: "plain-string-failure" }
    );
  });

  it("logs the completion with userId, exportId and archive size", async () => {
    const result = makeExportResult();
    createGdprExport.mockResolvedValue(result);

    const response = await initiateDataExport("user-abc");
    await waitForProcessingSteps();

    expect(logger.info).toHaveBeenCalledWith("Export processing completed", {
      userId: "user-abc",
      exportId: response.exportId,
      archiveSize: result.encryptedData.length,
    });
  });

  it("survives (and logs) a status-update failure after a failed export", async () => {
    createGdprExport.mockRejectedValue(new Error("encryption blew up"));
    // The 'failed' status update itself errors (e.g. Redis outage)
    updateDataExportStatus
      .mockResolvedValueOnce(makeExportJob({ status: "processing" }))
      .mockRejectedValueOnce(new Error("status update failed"));

    await initiateDataExport("user-abc");

    await vi.waitFor(
      () => {
        expect(logger.error).toHaveBeenCalledWith(
          "Failed to process export",
          expect.objectContaining({ userId: "user-abc" })
        );
      },
      { timeout: 2000, interval: 10 }
    );
  });
});

// ---------------------------------------------------------------------------
// Invalid / boundary inputs
// ---------------------------------------------------------------------------

describe("invalid and boundary inputs", () => {
  it("forwards an empty userId to the repository (contract: no service-side validation)", async () => {
    createDataExport.mockRejectedValue(new Error("invalid user"));

    await expect(initiateDataExport("")).rejects.toThrow("invalid user");
    expect(createDataExport).toHaveBeenCalledExactlyOnceWith("");
  });

  it("returns null for an empty exportId", async () => {
    getDataExport.mockResolvedValue(null);

    const response = await getExportStatus("");

    expect(getDataExport).toHaveBeenCalledExactlyOnceWith("");
    expect(response).toBeNull();
  });

  it("returns null for an empty archive id", async () => {
    const archive = await getExportArchive("");

    expect(archive).toBeNull();
    expect(mockRedisClient.get).toHaveBeenCalledWith("data-export-archive:");
  });
});
