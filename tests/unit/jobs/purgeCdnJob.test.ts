/**
 * Focused behaviour coverage for `enqueueCdnPurge` (src/jobs/purgeCdnJob.ts).
 *
 * The job is a thin wrapper around the CDN adapter + audit logger, so the
 * contract under test is precisely what happens on each side of the
 * success/failure fork:
 *
 *  - the URL that reaches the CDN adapter is forwarded verbatim, exactly once;
 *  - a successful purge records `success` with the purged URL;
 *  - a failed purge records `failed` with the normalised error string and is
 *    swallowed (the caller must never see a rejected promise);
 *  - the error normaliser handles both `Error` and non-`Error` rejections.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";

// Mocks must be declared before the module under test is imported.
vi.mock("../../../src/services/cdn/cdnClientAdapter.js", () => ({
  cdnClient: { purge: vi.fn() },
}));
vi.mock("../../../src/utils/logger.js", () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));
vi.mock("../../../src/services/audit/auditLog.js", () => ({
  recordCdnPurgeStatus: vi.fn(),
}));

import { enqueueCdnPurge } from "../../../src/jobs/purgeCdnJob.js";
import { cdnClient } from "../../../src/services/cdn/cdnClientAdapter.js";
import { logger } from "../../../src/utils/logger.js";
import { recordCdnPurgeStatus } from "../../../src/services/audit/auditLog.js";

const purgeMock = vi.mocked(cdnClient.purge);
const recordMock = vi.mocked(recordCdnPurgeStatus);
const infoMock = vi.mocked(logger.info);
const errorMock = vi.mocked(logger.error);

beforeEach(() => {
  vi.clearAllMocks();
  purgeMock.mockResolvedValue(undefined);
});

describe("enqueueCdnPurge — success path", () => {
  it("forwards the purge URL to the CDN adapter as a single-element list", async () => {
    await enqueueCdnPurge("att-1", "https://cdn.example.com/att-1.json");

    expect(purgeMock).toHaveBeenCalledTimes(1);
    expect(purgeMock).toHaveBeenCalledWith(["https://cdn.example.com/att-1.json"]);
  });

  it("records a `success` purge status with the purged URL", async () => {
    await enqueueCdnPurge("att-2", "https://cdn.example.com/att-2.json");

    expect(recordMock).toHaveBeenCalledTimes(1);
    expect(recordMock).toHaveBeenCalledWith("att-2", "success", {
      url: "https://cdn.example.com/att-2.json",
    });
  });

  it("logs an info line that names the attestation", async () => {
    await enqueueCdnPurge("att-3", "https://cdn.example.com/att-3.json");

    expect(infoMock).toHaveBeenCalledTimes(1);
    expect(String(infoMock.mock.calls[0][0])).toContain("att-3");
  });

  it("does not record a failure or log an error when the purge succeeds", async () => {
    await enqueueCdnPurge("att-4", "https://cdn.example.com/att-4.json");

    expect(recordMock).not.toHaveBeenCalledWith("att-4", "failed", expect.anything());
    expect(errorMock).not.toHaveBeenCalled();
  });

  it("resolves to undefined", async () => {
    await expect(
      enqueueCdnPurge("att-5", "https://cdn.example.com/att-5.json"),
    ).resolves.toBeUndefined();
  });
});

describe("enqueueCdnPurge — failure path", () => {
  it("records `failed` with the Error message when the CDN rejects", async () => {
    purgeMock.mockRejectedValue(new Error("CDN responded 503"));

    await enqueueCdnPurge("att-6", "https://cdn.example.com/att-6.json");

    expect(recordMock).toHaveBeenCalledTimes(1);
    expect(recordMock).toHaveBeenCalledWith("att-6", "failed", {
      error: "CDN responded 503",
    });
  });

  it("does not throw to the caller when the CDN rejects", async () => {
    purgeMock.mockRejectedValue(new Error("network down"));

    await expect(
      enqueueCdnPurge("att-7", "https://cdn.example.com/att-7.json"),
    ).resolves.toBeUndefined();
  });

  it("logs an error line that combines the attestation and the failure reason", async () => {
    purgeMock.mockRejectedValue(new Error("timeout after 30s"));

    await enqueueCdnPurge("att-8", "https://cdn.example.com/att-8.json");

    expect(errorMock).toHaveBeenCalledTimes(1);
    const line = String(errorMock.mock.calls[0][0]);
    expect(line).toContain("att-8");
    expect(line).toContain("timeout after 30s");
  });

  it("does not record a success status when the purge fails", async () => {
    purgeMock.mockRejectedValue(new Error("boom"));

    await enqueueCdnPurge("att-9", "https://cdn.example.com/att-9.json");

    expect(recordMock).not.toHaveBeenCalledWith("att-9", "success", expect.anything());
  });

  it("normalises a non-Error rejection (string) via String()", async () => {
    purgeMock.mockRejectedValue("plain string reason");

    await enqueueCdnPurge("att-10", "https://cdn.example.com/att-10.json");

    expect(recordMock).toHaveBeenCalledWith("att-10", "failed", {
      error: "plain string reason",
    });
  });

  it("normalises a non-Error rejection (object) via String()", async () => {
    purgeMock.mockRejectedValue({ code: 42 });

    await enqueueCdnPurge("att-11", "https://cdn.example.com/att-11.json");

    const [, status, details] = recordMock.mock.calls[0];
    expect(status).toBe("failed");
    // `String({ code: 42 })` is the default object-to-string rendering; the job
    // never throws while normalising a non-Error rejection.
    expect((details as { error: string }).error).toBe("[object Object]");
  });

  it("normalises a thrown TypeError from an invalid URL", async () => {
    purgeMock.mockRejectedValue(new TypeError("Invalid URL"));

    await enqueueCdnPurge("att-12", "not-a-url");

    expect(recordMock).toHaveBeenCalledWith("att-12", "failed", {
      error: "Invalid URL",
    });
    expect(purgeMock).toHaveBeenCalledWith(["not-a-url"]);
  });
});

describe("enqueueCdnPurge — repeated invocations", () => {
  it("keeps audit records independent per attestation", async () => {
    purgeMock.mockResolvedValueOnce(undefined).mockRejectedValueOnce(new Error("nope"));

    await enqueueCdnPurge("att-a", "https://cdn.example.com/a.json");
    await enqueueCdnPurge("att-b", "https://cdn.example.com/b.json");

    expect(purgeMock).toHaveBeenNthCalledWith(1, ["https://cdn.example.com/a.json"]);
    expect(purgeMock).toHaveBeenNthCalledWith(2, ["https://cdn.example.com/b.json"]);
    expect(recordMock).toHaveBeenNthCalledWith(1, "att-a", "success", {
      url: "https://cdn.example.com/a.json",
    });
    expect(recordMock).toHaveBeenNthCalledWith(2, "att-b", "failed", { error: "nope" });
  });
});
