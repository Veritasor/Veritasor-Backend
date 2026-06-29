import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  getSorobanSubmissionQueue,
  isSorobanBatchingEnabled,
  resetSorobanSubmissionQueue,
  submitAttestationQueued,
} from "../../../../src/services/soroban/submissionQueue.js";

vi.mock("../../../../src/services/soroban/submitAttestationBatch.js", () => ({
  submitAttestationBatch: vi.fn(async (items: unknown[]) =>
    items.map((_, index) => ({
      params: items[index],
      result: { txHash: `tx-${index}`, status: "confirmed" },
    })),
  ),
}));

vi.mock("../../../../src/services/soroban/submitAttestation.js", () => ({
  submitAttestationDirect: vi.fn(async () => ({
    txHash: "direct-tx",
    status: "confirmed",
  })),
}));

describe("submissionQueue", () => {
  beforeEach(() => {
    resetSorobanSubmissionQueue();
    delete process.env.SOROBAN_BATCHING_ENABLED;
  });

  afterEach(() => {
    resetSorobanSubmissionQueue();
  });

  it("reports batching enabled by default", () => {
    expect(isSorobanBatchingEnabled()).toBe(true);
  });

  it("bypasses the queue when batching is disabled", async () => {
    process.env.SOROBAN_BATCHING_ENABLED = "false";
    resetSorobanSubmissionQueue();

    const { submitAttestationDirect } = await import(
      "../../../../src/services/soroban/submitAttestation.js"
    );

    const result = await submitAttestationQueued({
      business: "biz",
      period: "2025-10",
      merkleRoot: "root",
      timestamp: 1,
      version: "1.0.0",
      sourcePublicKey: "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
    });

    expect(result.txHash).toBe("direct-tx");
    expect(submitAttestationDirect).toHaveBeenCalledTimes(1);
  });

  it("enqueues submissions for batched flushing", async () => {
    vi.useFakeTimers();

    const queue = getSorobanSubmissionQueue();
    const pending = submitAttestationQueued({
      business: "biz",
      period: "2025-10",
      merkleRoot: "root",
      timestamp: 1,
      version: "1.0.0",
      sourcePublicKey: "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
    });

    await vi.advanceTimersByTimeAsync(500);
    await expect(pending).resolves.toMatchObject({ txHash: "tx-0", status: "confirmed" });
    expect(queue.depth).toBe(0);

    vi.useRealTimers();
  });
});
