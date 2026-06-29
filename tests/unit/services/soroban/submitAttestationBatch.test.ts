import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Keypair } from "@stellar/stellar-sdk";
import {
  SorobanSubmissionError,
  type SubmitAttestationParams,
} from "../../../../src/services/soroban/submitAttestation.js";
import {
  submitAttestationBatch,
  unwrapBatchItemResult,
} from "../../../../src/services/soroban/submitAttestationBatch.js";
import { metricsRegistry } from "../../../../src/metrics.js";

const testKeypair = Keypair.random();

const baseParams = (overrides: Partial<SubmitAttestationParams> = {}): SubmitAttestationParams => ({
  business: "biz-1",
  period: "2025-10",
  merkleRoot: "0xabc123",
  timestamp: 1_700_000_000,
  version: "1.0.0",
  sourcePublicKey: testKeypair.publicKey(),
  signerSecret: testKeypair.secret(),
  submit: true,
  ...overrides,
});

vi.mock("../../../../src/services/soroban/batchSubmitTransport.js", () => ({
  validateBatchParams: vi.fn(),
  submitBatchTransaction: vi.fn(),
  submitSingleAttestationInBatchContext: vi.fn(),
}));

import * as transport from "../../../../src/services/soroban/batchSubmitTransport.js";

describe("submitAttestationBatch", () => {
  beforeEach(async () => {
    await metricsRegistry.resetMetrics();
    vi.clearAllMocks();
    vi.mocked(transport.validateBatchParams).mockImplementation(() => undefined);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("returns validation errors without blocking other items", async () => {
    vi.mocked(transport.validateBatchParams)
      .mockImplementationOnce(() => undefined)
      .mockImplementationOnce(() => {
        throw new SorobanSubmissionError("bad key", "VALIDATION_ERROR");
      });
    vi.mocked(transport.submitSingleAttestationInBatchContext).mockResolvedValue({
      txHash: "single-tx",
      status: "confirmed",
    });

    const results = await submitAttestationBatch([
      baseParams(),
      baseParams({ business: "biz-2" }),
    ]);

    expect(results).toHaveLength(2);
    expect(results[0].result?.txHash).toBe("single-tx");
    expect(results[1].error?.code).toBe("VALIDATION_ERROR");
    expect(transport.submitSingleAttestationInBatchContext).toHaveBeenCalledTimes(1);
  });

  it("submits a single valid item directly", async () => {
    vi.mocked(transport.submitSingleAttestationInBatchContext).mockResolvedValue({
      txHash: "abc",
      status: "confirmed",
    });

    const results = await submitAttestationBatch([baseParams()]);

    expect(transport.submitBatchTransaction).not.toHaveBeenCalled();
    expect(transport.submitSingleAttestationInBatchContext).toHaveBeenCalledTimes(1);
    expect(results[0].result?.txHash).toBe("abc");
  });

  it("uses a single transaction for multi-item batches", async () => {
    vi.mocked(transport.submitBatchTransaction).mockResolvedValue([
      { txHash: "batch-tx", status: "confirmed" },
      { txHash: "batch-tx", status: "confirmed" },
    ]);

    const results = await submitAttestationBatch([
      baseParams({ merkleRoot: "root-a" }),
      baseParams({ merkleRoot: "root-b", business: "biz-2" }),
    ]);

    expect(transport.submitBatchTransaction).toHaveBeenCalledTimes(1);
    expect(results.every((entry) => entry.result?.txHash === "batch-tx")).toBe(true);
  });

  it("partially replays items when the batch transaction fails", async () => {
    vi.mocked(transport.submitBatchTransaction).mockRejectedValue(
      new SorobanSubmissionError("batch failed", "SUBMIT_FAILED"),
    );
    vi.mocked(transport.submitSingleAttestationInBatchContext)
      .mockResolvedValueOnce({ txHash: "tx-1", status: "confirmed" })
      .mockRejectedValueOnce(
        new SorobanSubmissionError("leaf failed", "CONTRACT_ERROR"),
      )
      .mockResolvedValueOnce({ txHash: "tx-3", status: "confirmed" });

    const results = await submitAttestationBatch([
      baseParams({ merkleRoot: "root-1" }),
      baseParams({ merkleRoot: "root-2" }),
      baseParams({ merkleRoot: "root-3" }),
    ]);

    expect(transport.submitSingleAttestationInBatchContext).toHaveBeenCalledTimes(3);
    expect(results[0].result?.txHash).toBe("tx-1");
    expect(results[1].error?.code).toBe("CONTRACT_ERROR");
    expect(results[2].result?.txHash).toBe("tx-3");

    const metrics = await metricsRegistry.getMetricsAsJSON();
    const counter = metrics.find((m) => m.name === "soroban_batch_partial_replay_total");
    expect(counter?.values.some((v) => v.labels.outcome === "succeeded")).toBe(true);
    expect(counter?.values.some((v) => v.labels.outcome === "failed")).toBe(true);
  });

  it("unwrapBatchItemResult throws stored errors", () => {
    const error = new SorobanSubmissionError("nope", "SUBMIT_FAILED");
    expect(() =>
      unwrapBatchItemResult({ params: baseParams(), error }),
    ).toThrow(error);
  });
});
