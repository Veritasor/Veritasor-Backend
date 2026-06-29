import { config } from "../../config/index.js";
import { BatchingQueue, type FlushReason } from "./batchingQueue.js";
import {
  submitAttestationBatch,
  type BatchItemResult,
} from "./submitAttestationBatch.js";
import type {
  SubmitAttestationParams,
  SubmitAttestationResult,
} from "./submitAttestation.js";

export type SorobanBatchingConfig = typeof config.soroban.batching;

export function getSorobanBatchingConfig(): SorobanBatchingConfig {
  return config.soroban.batching;
}

let queueInstance: BatchingQueue<
  SubmitAttestationParams,
  SubmitAttestationResult
> | null = null;

async function flushBatch(
  items: SubmitAttestationParams[],
  reason: FlushReason,
): Promise<Array<SubmitAttestationResult | { error: unknown }>> {
  const batchResults = await submitAttestationBatch(items, reason);
  return batchResults.map((item: BatchItemResult) => {
    if (item.error) {
      return { error: item.error };
    }
    if (!item.result) {
      return {
        error: new Error("Batch item completed without a result."),
      };
    }
    return item.result;
  });
}

/**
 * Returns the process-wide Soroban submission batching queue.
 * Recreated when config changes in tests via `resetSorobanSubmissionQueue`.
 */
export function getSorobanSubmissionQueue(): BatchingQueue<
  SubmitAttestationParams,
  SubmitAttestationResult
> {
  if (!queueInstance) {
    const batchingConfig = getSorobanBatchingConfig();
    queueInstance = new BatchingQueue(flushBatch, {
      maxBatchSize: batchingConfig.maxBatchSize,
      minFlushMs: batchingConfig.minFlushMs,
      maxFlushMs: batchingConfig.maxFlushMs,
      backpressureThreshold: batchingConfig.backpressureThreshold,
    });
  }

  return queueInstance;
}

/** Test helper to rebuild the queue with fresh configuration. */
export function resetSorobanSubmissionQueue(): void {
  queueInstance = null;
}

/** Drains pending batched submissions during graceful shutdown. */
export async function drainSorobanSubmissionQueue(): Promise<void> {
  if (queueInstance) {
    await queueInstance.drain();
  }
}

export function isSorobanBatchingEnabled(): boolean {
  const raw = process.env.SOROBAN_BATCHING_ENABLED;
  if (raw !== undefined) {
    const normalized = raw.trim().toLowerCase();
    if (["true", "1", "yes", "on"].includes(normalized)) {
      return true;
    }
    if (["false", "0", "no", "off"].includes(normalized)) {
      return false;
    }
  }
  return config.soroban.batching.enabled;
}

/**
 * Enqueues an attestation for batched Soroban submission when batching is enabled.
 */
export async function submitAttestationQueued(
  params: SubmitAttestationParams,
): Promise<SubmitAttestationResult> {
  if (!isSorobanBatchingEnabled() || params.submit === false) {
    const { submitAttestationDirect } = await import("./submitAttestation.js");
    return submitAttestationDirect(params);
  }

  return getSorobanSubmissionQueue().enqueue(params);
}
