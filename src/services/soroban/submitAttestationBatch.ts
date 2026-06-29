import {
  SorobanSubmissionError,
  SubmitAttestationParams,
  SubmitAttestationResult,
} from "./submitAttestation.js";
import { sorobanBatchPartialReplayTotal } from "../../metrics.js";
import type { FlushReason } from "./batchingQueue.js";
import {
  submitBatchTransaction,
  submitSingleAttestationInBatchContext,
  validateBatchParams,
} from "./batchSubmitTransport.js";

export type BatchItemResult = {
  params: SubmitAttestationParams;
  result?: SubmitAttestationResult;
  error?: SorobanSubmissionError;
};

/**
 * Submits multiple attestations, attempting a single transaction first.
 *
 * When the batch transaction fails, falls back to per-item submission so a
 * single failing leaf does not roll back successful entries (partial replay).
 */
export async function submitAttestationBatch(
  paramsList: SubmitAttestationParams[],
  _reason?: FlushReason,
): Promise<BatchItemResult[]> {
  if (paramsList.length === 0) {
    return [];
  }

  const validated: { index: number; params: SubmitAttestationParams }[] = [];
  const results: BatchItemResult[] = paramsList.map((params) => ({ params }));

  for (let i = 0; i < paramsList.length; i++) {
    try {
      validateBatchParams(paramsList[i]);
      if (paramsList[i].submit === false) {
        throw new SorobanSubmissionError(
          "Unsigned submissions cannot be batched.",
          "VALIDATION_ERROR",
        );
      }
      validated.push({ index: i, params: paramsList[i] });
    } catch (error) {
      results[i].error =
        error instanceof SorobanSubmissionError
          ? error
          : new SorobanSubmissionError(
              "Failed to validate attestation submission parameters.",
              "VALIDATION_ERROR",
              error,
            );
    }
  }

  if (validated.length === 0) {
    return results;
  }

  if (validated.length === 1) {
    try {
      results[validated[0].index].result = await submitSingleAttestationInBatchContext(
        validated[0].params,
      );
    } catch (error) {
      results[validated[0].index].error = toSubmissionError(error);
    }
    return results;
  }

  const batchParams = validated.map((entry) => entry.params);

  try {
    const batchResults = await submitBatchTransaction(batchParams);
    for (let i = 0; i < validated.length; i++) {
      results[validated[i].index].result = batchResults[i];
    }
    return results;
  } catch {
    sorobanBatchPartialReplayTotal.inc({ outcome: "started" }, batchParams.length);

    for (const entry of validated) {
      try {
        results[entry.index].result = await submitSingleAttestationInBatchContext(
          entry.params,
        );
        sorobanBatchPartialReplayTotal.inc({ outcome: "succeeded" });
      } catch (error) {
        results[entry.index].error = toSubmissionError(error);
        sorobanBatchPartialReplayTotal.inc({ outcome: "failed" });
      }
    }
  }

  return results;
}

function toSubmissionError(error: unknown): SorobanSubmissionError {
  if (error instanceof SorobanSubmissionError) {
    return error;
  }
  return new SorobanSubmissionError(
    "Failed to build or submit attestation transaction on Soroban.",
    "SOROBAN_NETWORK_ERROR",
    error,
  );
}

/**
 * Converts batch handler output into thrown errors for queue consumers.
 */
export function unwrapBatchItemResult(item: BatchItemResult): SubmitAttestationResult {
  if (item.error) {
    throw item.error;
  }
  if (!item.result) {
    throw new SorobanSubmissionError(
      "Batch item completed without a result.",
      "SOROBAN_NETWORK_ERROR",
    );
  }
  return item.result;
}
