import { BASE_FEE, Contract, Keypair, StrKey, TransactionBuilder, nativeToScVal, rpc, scValToNative } from '@stellar/stellar-sdk';
import { createSorobanRpcServer, getSorobanConfig } from './client.js';
import { getSorobanBatchedSubmissionFlag } from '../features/flags.js';
import { logger } from '../../utils/logger.js';
import { AdaptiveBatchSizeController, sampleSorobanFeeStats } from './adaptiveBatchSize.js';
import { DrrScheduler, type BatchQueueItem, type TenantTier } from './drrScheduler.js';
import {
  sorobanAdaptiveBatchSize,
  sorobanFeeEwma,
  sorobanCurrentFee,
  sorobanFeeVolatility,
  sorobanFeeSpikeProtectionsTotal,
} from '../../metrics.js';

export class SorobanSubmissionError extends Error {
  constructor(message: string, public code: string, public cause?: unknown) {
    super(message);
    this.name = 'SorobanSubmissionError';
  }
}

export type SubmitAttestationParams = {
  business: string;
  period: string;
  merkleRoot: string;
  timestamp: number | bigint;
  version: string;
  sourcePublicKey: string;
  signerSecret?: string;
  submit?: boolean;
  userId?: string;
};

export type SubmitAttestationResult = {
  txHash: string;
  status: 'pending' | 'confirmed' | 'unsigned';
  unsignedXdr?: string;
  ledger?: number;
  resultMerkleRoot?: string;
  resultTimestamp?: number;
};

/** Default polling config for transaction confirmation. */
const CONFIRMATION_POLL_INTERVAL_MS = 2000;
const CONFIRMATION_MAX_ATTEMPTS = 15;

/** Valid hex hash: 64 lowercase hex chars. */
const TX_HASH_RE = /^[0-9a-f]{64}$/;

/**
 * Global singleton adaptive batch-size controller.
 *
 * Created once at module load and shared across all attestation submission
 * calls. The controller samples Soroban network fee stats via RPC and
 * adjusts the batch size within configured bounds using an EWMA-smoothed
 * fee signal.
 */
export const adaptiveBatchController = new AdaptiveBatchSizeController();

// ---------------------------------------------------------------------------
// DRR fair-batch scheduler singleton
// ---------------------------------------------------------------------------

/**
 * Global singleton DRR fair-batch scheduler.
 *
 * Tenants enqueue attestation submissions here via
 * {@link enqueueToBatchScheduler}. The scheduler interleaves items from
 * competing tenants using Deficit Round-Robin, preventing any single noisy
 * tenant from monopolising batch slots.
 *
 * Weights are resolved from the `DRR_SCHEDULER_TIER_WEIGHTS` env var (JSON)
 * with built-in fallbacks: free=1, starter=2, growth=4, enterprise=8.
 */
export const drrBatchScheduler = new DrrScheduler<SubmitAttestationParams>();

/**
 * Samples Soroban network fee stats and returns the current tuned batch
 * size from the global adaptive batch-size controller.
 *
 * Updates Prometheus metrics for observability. If fee spike protection
 * activates, increments the spike protection counter.
 *
 * If the sample interval has not elapsed since the last sample, returns
 * the previously tuned batch size without a new RPC call.
 *
 * @param server - A connected Soroban RPC server instance.
 * @returns The current tuned batch size (clamped between min and max).
 */
export async function getAdaptiveBatchSize(server: rpc.Server): Promise<number> {
  const controller = adaptiveBatchController;
  const config = controller.getConfig();

  const sampled = await controller.sampleAndTune(server);

  if (sampled) {
    const ewmaFee = controller.getEwmaFee();
    sorobanAdaptiveBatchSize.set(controller.getBatchSize());
    if (ewmaFee !== null) {
      sorobanFeeEwma.set(ewmaFee);
    }
  }

  return controller.getBatchSize();
}

/**
 * Samples fee stats explicitly and updates all Prometheus metrics,
 * including the spike protection counter if spike protection is active.
 *
 * This is called internally by `getAdaptiveBatchSize` but is exported
 * for callers that need to sample fees independently of tuning.
 */
export async function sampleAndUpdateMetrics(server: rpc.Server): Promise<void> {
  const sample = await sampleSorobanFeeStats(server);
  sorobanCurrentFee.set(sample.fee);
  sorobanFeeVolatility.set(sample.volatility);

  const controller = adaptiveBatchController;
  const config = controller.getConfig();
  const prevBatchSize = controller.getBatchSize();

  controller.tune(sample.fee, sample.volatility);

  sorobanAdaptiveBatchSize.set(controller.getBatchSize());
  const ewmaFee = controller.getEwmaFee();
  if (ewmaFee !== null) {
    sorobanFeeEwma.set(ewmaFee);
  }

  // Detect spike protection activation
  const ratio = sample.fee / (ewmaFee ?? sample.fee);
  if (ratio > config.feeSpikeMultiplier && controller.getBatchSize() < prevBatchSize) {
    sorobanFeeSpikeProtectionsTotal.inc();
  }
}

function normalizeTimestamp(timestamp: number | bigint): bigint {
  if (typeof timestamp === 'bigint') {
    return timestamp;
  }
  if (!Number.isFinite(timestamp) || timestamp < 0) {
    throw new SorobanSubmissionError('timestamp must be a non-negative number or bigint', 'VALIDATION_ERROR');
  }
  return BigInt(Math.floor(timestamp));
}

function mapSendResponseError(response: rpc.Api.SendTransactionResponse): string {
  if (response.status === 'TRY_AGAIN_LATER') {
    return 'Soroban RPC asked to retry later. The network may be overloaded.';
  }
  if (response.status === 'ERROR') {
    return 'Soroban RPC rejected the transaction.';
  }
  return 'Failed to submit Soroban transaction.';
}

/**
 * Validates the immediate response from `sendTransaction`.
 *
 * Ensures the response contains a well-formed transaction hash and an
 * expected status value. Throws `SorobanSubmissionError` with code
 * `INVALID_RESPONSE` when the response shape is unexpected.
 */
export function validateSendTransactionResponse(
  response: rpc.Api.SendTransactionResponse,
): void {
  if (!response || typeof response !== 'object') {
    throw new SorobanSubmissionError(
      'sendTransaction returned an invalid response object.',
      'INVALID_RESPONSE',
      response,
    );
  }

  if (typeof response.hash !== 'string' || !TX_HASH_RE.test(response.hash)) {
    throw new SorobanSubmissionError(
      `sendTransaction returned an invalid transaction hash: "${response.hash}".`,
      'INVALID_RESPONSE',
      response,
    );
  }

  const validStatuses = ['PENDING', 'DUPLICATE', 'ERROR', 'TRY_AGAIN_LATER'];
  if (!validStatuses.includes(response.status)) {
    throw new SorobanSubmissionError(
      `sendTransaction returned an unexpected status: "${response.status}".`,
      'INVALID_RESPONSE',
      response,
    );
  }
}

/**
 * Polls `getTransaction` until the transaction reaches a terminal state
 * (SUCCESS or FAILED) or the maximum number of attempts is exhausted.
 *
 * Returns the confirmed response, or throws `SorobanSubmissionError` with
 * code `CONFIRMATION_TIMEOUT` or `CONFIRMATION_FAILED`.
 */
export async function waitForConfirmation(
  server: rpc.Server,
  txHash: string,
  pollIntervalMs: number = CONFIRMATION_POLL_INTERVAL_MS,
  maxAttempts: number = CONFIRMATION_MAX_ATTEMPTS,
): Promise<rpc.Api.GetTransactionResponse> {
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const txResponse = await server.getTransaction(txHash);

    if (txResponse.status === 'SUCCESS') {
      return txResponse;
    }

    if (txResponse.status === 'FAILED') {
      throw new SorobanSubmissionError(
        'Transaction was included in a ledger but execution failed.',
        'CONFIRMATION_FAILED',
        txResponse,
      );
    }

    // status === 'NOT_FOUND' means still pending — keep polling
    if (attempt < maxAttempts - 1) {
      await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));
    }
  }

  throw new SorobanSubmissionError(
    `Transaction ${txHash} was not confirmed after ${maxAttempts} polling attempts.`,
    'CONFIRMATION_TIMEOUT',
  );
}

/**
 * Validates the confirmed transaction result against the originally
 * submitted attestation parameters.
 *
 * Extracts the contract return value and checks that the merkle root
 * stored on-chain matches what was submitted. Returns the validated
 * on-chain values for inclusion in the result.
 */
export function validateConfirmedResult(
  txResponse: rpc.Api.GetSuccessfulTransactionResponse,
  submittedMerkleRoot: string,
): { merkleRoot: string; timestamp: number } {
  if (!txResponse.returnValue) {
    throw new SorobanSubmissionError(
      'Confirmed transaction has no return value. The contract may not have returned attestation data.',
      'RESULT_VALIDATION_FAILED',
      txResponse,
    );
  }

  let native: Record<string, unknown>;
  try {
    native = scValToNative(txResponse.returnValue) as Record<string, unknown>;
  } catch (err) {
    throw new SorobanSubmissionError(
      'Failed to decode the contract return value from the confirmed transaction.',
      'RESULT_VALIDATION_FAILED',
      err,
    );
  }

  if (!native || typeof native !== 'object') {
    throw new SorobanSubmissionError(
      'Contract return value is not a valid object.',
      'RESULT_VALIDATION_FAILED',
      native,
    );
  }

  const onChainRoot = typeof native.merkle_root === 'string'
    ? native.merkle_root
    : String(native.merkle_root ?? '');

  if (!onChainRoot) {
    throw new SorobanSubmissionError(
      'Confirmed transaction result does not contain a merkle_root field.',
      'RESULT_VALIDATION_FAILED',
      native,
    );
  }

  if (onChainRoot !== submittedMerkleRoot) {
    throw new SorobanSubmissionError(
      `On-chain merkle root "${onChainRoot}" does not match submitted value "${submittedMerkleRoot}".`,
      'RESULT_MISMATCH',
      { expected: submittedMerkleRoot, actual: onChainRoot },
    );
  }

  const onChainTimestamp = native.timestamp !== undefined
    ? Number(native.timestamp)
    : undefined;

  if (onChainTimestamp === undefined || !Number.isFinite(onChainTimestamp)) {
    throw new SorobanSubmissionError(
      'Confirmed transaction result does not contain a valid timestamp.',
      'RESULT_VALIDATION_FAILED',
      native,
    );
  }

  return { merkleRoot: onChainRoot, timestamp: onChainTimestamp };
}

export async function submitAttestation(params: SubmitAttestationParams): Promise<SubmitAttestationResult> {
  const { contractId, networkPassphrase, rpcUrl } = getSorobanConfig();
  const server = createSorobanRpcServer(rpcUrl);

  if (!StrKey.isValidEd25519PublicKey(params.sourcePublicKey)) {
    throw new SorobanSubmissionError('sourcePublicKey must be a valid Stellar public key (G...)', 'VALIDATION_ERROR');
  }

  const shouldSubmit = params.submit ?? true;
  const signerSecret = params.signerSecret ?? process.env.SOROBAN_SOURCE_SECRET;

  if (params.userId) {
    try {
      const useBatched = await getSorobanBatchedSubmissionFlag({
        businessId: params.business,
        userId: params.userId,
      });
      if (useBatched) {
        logger.info({
          event: 'soroban_batched_submission_enabled',
          business: params.business,
          userId: params.userId,
        });
      }
    } catch {
      // flag evaluation failure is non-fatal; proceed with default behavior
    }
  }

  try {
    const account = await server.getAccount(params.sourcePublicKey);
    const contract = new Contract(contractId);

    const operation = contract.call(
      'submit_attestation',
      nativeToScVal(params.business),
      nativeToScVal(params.period),
      nativeToScVal(params.merkleRoot),
      nativeToScVal(normalizeTimestamp(params.timestamp), { type: 'u64' }),
      nativeToScVal(params.version),
    );

    const tx = new TransactionBuilder(account, {
      fee: BASE_FEE,
      networkPassphrase,
    })
      .addOperation(operation)
      .setTimeout(30)
      .build();

    const prepared = await server.prepareTransaction(tx);
    const preparedHash = prepared.hash().toString('hex');

    if (!shouldSubmit) {
      return {
        txHash: preparedHash,
        status: 'unsigned',
        unsignedXdr: prepared.toXDR(),
      };
    }

    if (!signerSecret) {
      throw new SorobanSubmissionError(
        'No signer secret available. Provide params.signerSecret or set SOROBAN_SOURCE_SECRET, or call with submit:false.',
        'MISSING_SIGNER',
      );
    }

    const signer = Keypair.fromSecret(signerSecret);
    if (signer.publicKey() !== params.sourcePublicKey) {
      throw new SorobanSubmissionError(
        'signerSecret does not match sourcePublicKey.',
        'SIGNER_MISMATCH',
      );
    }

    prepared.sign(signer);
    const response = await server.sendTransaction(prepared);

    // Validate the immediate sendTransaction response structure.
    validateSendTransactionResponse(response);

    if (response.status === 'ERROR' || response.status === 'TRY_AGAIN_LATER') {
      throw new SorobanSubmissionError(mapSendResponseError(response), 'SUBMIT_FAILED', response);
    }

    // Poll for transaction confirmation and validate the on-chain result.
    try {
      const confirmed = await waitForConfirmation(server, response.hash);

      const successResponse = confirmed as rpc.Api.GetSuccessfulTransactionResponse;
      const validated = validateConfirmedResult(successResponse, params.merkleRoot);

      return {
        txHash: response.hash,
        status: 'confirmed',
        ledger: successResponse.ledger,
        resultMerkleRoot: validated.merkleRoot,
        resultTimestamp: validated.timestamp,
      };
    } catch (confirmError) {
      // If confirmation polling fails but the tx was accepted, return
      // pending status so the caller can retry confirmation separately.
      if (
        confirmError instanceof SorobanSubmissionError &&
        confirmError.code === 'CONFIRMATION_TIMEOUT'
      ) {
        return {
          txHash: response.hash,
          status: 'pending',
        };
      }
      throw confirmError;
    }
  } catch (error) {
    if (error instanceof SorobanSubmissionError) {
      throw error;
    }

    throw new SorobanSubmissionError(
      'Failed to build or submit attestation transaction on Soroban.',
      'SOROBAN_NETWORK_ERROR',
      error,
    );
  }
}

// ---------------------------------------------------------------------------
// DRR scheduler public API
// ---------------------------------------------------------------------------

/**
 * Extended params for enqueueing into the DRR fair-batch scheduler.
 */
export type EnqueueParams = SubmitAttestationParams & {
  /** Tenant identifier used for DRR queue assignment (typically businessId). */
  tenantId: string;
  /**
   * Tenant tier used to determine DRR weight.
   * @example 'free' | 'starter' | 'growth' | 'enterprise'
   */
  tier: TenantTier;
};

/**
 * Enqueues a Soroban attestation submission into the global DRR fair-batch
 * scheduler instead of submitting immediately.
 *
 * The item will be drained in a future call to {@link processBatchSchedulerDrain}.
 * Using the scheduler guarantees that high-volume tenants cannot starve
 * lower-volume tenants in the batch queue.
 *
 * **Security note:** This function is a thin queue wrapper. All input
 * validation (key format, signer match, contract call) happens inside
 * {@link submitAttestation} at drain time — inputs are not validated twice
 * here to avoid inconsistent state if validation rules change.
 *
 * @param params - Attestation params plus `tenantId` and `tier`.
 * @returns The number of items in the tenant's queue after enqueue.
 */
export function enqueueToBatchScheduler(params: EnqueueParams): number {
  const item: BatchQueueItem<SubmitAttestationParams> = {
    tenantId: params.tenantId,
    tier: params.tier,
    payload: params,
    enqueuedAt: Date.now(),
  };
  drrBatchScheduler.enqueue(item);

  const stats = drrBatchScheduler.stats();
  const tenantDepth = stats.tenants[params.tenantId]?.depth ?? 0;

  logger.info(
    {
      event: 'drr_enqueue',
      tenantId: params.tenantId,
      tier: params.tier,
      tenantDepth,
      totalDepth: stats.totalDepth,
    },
    'drr-scheduler: attestation enqueued',
  );

  return tenantDepth;
}

/**
 * Drains up to `batchSize` items from the DRR scheduler and submits each
 * one via {@link submitAttestation}.
 *
 * Results and errors are collected per-item — a single failure does not
 * abort the rest of the batch, preserving fairness guarantees.
 *
 * Callers (e.g. a background job or the batched-submission flag handler)
 * should size `batchSize` using the adaptive batch-size controller:
 * ```ts
 * const server = createSorobanRpcServer(rpcUrl);
 * const size   = await getAdaptiveBatchSize(server);
 * const items  = await processBatchSchedulerDrain(size);
 * ```
 *
 * @param batchSize - Maximum number of items to drain and submit.
 * @returns Array of settled results in DRR-fair order.
 */
export async function processBatchSchedulerDrain(
  batchSize: number,
): Promise<Array<{ tenantId: string; result?: SubmitAttestationResult; error?: unknown }>> {
  const items = drrBatchScheduler.dequeueBatch(batchSize);

  if (items.length === 0) {
    return [];
  }

  logger.info(
    {
      event: 'drr_drain_start',
      count: items.length,
      batchSize,
      schedulerStats: drrBatchScheduler.stats(),
    },
    'drr-scheduler: draining batch',
  );

  const settled = await Promise.allSettled(
    items.map(async (item) => {
      try {
        const result = await submitAttestation(item.payload);
        return { tenantId: item.tenantId, result };
      } catch (error) {
        logger.error(
          { event: 'drr_item_error', tenantId: item.tenantId, error },
          'drr-scheduler: item submission failed',
        );
        return { tenantId: item.tenantId, error };
      }
    }),
  );

  return settled.map((s) =>
    s.status === 'fulfilled' ? s.value : { tenantId: 'unknown', error: s.reason },
  );
}
