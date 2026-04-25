import { BASE_FEE, Contract, Keypair, StrKey, TransactionBuilder, nativeToScVal, rpc, scValToNative } from '@stellar/stellar-sdk';
import { createSorobanRpcServer, getSorobanConfig } from './client.js';

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
