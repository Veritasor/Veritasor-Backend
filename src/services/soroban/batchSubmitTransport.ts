import {
  BASE_FEE,
  Contract,
  Keypair,
  StrKey,
  TransactionBuilder,
  nativeToScVal,
  rpc,
} from "@stellar/stellar-sdk";
import { createSorobanRpcServer, getSorobanConfig } from "./client.js";
import {
  SorobanSubmissionError,
  SubmitAttestationParams,
  SubmitAttestationResult,
  validateConfirmedResult,
  validateSendTransactionResponse,
  waitForConfirmation,
} from "./submitAttestation.js";

function normalizeTimestamp(timestamp: number | bigint): bigint {
  if (typeof timestamp === "bigint") {
    return timestamp;
  }
  if (!Number.isFinite(timestamp) || timestamp < 0) {
    throw new SorobanSubmissionError(
      "timestamp must be a non-negative number or bigint",
      "VALIDATION_ERROR",
    );
  }
  return BigInt(Math.floor(timestamp));
}

export function validateBatchParams(params: SubmitAttestationParams): void {
  if (!StrKey.isValidEd25519PublicKey(params.sourcePublicKey)) {
    throw new SorobanSubmissionError(
      "sourcePublicKey must be a valid Stellar public key (G...)",
      "VALIDATION_ERROR",
    );
  }

  const shouldSubmit = params.submit ?? true;
  if (shouldSubmit && !params.signerSecret && !process.env.SOROBAN_SOURCE_SECRET) {
    throw new SorobanSubmissionError(
      "No signer secret available. Provide params.signerSecret or set SOROBAN_SOURCE_SECRET, or call with submit:false.",
      "MISSING_SIGNER",
    );
  }
}

function resolveSigner(params: SubmitAttestationParams): Keypair {
  const signerSecret = params.signerSecret ?? process.env.SOROBAN_SOURCE_SECRET;
  if (!signerSecret) {
    throw new SorobanSubmissionError(
      "No signer secret available.",
      "MISSING_SIGNER",
    );
  }

  const signer = Keypair.fromSecret(signerSecret);
  if (signer.publicKey() !== params.sourcePublicKey) {
    throw new SorobanSubmissionError(
      "signerSecret does not match sourcePublicKey.",
      "SIGNER_MISMATCH",
    );
  }

  return signer;
}

function mapSendResponseError(response: rpc.Api.SendTransactionResponse): string {
  if (response.status === "TRY_AGAIN_LATER") {
    return "Soroban RPC asked to retry later. The network may be overloaded.";
  }
  if (response.status === "ERROR") {
    return "Soroban RPC rejected the transaction.";
  }
  return "Failed to submit Soroban transaction.";
}

async function confirmSubmission(
  server: rpc.Server,
  response: rpc.Api.SendTransactionResponse,
  merkleRoot: string,
): Promise<SubmitAttestationResult> {
  try {
    const confirmed = await waitForConfirmation(server, response.hash);
    const successResponse = confirmed as rpc.Api.GetSuccessfulTransactionResponse;
    const validated = validateConfirmedResult(successResponse, merkleRoot);

    return {
      txHash: response.hash,
      status: "confirmed",
      ledger: successResponse.ledger,
      resultMerkleRoot: validated.merkleRoot,
      resultTimestamp: validated.timestamp,
    };
  } catch (confirmError) {
    if (
      confirmError instanceof SorobanSubmissionError &&
      confirmError.code === "CONFIRMATION_TIMEOUT"
    ) {
      return {
        txHash: response.hash,
        status: "pending",
      };
    }
    throw confirmError;
  }
}

/**
 * Builds a multi-operation Soroban transaction for batched attestation submission.
 */
export async function buildBatchAttestationTransaction(
  paramsList: SubmitAttestationParams[],
): Promise<{ prepared: ReturnType<TransactionBuilder["build"]>; server: rpc.Server }> {
  if (paramsList.length === 0) {
    throw new SorobanSubmissionError("Batch must contain at least one item", "VALIDATION_ERROR");
  }

  const { contractId, networkPassphrase, rpcUrl } = getSorobanConfig();
  const server = createSorobanRpcServer(rpcUrl);
  const sourcePublicKey = paramsList[0].sourcePublicKey;
  const signer = resolveSigner(paramsList[0]);

  for (const params of paramsList) {
    validateBatchParams(params);
    if (params.sourcePublicKey !== sourcePublicKey) {
      throw new SorobanSubmissionError(
        "All batched submissions must share the same sourcePublicKey.",
        "VALIDATION_ERROR",
      );
    }
    if (params.submit === false) {
      throw new SorobanSubmissionError(
        "Unsigned submissions cannot be batched.",
        "VALIDATION_ERROR",
      );
    }
  }

  const account = await server.getAccount(sourcePublicKey);
  const contract = new Contract(contractId);

  const builder = new TransactionBuilder(account, {
    fee: (Number.parseInt(BASE_FEE, 10) * paramsList.length).toString(),
    networkPassphrase,
  });

  for (const params of paramsList) {
    builder.addOperation(
      contract.call(
        "submit_attestation",
        nativeToScVal(params.business),
        nativeToScVal(params.period),
        nativeToScVal(params.merkleRoot),
        nativeToScVal(normalizeTimestamp(params.timestamp), { type: "u64" }),
        nativeToScVal(params.version),
      ),
    );
  }

  const tx = builder.setTimeout(30).build();
  const prepared = await server.prepareTransaction(tx);
  prepared.sign(signer);

  return { prepared, server };
}

/**
 * Submits a batch as a single Soroban transaction.
 */
export async function submitBatchTransaction(
  paramsList: SubmitAttestationParams[],
): Promise<SubmitAttestationResult[]> {
  const { prepared, server } = await buildBatchAttestationTransaction(paramsList);
  const response = await server.sendTransaction(prepared);

  validateSendTransactionResponse(response);

  if (response.status === "ERROR" || response.status === "TRY_AGAIN_LATER") {
    throw new SorobanSubmissionError(
      mapSendResponseError(response),
      "SUBMIT_FAILED",
      response,
    );
  }

  const confirmed = await confirmSubmission(server, response, paramsList[0].merkleRoot);

  return paramsList.map(() => ({
    ...confirmed,
    txHash: response.hash,
  }));
}

/**
 * Submits one attestation outside of a batch (used for partial replay).
 */
export async function submitSingleAttestationInBatchContext(
  params: SubmitAttestationParams,
): Promise<SubmitAttestationResult> {
  const results = await submitBatchTransaction([params]);
  return results[0];
}
