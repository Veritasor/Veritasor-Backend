import { BASE_FEE, Contract, Keypair, StrKey, TransactionBuilder, nativeToScVal, rpc } from '@stellar/stellar-sdk';
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
  unsignedXdr?: string;
};

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

    if (response.status === 'ERROR' || response.status === 'TRY_AGAIN_LATER') {
      throw new SorobanSubmissionError(mapSendResponseError(response), 'SUBMIT_FAILED', response);
    }

    return {
      txHash: response.hash,
    };
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
