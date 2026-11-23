import { getPgClient } from "../../db/client.js";
import { getById, updateStatus } from "../../repositories/attestationRepository.js";
import { createAuditLog } from "../../repositories/auditLogRepository.js";
import {
  getSorobanConfig,
  createSorobanRpcServer,
} from "../soroban/client.js";
import {
  Contract,
  TransactionBuilder,
  BASE_FEE,
  Keypair,
  nativeToScVal,
} from "@stellar/stellar-sdk";
import {
  validateSendTransactionResponse,
  waitForConfirmation,
  SorobanSubmissionError,
} from "../soroban/submitAttestation.js";

const MAX_BATCH_SIZE = 500;
const CONCURRENCY = 5;

export interface RevokeBatchResult {
  revoked: string[];
  failed: Array<{ id: string; error: string }>;
}

async function revokeOnChain(
  server: ReturnType<typeof createSorobanRpcServer>,
  contractId: string,
  networkPassphrase: string,
  signer: Keypair,
  att: { businessId: string; period: string | number },
): Promise<void> {
  const account = await server.getAccount(signer.publicKey());
  const contract = new Contract(contractId);
  const tx = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase,
  })
    .addOperation(
      contract.call(
        "revoke_attestation",
        nativeToScVal(att.businessId),
        nativeToScVal(att.period),
      ),
    )
    .setTimeout(30)
    .build();

  const prepared = await server.prepareTransaction(tx);
  prepared.sign(signer);

  const response = await server.sendTransaction(prepared);
  validateSendTransactionResponse(response);

  if (response.status === "ERROR" || response.status === "TRY_AGAIN_LATER") {
    throw new SorobanSubmissionError(
      "Failed to submit revoke",
      "SUBMIT_FAILED",
      response,
    );
  }

  await waitForConfirmation(server, response.hash);
}

async function runWithConcurrency<T, R>(
  items: T[],
  limit: number,
  fn: (item: T) => Promise<R>,
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let idx = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (true) {
      const current = idx++;
      if (current >= items.length) return;
      results[current] = await fn(items[current]);
    }
  });
  await Promise.all(workers);
  return results;
}

export async function revokeBatchAttestations(
  attestationIds: string[],
  adminId: string,
): Promise<RevokeBatchResult> {
  if (!attestationIds || attestationIds.length === 0) {
    throw new Error("No attestations provided for revocation.");
  }
  if (attestationIds.length > MAX_BATCH_SIZE) {
    throw new Error("Batch size capped at 500");
  }

  const sourceSecret = process.env.SOROBAN_SOURCE_SECRET;
  if (!sourceSecret) {
    throw new Error(
      "SOROBAN_SOURCE_SECRET is not configured; cannot revoke attestations on-chain.",
    );
  }

  const { contractId, networkPassphrase, rpcUrl } = getSorobanConfig();
  const server = createSorobanRpcServer(rpcUrl);
  const signer = Keypair.fromSecret(sourceSecret);

  const pg = getPgClient();
  const client = await pg.getClient();

  try {
    await client.query("BEGIN");

    // Load and validate all attestations first
    const attestations = [];
    for (const id of attestationIds) {
      const att = await getById(client, id);
      if (!att) {
        throw new Error(`Attestation not found: ${id}`);
      }
      if (att.status === "revoked") {
        throw new Error(`Attestation ${id} is already revoked`);
      }
      attestations.push(att);
    }

    // Submit one Soroban tx per attestation with bounded concurrency
    const outcomes = await runWithConcurrency(
      attestations,
      CONCURRENCY,
      async (att) => {
        try {
          await revokeOnChain(
            server,
            contractId,
            networkPassphrase,
            signer,
            att,
          );
          return { id: att.id, ok: true as const };
        } catch (err) {
          const message = err instanceof Error ? err.message : String(err);
          return { id: att.id, ok: false as const, error: message };
        }
      },
    );

    const revoked: string[] = [];
    const failed: Array<{ id: string; error: string }> = [];

    for (const outcome of outcomes) {
      if (outcome.ok) {
        await updateStatus(client, outcome.id, "revoked");
        await createAuditLog(
          {
            userId: adminId,
            action: "REVOKE_ATTESTATION",
            resource: "attestation",
            resourceId: outcome.id,
            metadata: { outcome: "success", batch: true },
          },
          client,
        );
        revoked.push(outcome.id);
      } else {
        failed.push({ id: outcome.id, error: outcome.error });
      }
    }

    await client.query("COMMIT");
    return { revoked, failed };
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}
