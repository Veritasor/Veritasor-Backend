import { db } from "../../db/client.js";
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

/**
 * Revokes multiple attestations in a single transaction on both DB and Soroban.
 * Batch size is capped at 500.
 */
export async function revokeBatchAttestations(
  attestationIds: string[],
  adminId: string,
) {
  if (!attestationIds || attestationIds.length === 0) {
    throw new Error("No attestations provided for revocation.");
  }
  if (attestationIds.length > 500) {
    throw new Error("Batch size capped at 500");
  }

  const client = await db.connect();
  try {
    await client.query("BEGIN");

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

      await updateStatus(client, id, "revoked");
      await createAuditLog({
        userId: adminId,
        action: "REVOKE_ATTESTATION",
        resource: "attestation",
        resourceId: id,
        metadata: { outcome: "success", batch: true },
      });
    }

    // Attempt Soroban multi-operation transaction
    const { contractId, networkPassphrase, rpcUrl } = getSorobanConfig();
    const server = createSorobanRpcServer(rpcUrl);
    const sourceSecret = process.env.SOROBAN_SOURCE_SECRET;

    if (sourceSecret && attestations.length > 0) {
      const signer = Keypair.fromSecret(sourceSecret);
      const account = await server.getAccount(signer.publicKey());
      const contract = new Contract(contractId);

      const builder = new TransactionBuilder(account, {
        fee: (Number.parseInt(BASE_FEE, 10) * attestations.length).toString(),
        networkPassphrase,
      });

      for (const att of attestations) {
        builder.addOperation(
          contract.call(
            "revoke_attestation",
            nativeToScVal(att.businessId),
            nativeToScVal(att.period),
          ),
        );
      }

      const tx = builder.setTimeout(30).build();
      const prepared = await server.prepareTransaction(tx);
      prepared.sign(signer);

      const response = await server.sendTransaction(prepared);
      validateSendTransactionResponse(response);

      if (
        response.status === "ERROR" ||
        response.status === "TRY_AGAIN_LATER"
      ) {
        throw new SorobanSubmissionError(
          "Failed to submit batch revoke",
          "SUBMIT_FAILED",
          response,
        );
      }

      await waitForConfirmation(server, response.hash);
    }

    await client.query("COMMIT");
    return attestations;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}
