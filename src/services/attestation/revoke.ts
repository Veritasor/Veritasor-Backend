import * as attestationRepository from "../../repositories/attestationRepository.js";
import { db } from "../../db/client.js";
import { businessRepository } from "../../repositories/business.js";
import { logger } from "../../utils/logger.js";
import { cdnClient } from "../../services/cdn/cdnClientAdapter.js";
import { recordCdnPurgeStatus } from "../../services/audit/auditLog.js";
import { createAuditLog } from "../../repositories/auditLogRepository.js";
import { FlagKeys, getBooleanFlag } from "../features/flags.js";
import { revokeAttestationOnChain } from "../soroban/submitAttestation.js";

/**
 * Revoke an existing attestation.
 *
 * - Verifies the attestation exists.
 * - Verifies the attestation belongs to a business owned by the requesting user.
 * - Checks if already revoked.
 * - Persists the revoked status with optimistic locking before purging cached data.
 *
 * @param attestationId - The ID of the attestation to revoke.
 * @param userId - The ID of the user requesting the revocation.
 * @param reason - Optional reason for revocation.
 * @throws {Error} If the attestation is not found, already revoked, or the user is not authorised.
 */
export async function revokeAttestation(
  attestationId: string,
  userId: string,
  reason?: string,
): Promise<void> {
  // 1. Look up attestation
  const attestation = await attestationRepository.getById(db, attestationId);
  if (!attestation) {
    throw new Error(`Attestation not found: ${attestationId}`);
  }

  // 2. Verify ownership — the attestation's business must belong to the user
  const business = await businessRepository.findById(attestation.businessId);
  if (!business || business.userId !== userId) {
    throw new Error(
      "Unauthorized: attestation does not belong to your business",
    );
  }

  // 3. Check if already revoked
  if (attestation.status === "revoked") {
    throw new Error(`Attestation ${attestationId} is already revoked`);
  }

  // 4. Update status in repository before external side effects.
  const updateData: Partial<typeof attestation> = {
    status: "revoked",
    revokedAt: new Date().toISOString(),
  };
  if (reason) {
    updateData.revokeReason = reason;
  // 4. Update status in repository
  const updated = await attestationRepository.updateStatus(
    db, attestationId, 'revoked', attestation.version,
  );
  if (!updated) {
    throw new Error(`Attestation not found: ${attestationId}`);
  }
  const updatedAttestation = attestationRepository.update(attestationId, updateData);
  if (!updatedAttestation) {
    throw new Error(`Failed to update attestation ${attestationId}`);
  }

  // 5. Trigger CDN purge for the revoked attestation
  try {
    const purgeUrl = `${process.env.CDN_BASE_URL ?? ''}/attestations/${attestationId}`;
    await cdnClient.purge([purgeUrl]);
    recordCdnPurgeStatus(attestationId, 'success', { url: purgeUrl, reason });
    logger.info(`CDN purge successful for attestation ${attestationId}`);
  } catch (err) {
    const error = err instanceof Error ? err.message : String(err);
    recordCdnPurgeStatus(attestationId, 'failed', { error: error });
    logger.error(`CDN purge failed for attestation ${attestationId}: ${error}`);
  }

  const revokeOnChain = await getBooleanFlag(
    FlagKeys.SOROBAN_ATTESTATION_REVOCATION,
    false,
    { businessId: attestation.businessId, userId },
  );
  if (!revokeOnChain) {
    return;
  }

  try {
    if (!attestation.period) {
      throw new Error(`Attestation ${attestationId} has no period for Soroban revocation`);
    }

    const txHash = await revokeAttestationOnChain({
      business: attestation.businessId,
      period: attestation.period,
    });
    const hashUpdate = attestationRepository.update(attestationId, { revokeTxHash: txHash });
    if (!hashUpdate) {
      logger.error(
        { attestationId, txHash },
        "Soroban revocation succeeded but its transaction hash could not be persisted",
      );
    }
  } catch (err) {
    const error = err instanceof Error ? err.message : String(err);
    logger.error(
      { attestationId, error },
      "Soroban revocation failed; local revocation remains in effect",
    );

    try {
      await createAuditLog({
        userId,
        action: "ATTESTATION_REVOKE_RETRY_QUEUED",
        resource: "attestation",
        resourceId: attestationId,
        metadata: {
          businessId: attestation.businessId,
          period: attestation.period,
          reason: error,
        },
      });
    } catch (enqueueError) {
      logger.error(
        {
          attestationId,
          error: enqueueError instanceof Error
            ? enqueueError.message
            : String(enqueueError),
        },
        "Failed to enqueue Soroban attestation revocation retry",
      );
    }
  }
}

export default revokeAttestation;
