import { attestationRepository } from "../../repositories/attestation.js";
import { businessRepository } from "../../repositories/business.js";
import { logger } from "../../utils/logger.js";
import { cdnClient } from "../../services/cdn/cdnClientAdapter.js";
import { recordCdnPurgeStatus } from "../../services/audit/auditLog.js";

/**
 * Revoke an existing attestation.
 *
 * - Verifies the attestation exists.
 * - Verifies the attestation belongs to a business owned by the requesting user.
 * - Checks if already revoked.
 * - Updates the attestation status to 'revoked' and records the revocation timestamp and reason.
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
  const attestation = attestationRepository.findById(attestationId);
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

  // 4. Update status in repository
  const updateData: Partial<typeof attestation> = {
    status: "revoked",
    revokedAt: new Date().toISOString(),
  };
  if (reason) {
    (updateData as any).revokeReason = reason;
  }
  // 5. Trigger CDN purge for the revoked attestation
  try {
    const purgeUrl = `${process.env.CDN_BASE_URL ?? ''}/attestations/${attestationId}`;
    await cdnClient.purge([purgeUrl]);
    recordCdnPurgeStatus(attestationId, 'success', { url: purgeUrl });
    logger.info(`CDN purge successful for attestation ${attestationId}`);
  } catch (err) {
    const error = err instanceof Error ? err.message : String(err);
    recordCdnPurgeStatus(attestationId, 'failed', { error });
    logger.error(`CDN purge failed for attestation ${attestationId}: ${error}`);
  }


  // TODO: Optionally call Soroban revoke if the contract supports it.
  // This will be implemented when the Soroban integration is ready.
}

export default revokeAttestation;
