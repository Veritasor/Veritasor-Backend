// src/jobs/purgeCdnJob.ts

import { cdnClient } from "../services/cdn/cdnClientAdapter.js";
import { logger } from "../utils/logger.js";
import { recordCdnPurgeStatus } from "../services/audit/auditLog.js";

/**
 * Enqueue a CDN purge for a given attestation.
 * In this implementation we perform the purge immediately.
 * In a real system this would add a job to a background queue
 * (e.g., BullMQ) to be processed asynchronously.
 */
export async function enqueueCdnPurge(attestationId: string, purgeUrl: string): Promise<void> {
  try {
    await cdnClient.purge([purgeUrl]);
    recordCdnPurgeStatus(attestationId, "success", { url: purgeUrl });
    logger.info(`CDN purge successful for attestation ${attestationId}`);
  } catch (err) {
    const error = err instanceof Error ? err.message : String(err);
    recordCdnPurgeStatus(attestationId, "failed", { error });
    logger.error(`CDN purge failed for attestation ${attestationId}: ${error}`);
  }
}
