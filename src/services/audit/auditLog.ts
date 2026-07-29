// src/services/audit/auditLog.ts

import { logger } from "../utils/logger.js";

export type PurgeStatus = "queued" | "success" | "failed";

/**
 * Record CDN purge status in audit logs.
 * For now, this simply logs via the standard logger. In a real system,
 * this could write to a dedicated audit database or external service.
 */
export function recordCdnPurgeStatus(attestationId: string, status: PurgeStatus, details?: any): void {
  logger.info({ attestationId, status, details }, "cdn-purge-status");
}
