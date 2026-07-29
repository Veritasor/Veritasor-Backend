/**
 * src/jobs/auditAnchorJob.ts
 *
 * Hourly chain-root anchor job.
 *
 * Purpose
 * -------
 * The in-memory audit-log chain can be verified internally, but an attacker
 * who controls the process could rewrite both the logs and their hashes
 * simultaneously.  To make that detectable, this job periodically emits the
 * current chain root to an off-system sink (structured log line, external
 * HTTP endpoint, etc.).  A later chain verification can then compare the
 * current root against the previously anchored value.
 *
 * Architecture
 * ------------
 *   1.  `anchorChainRoot()` – emits the current root synchronously.
 *       Returns the root string (or null for an empty chain).
 *   2.  `createAuditAnchorJob(options)` – creates a scheduled interval
 *       that calls `anchorChainRoot()` every `intervalMs` milliseconds
 *       (default: 1 hour).  The interval is `unref()`'d so it does not
 *       block process exit.
 *   3.  The job writes to the structured logger; in production, ship the
 *       log to an append-only sink (e.g. CloudWatch Logs, Datadog, S3
 *       with object lock) that is separate from the application database.
 *
 * Integration
 * -----------
 * Start the job from `src/index.ts` after the server is listening:
 *
 *   import { createAuditAnchorJob } from './jobs/auditAnchorJob.js'
 *   const anchorJob = createAuditAnchorJob()
 *   // Stop it during graceful shutdown:
 *   anchorJob.stop()
 *
 * Concurrent-insert safety
 * ------------------------
 * Because JavaScript is single-threaded, `getCurrentChainRoot()` returns a
 * snapshot of the latest inserted entry's hash.  Entries inserted while the
 * anchor callback runs are not included in the emitted root, but they will be
 * captured in the next cycle.
 */

import { logger } from '../utils/logger.js'
import {
  getCurrentChainRoot,
  verifyChain,
} from '../repositories/auditLogRepository.js'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface AnchorRecord {
  /** ISO 8601 timestamp when the anchor was taken. */
  anchoredAt: string
  /** SHA-256 HMAC chain root of the last inserted entry, or null for an empty chain. */
  chainRoot: string | null
  /** Total number of entries in the chain at the time of anchoring. */
  entryCount: number
  /** Whether the chain was intact at the time of anchoring. */
  chainValid: boolean
}

export interface AuditAnchorJob {
  /** Stop the periodic anchor job. */
  stop(): void
  /** Fire one anchor immediately (useful for graceful shutdown). */
  flush(): AnchorRecord
}

// ---------------------------------------------------------------------------
// Core anchor function
// ---------------------------------------------------------------------------

/**
 * Compute the current chain root, verify the chain, and emit an anchor record
 * to the structured logger.
 *
 * Returns the AnchorRecord so callers can inspect or forward it.
 */
export function anchorChainRoot(): AnchorRecord {
  const verification = verifyChain()
  const record: AnchorRecord = {
    anchoredAt: new Date().toISOString(),
    chainRoot:  verification.chainRoot,
    entryCount: verification.checkedCount,
    chainValid: verification.valid,
  }

  if (!verification.valid) {
    logger.error(
      {
        event:          'audit_chain_anchor',
        chainRoot:      record.chainRoot,
        entryCount:     record.entryCount,
        chainValid:     false,
        brokenAtIndex:  verification.brokenAtIndex,
        brokenAtId:     verification.brokenAtId,
      },
      'AUDIT CHAIN INTEGRITY VIOLATION – chain is broken; investigate immediately'
    )
  } else {
    logger.info(
      {
        event:      'audit_chain_anchor',
        chainRoot:  record.chainRoot,
        entryCount: record.entryCount,
        chainValid: true,
      },
      'Audit chain root anchored'
    )
  }

  return record
}

// ---------------------------------------------------------------------------
// Scheduled job factory
// ---------------------------------------------------------------------------

const DEFAULT_INTERVAL_MS = 60 * 60 * 1000 // 1 hour

/**
 * Create a periodic audit-chain anchor job.
 *
 * @param options.intervalMs   Interval between anchor emissions (default: 1 h).
 * @param options.runImmediately  Emit one anchor immediately on creation (default: false).
 */
export function createAuditAnchorJob(options: {
  intervalMs?: number
  runImmediately?: boolean
} = {}): AuditAnchorJob {
  const intervalMs = options.intervalMs ?? DEFAULT_INTERVAL_MS

  if (options.runImmediately) {
    anchorChainRoot()
  }

  const timer = setInterval(() => {
    anchorChainRoot()
  }, intervalMs)

  // Unref so the timer does not block process exit.
  if (timer.unref) timer.unref()

  return {
    stop(): void {
      clearInterval(timer)
    },
    flush(): AnchorRecord {
      return anchorChainRoot()
    },
  }
}
