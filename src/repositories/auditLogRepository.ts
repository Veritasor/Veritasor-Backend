/**
 * src/repositories/auditLogRepository.ts
 *
 * In-memory audit-log store with a tamper-evident hash chain.
 *
 * How the chain works
 * ===================
 * Each entry carries a `chainHash` that is a SHA-256 HMAC over a
 * canonical representation of that entry's immutable fields PLUS the
 * previous entry's `chainHash` (or the GENESIS constant for the first
 * entry).  This forms a linked list whose integrity can be verified by
 * recomputing every hash in sequence.
 *
 *   chainHash[0] = HMAC( GENESIS_SENTINEL || entry[0] )
 *   chainHash[N] = HMAC( chainHash[N-1]   || entry[N] )
 *
 * Tampering with any field, or re-ordering entries, or deleting an entry
 * causes the chain to break at that position.  The `verifyChain()` export
 * returns the exact index and entry ID where the break was detected.
 *
 * Concurrent-insert ordering
 * ==========================
 * Because JavaScript is single-threaded, `push` to the in-memory array is
 * atomic from the caller's perspective.  The `chainHash` of each entry
 * depends only on the hash of the entry immediately before it in insertion
 * order, so the chain is deterministic regardless of timestamp precision.
 *
 * Chain anchor
 * ============
 * `getCurrentChainRoot()` returns the hash of the most-recent entry.
 * An external anchor job (`src/jobs/auditAnchorJob.ts`) calls this every
 * hour and emits the root to an off-system sink (log, external service).
 * If the root stored in the anchor log ever disagrees with the
 * recomputed root, the discrepancy is evidence of tampering.
 *
 * HMAC key
 * ========
 * The key is read from the `AUDIT_CHAIN_SECRET` environment variable.
 * In production, inject this from a secrets manager.  In tests the
 * module falls back to a fixed test key so the test environment does not
 * need a real secret.
 */

import crypto, { randomBytes } from 'node:crypto'
import { decodeCursor, encodeCursor } from '../utils/pagination.js'
import { computePayloadHash } from '../services/webhooks/deadLetterQueue.js'

// ---------------------------------------------------------------------------
// Chain constants
// ---------------------------------------------------------------------------

/**
 * Sentinel value used as "previous hash" for the very first entry.
 * Changing this value invalidates every existing chain, so it must
 * never change in production.
 */
export const GENESIS_SENTINEL = '0000000000000000000000000000000000000000000000000000000000000000'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface AuditLog {
  id: string
  userId: string
  action: string
  resource: string
  resourceId?: string
  metadata?: any
  contentHash?: string
  timestamp: Date
  /** SHA-256 HMAC over (prevHash || canonicalEntry).  Present on every entry after creation. */
  chainHash: string
  /** Sequential position in insertion order (0-based). Used for faster gap detection. */
  seq: number
}

export type AuditLogInput = Omit<AuditLog, 'id' | 'timestamp' | 'chainHash' | 'seq'>

export type AuditLogQuery = {
  actorId?: string
  action?: string
  resource?: string
  from?: Date
  to?: Date
  limit?: number
  cursor?: string
}

export interface PaginatedAuditResult {
  data: AuditLog[]
  nextCursor: string | null
  hasMore: boolean
}

export interface ChainVerificationResult {
  valid: boolean
  /** Number of entries verified before a break was found (or total length if valid). */
  checkedCount: number
  /** Index of the first broken entry, or null if the chain is intact. */
  brokenAtIndex: number | null
  /** ID of the first broken entry, or null if the chain is intact. */
  brokenAtId: string | null
  /** Current chain root (hash of the last entry), or null if the log is empty. */
  chainRoot: string | null
}

// ---------------------------------------------------------------------------
// HMAC key
// ---------------------------------------------------------------------------

function getChainKey(): Buffer {
  const secret = process.env.AUDIT_CHAIN_SECRET
  if (!secret) {
    // Fall back to a deterministic test key so unit tests don't fail when the
    // env var is absent.  Do NOT use this path in production – set the env var.
    return Buffer.from('veritasor-audit-chain-test-key-do-not-use-in-production')
  }
  return Buffer.from(secret, 'utf-8')
}

// ---------------------------------------------------------------------------
// Canonical entry serialisation
// ---------------------------------------------------------------------------

/**
 * Build the canonical string representation of an entry for HMAC input.
 *
 * Only immutable fields are included.  `metadata` is intentionally included
 * so that post-hoc metadata edits are detectable.  The format is stable and
 * must not be changed without migrating all existing chain hashes.
 *
 * Format (pipe-delimited, no whitespace):
 *   seq|id|userId|action|resource|resourceId|contentHash|timestamp_iso|metadata_sha256
 */
export function canonicaliseEntry(entry: Omit<AuditLog, 'chainHash'>): string {
  const metaHash = entry.metadata
    ? crypto.createHash('sha256').update(JSON.stringify(entry.metadata)).digest('hex')
    : ''

  return [
    entry.seq,
    entry.id,
    entry.userId,
    entry.action,
    entry.resource,
    entry.resourceId ?? '',
    entry.contentHash ?? '',
    entry.timestamp.toISOString(),
    metaHash,
  ].join('|')
}

/**
 * Compute the HMAC-SHA-256 chain hash for an entry given the previous hash.
 */
export function computeChainHash(
  entry: Omit<AuditLog, 'chainHash'>,
  prevHash: string
): string {
  const data = prevHash + '|' + canonicaliseEntry(entry)
  return crypto
    .createHmac('sha256', getChainKey())
    .update(data)
    .digest('hex')
}

// ---------------------------------------------------------------------------
// In-memory store
// ---------------------------------------------------------------------------

const auditLogs: AuditLog[] = []

// ---------------------------------------------------------------------------
// Write API
// ---------------------------------------------------------------------------

/**
 * Create a new audit log entry and append it to the chain.
 *
 * The `chainHash` is computed over the previous entry's `chainHash` (or
 * GENESIS_SENTINEL for the first entry) and the canonical representation of
 * the new entry.
 */
export async function createAuditLog(
  log: AuditLogInput,
  content?: any
): Promise<AuditLog> {
  const id = randomBytes(16).toString('hex')
  const timestamp = new Date()
  const seq = auditLogs.length
  const prevHash = auditLogs.length > 0
    ? auditLogs[auditLogs.length - 1].chainHash
    : GENESIS_SENTINEL

  const partial: Omit<AuditLog, 'chainHash'> = {
    ...log,
    id,
    timestamp,
    seq,
    contentHash: content ? computePayloadHash(content) : log.contentHash,
  }

  const chainHash = computeChainHash(partial, prevHash)

  const newLog: AuditLog = { ...partial, chainHash }
  auditLogs.push(newLog)
  return newLog
}

// ---------------------------------------------------------------------------
// Read API
// ---------------------------------------------------------------------------

/**
 * Get all audit logs in reverse-chronological order (most recent first).
 */
export async function getAllAuditLogs(): Promise<AuditLog[]> {
  return [...auditLogs].sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
}

/**
 * Query audit logs with optional filters and cursor pagination.
 * Cursor format: base64(JSON.stringify({ value: created_at_iso, id }))
 */
export async function queryAuditLogs(query: AuditLogQuery): Promise<PaginatedAuditResult> {
  const { actorId, action, resource, from, to } = query
  let limit = Number(query.limit || 20)
  if (!Number.isInteger(limit) || limit <= 0) limit = 20
  limit = Math.min(100, limit)

  let cursorTs: number | undefined
  let cursorId: string | undefined

  const decodedCursor = decodeCursor(query.cursor)
  if (decodedCursor) {
    const d = new Date(decodedCursor.value)
    if (!Number.isNaN(d.getTime())) {
      cursorTs = d.getTime()
      cursorId = decodedCursor.id
    }
  }

  let rows = auditLogs.slice()
  if (actorId) rows = rows.filter(r => r.userId === actorId)
  if (action)  rows = rows.filter(r => r.action === action)
  if (resource) rows = rows.filter(r => r.resource === resource)
  if (from)    rows = rows.filter(r => r.timestamp.getTime() >= from.getTime())
  if (to)      rows = rows.filter(r => r.timestamp.getTime() <= to.getTime())

  rows.sort((a, b) => {
    const ta = a.timestamp.getTime()
    const tb = b.timestamp.getTime()
    if (ta !== tb) return tb - ta
    return b.id.localeCompare(a.id)
  })

  if (typeof cursorTs === 'number' && cursorId) {
    rows = rows.filter(r => {
      const t = r.timestamp.getTime()
      if (t < cursorTs!) return true
      if (t === cursorTs! && r.id < cursorId!) return true
      return false
    })
  }

  const hasMore = rows.length > limit
  const slice = rows.slice(0, Math.min(limit, 100))

  let nextCursor: string | null = null
  if (hasMore && slice.length > 0) {
    const last = slice[slice.length - 1]
    nextCursor = encodeCursor({ value: last.timestamp.toISOString(), id: last.id })
  }

  return { data: slice, nextCursor, hasMore }
}

/**
 * Get audit logs for a specific user in reverse-chronological order.
 */
export async function getAuditLogsByUser(userId: string): Promise<AuditLog[]> {
  return auditLogs
    .filter(log => log.userId === userId)
    .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
}

// ---------------------------------------------------------------------------
// Chain verification
// ---------------------------------------------------------------------------

/**
 * Verify the integrity of the entire audit-log chain.
 *
 * Iterates over entries in insertion order (ascending seq) and recomputes
 * each chainHash.  Returns on the first mismatch so callers get the exact
 * position of tampering.
 *
 * Time complexity: O(N) where N is the total number of log entries.
 */
export function verifyChain(entries?: AuditLog[]): ChainVerificationResult {
  const logs = entries ?? auditLogs

  if (logs.length === 0) {
    return {
      valid: true,
      checkedCount: 0,
      brokenAtIndex: null,
      brokenAtId: null,
      chainRoot: null,
    }
  }

  // Work on an insertion-order sorted copy.
  const ordered = [...logs].sort((a, b) => a.seq - b.seq)

  let prevHash = GENESIS_SENTINEL

  for (let i = 0; i < ordered.length; i++) {
    const entry = ordered[i]
    const { chainHash, ...rest } = entry
    const expected = computeChainHash(rest as Omit<AuditLog, 'chainHash'>, prevHash)

    if (!crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(chainHash, 'hex'))) {
      return {
        valid: false,
        checkedCount: i,
        brokenAtIndex: i,
        brokenAtId: entry.id,
        chainRoot: ordered[ordered.length - 1].chainHash,
      }
    }

    prevHash = chainHash
  }

  return {
    valid: true,
    checkedCount: ordered.length,
    brokenAtIndex: null,
    brokenAtId: null,
    chainRoot: ordered[ordered.length - 1].chainHash,
  }
}

/**
 * Return the current chain root – the chainHash of the most-recently
 * inserted entry.  Returns null when the log is empty.
 *
 * The anchor job calls this every hour and persists the value off-system.
 */
export function getCurrentChainRoot(): string | null {
  if (auditLogs.length === 0) return null
  return auditLogs[auditLogs.length - 1].chainHash
}

// ---------------------------------------------------------------------------
// Testing utilities
// ---------------------------------------------------------------------------

/**
 * Clear all audit logs (testing only).
 */
export function clearAllAuditLogs(): void {
  auditLogs.length = 0
}
