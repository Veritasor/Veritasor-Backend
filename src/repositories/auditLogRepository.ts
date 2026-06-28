import { randomBytes } from 'crypto'
import { decodeCursor, encodeCursor } from '../utils/pagination.js'
import { computePayloadHash } from '../services/webhooks/deadLetterQueue.js'

export interface AuditLog {
  id: string
  userId: string
  action: string
  resource: string
  resourceId?: string
  metadata?: any
  contentHash?: string
  timestamp: Date
}

const auditLogs: AuditLog[] = []

/**
 * Create a new audit log entry
 */
export async function createAuditLog(
  log: Omit<AuditLog, 'id' | 'timestamp'>,
  content?: any
): Promise<AuditLog> {
  const newLog: AuditLog = {
    ...log,
    id: randomBytes(16).toString('hex'),
    timestamp: new Date(),
    contentHash: content ? computePayloadHash(content) : log.contentHash,
  }
  auditLogs.push(newLog)
  return newLog
}

/**
 * Get all audit logs (admin only)
 */
export async function getAllAuditLogs(): Promise<AuditLog[]> {
  return [...auditLogs].sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
}

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

  // Apply filters
  let rows = auditLogs.slice()
  if (actorId) {
    rows = rows.filter(r => r.userId === actorId)
  }
  if (action) {
    rows = rows.filter(r => r.action === action)
  }
  if (resource) {
    rows = rows.filter(r => r.resource === resource)
  }
  if (from) {
    rows = rows.filter(r => r.timestamp.getTime() >= from.getTime())
  }
  if (to) {
    rows = rows.filter(r => r.timestamp.getTime() <= to.getTime())
  }

  // Stable ordering: timestamp DESC, id DESC
  rows.sort((a, b) => {
    const ta = a.timestamp.getTime()
    const tb = b.timestamp.getTime()
    if (ta !== tb) return tb - ta
    return b.id.localeCompare(a.id)
  })

  // Apply cursor: return items after the cursor (older entries)
  if (typeof cursorTs === 'number' && cursorId) {
    rows = rows.filter(r => {
      const t = r.timestamp.getTime()
      if (t < cursorTs) return true
      if (t === cursorTs && r.id < cursorId) return true
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
 * Get audit logs for a specific user
 */
export async function getAuditLogsByUser(userId: string): Promise<AuditLog[]> {
  return auditLogs.filter(log => log.userId === userId).sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
}

/**
 * Clear all audit logs (testing only)
 */
export function clearAllAuditLogs(): void {
  auditLogs.length = 0
}
