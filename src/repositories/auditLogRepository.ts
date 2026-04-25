import { randomBytes } from 'crypto'

export interface AuditLog {
  id: string
  userId: string
  action: string
  resource: string
  resourceId?: string
  metadata?: any
  timestamp: Date
}

const auditLogs: AuditLog[] = []

/**
 * Create a new audit log entry
 */
export async function createAuditLog(log: Omit<AuditLog, 'id' | 'timestamp'>): Promise<AuditLog> {
  const newLog: AuditLog = {
    ...log,
    id: randomBytes(16).toString('hex'),
    timestamp: new Date(),
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
