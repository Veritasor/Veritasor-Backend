import { randomBytes } from 'node:crypto'
import { getRedisClient, redisCircuitBreaker, type RedisClient } from '../redis.js'

export interface DataExport {
  id: string
  userId: string
  status: 'pending' | 'processing' | 'completed' | 'failed'
  createdAt: Date
  completedAt?: Date
  expiresAt: Date
  downloadedAt?: Date
  error?: string
  archiveSize?: number
}

export interface DataExportToken {
  exportId: string
  token: string
  oneTimeDownload: boolean
}

const EXPORT_TTL_SECONDS = 7 * 24 * 60 * 60 // 7 days
const EXPORT_KEY_PREFIX = 'data-export:'
const TOKEN_KEY_PREFIX = 'data-export-token:'

/**
 * Create a new data export job
 */
export async function createDataExport(userId: string): Promise<DataExport> {
  const now = new Date()
  const expiresAt = new Date(now.getTime() + EXPORT_TTL_SECONDS * 1000)

  const exportId = randomBytes(16).toString('hex')
  const exportRecord: DataExport = {
    id: exportId,
    userId,
    status: 'pending',
    createdAt: now,
    expiresAt,
  }

  const client = getRedisClient()
  const key = `${EXPORT_KEY_PREFIX}${exportId}`

  await redisCircuitBreaker.execute(() => client.setex(
    key,
    EXPORT_TTL_SECONDS,
    JSON.stringify(exportRecord)
  ))

  return exportRecord
}

/**
 * Get export by ID
 */
export async function getDataExport(exportId: string): Promise<DataExport | null> {
  const client = getRedisClient()
  const key = `${EXPORT_KEY_PREFIX}${exportId}`

  const data = await redisCircuitBreaker.execute(() => client.get(key))
  if (!data) return null

  return JSON.parse(data)
}

/**
 * Get export by ID, only if it belongs to the given user
 */
export async function getExportForUser(exportId: string, userId: string): Promise<DataExport | null> {
  const exportRecord = await getDataExport(exportId)
  if (!exportRecord) return null
  if (exportRecord.userId !== userId) return null
  return exportRecord
}

/**
 * Update export status
 */
export async function updateDataExportStatus(
  exportId: string,
  status: DataExport['status'],
  updates?: Partial<DataExport>
): Promise<DataExport | null> {
  const client = getRedisClient()
  const key = `${EXPORT_KEY_PREFIX}${exportId}`

  const existing = await getDataExport(exportId)
  if (!existing) return null

  const updated: DataExport = {
    ...existing,
    status,
    ...updates,
    completedAt: status === 'completed' || status === 'failed' ? new Date() : existing.completedAt,
  }

  await redisCircuitBreaker.execute(() => client.setex(
    key,
    EXPORT_TTL_SECONDS,
    JSON.stringify(updated)
  ))

  return updated
}

/**
 * Generate a download token for the export
 */
export async function createDownloadToken(exportId: string): Promise<string> {
  const client = getRedisClient()
  const token = randomBytes(32).toString('hex')
  const tokenKey = `${TOKEN_KEY_PREFIX}${token}`

  // Token expires after 24 hours or on first download
  await redisCircuitBreaker.execute(() => client.setex(
    tokenKey,
    24 * 60 * 60,
    JSON.stringify({ exportId, downloaded: false })
  ))

  return token
}

/**
 * Read the export id behind a download token without consuming it.
 */
export async function peekDownloadToken(token: string): Promise<string | null> {
  const client = getRedisClient()
  const tokenKey = `${TOKEN_KEY_PREFIX}${token}`

  const data = await redisCircuitBreaker.execute(() => client.get(tokenKey))
  if (!data) return null

  const tokenData = JSON.parse(data)
  if (tokenData.downloaded) return null

  return tokenData.exportId
}

/**
 * Verify and consume download token (one-time use)
 */
export async function consumeDownloadToken(token: string): Promise<string | null> {
  const client = getRedisClient()
  const tokenKey = `${TOKEN_KEY_PREFIX}${token}`

  const script = `local value = redis.call('GET', KEYS[1]); if not value then return nil end; local data = cjson.decode(value); if data.downloaded then return nil end; data.downloaded = true; redis.call('SET', KEYS[1], cjson.encode(data), 'KEEPTTL'); return data.exportId`
  const result = await redisCircuitBreaker.execute(() => client.eval(script, 1, tokenKey))
  return typeof result === 'string' ? result : null
}

/** Read the export ID without consuming the one-time token. */
export async function peekDownloadToken(token: string): Promise<string | null> {
  const client = getRedisClient()
  const data = await redisCircuitBreaker.execute(() => client.get(`${TOKEN_KEY_PREFIX}${token}`))
  if (!data) return null
  const parsed = JSON.parse(data)
  return parsed.downloaded ? null : parsed.exportId
}

/**
 * Get export for user
 */
export async function getUserDataExports(userId: string): Promise<DataExport[]> {
  // In a production system, you'd maintain an index.
  // For this implementation, we'll scan or use a simple approach.
  // This is a simplified version; in production, use Redis streams or a database.
  const client = getRedisClient()

  // For demonstration, return empty since we don't have an index
  // In production, you'd query a database or maintain a set of export IDs per user
  return []
}

/**
 * Delete export (cleanup)
 */
export async function deleteDataExport(exportId: string): Promise<boolean> {
  const client = getRedisClient()
  const key = `${EXPORT_KEY_PREFIX}${exportId}`

  const result = await redisCircuitBreaker.execute(() => client.del(key))
  return result > 0
}
