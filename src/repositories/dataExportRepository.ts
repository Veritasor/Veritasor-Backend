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
 * Verify and consume download token (one-time use)
 */
export async function consumeDownloadToken(token: string): Promise<string | null> {
  const client = getRedisClient()
  const tokenKey = `${TOKEN_KEY_PREFIX}${token}`

  const data = await redisCircuitBreaker.execute(() => client.get(tokenKey))
  if (!data) return null

  const tokenData = JSON.parse(data)

  // Check if already downloaded
  if (tokenData.downloaded) {
    return null
  }

  // Mark as downloaded
  tokenData.downloaded = true
  await redisCircuitBreaker.execute(() => client.set(tokenKey, JSON.stringify(tokenData)))

  return tokenData.exportId
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
