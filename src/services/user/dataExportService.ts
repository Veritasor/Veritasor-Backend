import { getRedisClient } from '../../redis.js'
import { logger } from '../../utils/logger.js'
import {
  createDataExport,
  updateDataExportStatus,
  createDownloadToken,
  getDataExport,
} from '../../repositories/dataExportRepository.js'
import { createGdprExport } from './createGdprExport.js'

const ARCHIVE_KEY_PREFIX = 'data-export-archive:'
const ARCHIVE_TTL_SECONDS = 7 * 24 * 60 * 60 // 7 days

export interface ExportResponse {
  exportId: string
  status: 'pending' | 'processing' | 'completed' | 'failed'
  downloadToken?: string
  expiresAt: string
  createdAt: string
}

/**
 * Initiate a GDPR data export for a user
 */
export async function initiateDataExport(userId: string): Promise<ExportResponse> {
  try {
    // Create export job
    const exportJob = await createDataExport(userId)

    // Queue the export processing asynchronously
    // In production, this would be sent to Kafka or a background job queue
    processExportAsync(userId, exportJob.id).catch(err => {
      logger.error('Failed to process export', { userId, exportId: exportJob.id, error: err })
    })

    return {
      exportId: exportJob.id,
      status: exportJob.status,
      expiresAt: exportJob.expiresAt.toISOString(),
      createdAt: exportJob.createdAt.toISOString(),
    }
  } catch (err) {
    logger.error('Failed to initiate data export', { userId, error: err })
    throw err
  }
}

/**
 * Get export status
 */
export async function getExportStatus(exportId: string): Promise<ExportResponse | null> {
  try {
    const exportJob = await getDataExport(exportId)
    if (!exportJob) return null

    // Handle dates from Redis (they come as strings from JSON.parse)
    const expiresAt = typeof exportJob.expiresAt === 'string'
      ? exportJob.expiresAt
      : exportJob.expiresAt.toISOString()
    const createdAt = typeof exportJob.createdAt === 'string'
      ? exportJob.createdAt
      : exportJob.createdAt.toISOString()

    let response: ExportResponse = {
      exportId: exportJob.id,
      status: exportJob.status,
      expiresAt,
      createdAt,
    }

    // If completed, generate download token
    if (exportJob.status === 'completed') {
      const downloadToken = await createDownloadToken(exportJob.id)
      response.downloadToken = downloadToken
    }

    return response
  } catch (err) {
    logger.error('Failed to get export status', { exportId, error: err })
    throw err
  }
}

/**
 * Get export archive for download
 */
export async function getExportArchive(exportId: string): Promise<Buffer | null> {
  try {
    const client = getRedisClient()
    const key = `${ARCHIVE_KEY_PREFIX}${exportId}`

    const data = await client.get(key)
    if (!data) return null

    // Parse the stored export data
    const archived = JSON.parse(data)
    return Buffer.from(archived.buffer, 'base64')
  } catch (err) {
    logger.error('Failed to get export archive', { exportId, error: err })
    return null
  }
}

/**
 * Process export asynchronously (in real scenario, this would be a Kafka consumer)
 */
async function processExportAsync(userId: string, exportId: string): Promise<void> {
  try {
    // Update status to processing
    await updateDataExportStatus(exportId, 'processing')

    // Create and encrypt the export
    const exportResult = await createGdprExport(userId)

    // Store the encrypted archive in Redis
    const client = getRedisClient()
    const archiveKey = `${ARCHIVE_KEY_PREFIX}${exportId}`

    const archiveData = {
      buffer: exportResult.encryptedData.toString('base64'),
      iv: exportResult.iv.toString('hex'),
      salt: exportResult.salt.toString('hex'),
      signature: exportResult.signature,
      metadata: exportResult.metadata,
    }

    await client.setex(
      archiveKey,
      ARCHIVE_TTL_SECONDS,
      JSON.stringify(archiveData)
    )

    // Update status to completed with archive size
    await updateDataExportStatus(exportId, 'completed', {
      archiveSize: exportResult.encryptedData.length,
    })

    logger.info('Export processing completed', {
      userId,
      exportId,
      archiveSize: exportResult.encryptedData.length,
    })
  } catch (err) {
    logger.error('Export processing failed', { userId, exportId, error: err })

    // Update status to failed
    await updateDataExportStatus(exportId, 'failed', {
      error: err instanceof Error ? err.message : String(err),
    })
  }
}
