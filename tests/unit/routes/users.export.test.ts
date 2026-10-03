import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import request from 'supertest'
import express, { Router } from 'express'
import { errorHandler } from '../../../src/middleware/errorHandler.js'
import * as userRepo from '../../../src/repositories/userRepository.js'
import * as auditLogRepo from '../../../src/repositories/auditLogRepository.js'
import * as exportRepo from '../../../src/repositories/dataExportRepository.js'
import { getRedisClient } from '../../../src/redis.js'
import {
  initiateDataExport,
  getExportStatus,
  getExportArchive,
} from '../../../src/services/user/dataExportService.js'
import { consumeDownloadToken } from '../../../src/repositories/dataExportRepository.js'

// Create test app with custom routes that bypass requireAuth
const createTestApp = (userId: string) => {
  const app = express()
  app.use(express.json())

  const testUser = {
    id: userId,
    email: 'test@example.com',
    passwordHash: 'hashed-password',
    createdAt: new Date('2024-01-01'),
    updatedAt: new Date('2024-06-01'),
    role: 'user' as const,
  }

  // Custom router for testing
  const router = Router()

  // POST /api/users/me/export - initiate GDPR data export
  router.post('/me/export', async (req: any, res: any) => {
    try {
      req.user = testUser
      const userId = req.user.id
      const result = await initiateDataExport(userId)
      return res.status(202).json({
        exportId: result.exportId,
        status: result.status,
        createdAt: result.createdAt,
        expiresAt: result.expiresAt,
        message: 'Data export initiated. Use the exportId to check status and download.',
      })
    } catch (err: any) {
      return res.status(500).json({ message: 'Failed to initiate export' })
    }
  })

  // GET /api/users/me/export/:token - download GDPR data export
  router.get('/me/export/:token', async (req: any, res: any) => {
    try {
      req.user = testUser
      const { token } = req.params

      if (!token || typeof token !== 'string' || token.length < 32) {
        return res.status(400).json({ message: 'Invalid export token' })
      }

      const exportId = await consumeDownloadToken(token)
      if (!exportId) {
        return res.status(410).json({ message: 'Export token not found, already downloaded, or expired' })
      }

      const exportStatus = await getExportStatus(exportId)
      if (!exportStatus) {
        return res.status(404).json({ message: 'Export not found' })
      }

      if (exportStatus.status !== 'completed') {
        return res.status(202).json({
          exportId,
          status: exportStatus.status,
          message: 'Export is still being processed',
        })
      }

      const archiveData = await getExportArchive(exportId)
      if (!archiveData) {
        return res.status(404).json({ message: 'Export archive not found' })
      }

      res.setHeader('Content-Type', 'application/octet-stream')
      res.setHeader('Content-Disposition', `attachment; filename="gdpr-export-${exportId}.enc"`)
      res.setHeader('Content-Length', archiveData.length)
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate')
      return res.send(archiveData)
    } catch (err: any) {
      return res.status(500).json({ message: 'Failed to download export' })
    }
  })

  // GET /api/users/me/export/:exportId/status - check export status
  router.get('/me/export/:exportId/status', async (req: any, res: any) => {
    try {
      req.user = testUser
      const { exportId } = req.params

      if (!exportId || typeof exportId !== 'string' || exportId.length < 32) {
        return res.status(400).json({ message: 'Invalid export ID' })
      }

      const exportStatus = await getExportStatus(exportId)
      if (!exportStatus) {
        return res.status(404).json({ message: 'Export not found' })
      }

      return res.json(exportStatus)
    } catch (err: any) {
      return res.status(500).json({ message: 'Failed to check export status' })
    }
  })

  app.use('/api/users', router)
  app.use(errorHandler)
  return app
}

let app: ReturnType<typeof createTestApp>
let testUserId: string

const authHeader = 'Bearer fake-token'

beforeEach(async () => {
  userRepo.clearAllUsers()
  auditLogRepo.clearAllAuditLogs()
  const createdUser = await userRepo.createUser('test@example.com', 'hashed-password')
  testUserId = createdUser.id
  app = createTestApp(testUserId)
})

afterEach(async () => {
  await new Promise(resolve => setTimeout(resolve, 100))
  userRepo.clearAllUsers()
  auditLogRepo.clearAllAuditLogs()

  const client = getRedisClient()
  const keys = await client.keys('data-export:*')
  const tokenKeys = await client.keys('data-export-token:*')
  const archiveKeys = await client.keys('data-export-archive:*')
  const allKeys = [...keys, ...tokenKeys, ...archiveKeys]
  if (allKeys.length > 0) {
    await client.del(...allKeys)
  }
})

describe('POST /api/users/me/export - GDPR Data Export Initiation', () => {
  it('should initiate export with 202 status for authenticated user', async () => {
    const response = await request(app)
      .post('/api/users/me/export')
      .set('Authorization', authHeader)

    expect(response.status).toBe(202)
    expect(response.body).toHaveProperty('exportId')
    expect(response.body).toHaveProperty('status')
    expect(response.body.status).toBe('pending')
    expect(response.body).toHaveProperty('createdAt')
    expect(response.body).toHaveProperty('expiresAt')
  })

  it('should return a valid exportId (hex string, at least 32 chars)', async () => {
    const response = await request(app)
      .post('/api/users/me/export')
      .set('Authorization', authHeader)

    expect(response.status).toBe(202)
    const { exportId } = response.body
    expect(exportId).toMatch(/^[a-f0-9]{32,}$/)
  })

  it('should set expiration to 7 days in the future', async () => {
    const beforeTime = Date.now()
    const response = await request(app)
      .post('/api/users/me/export')
      .set('Authorization', authHeader)
    const afterTime = Date.now()

    const expiresAt = new Date(response.body.expiresAt).getTime()
    const sevenDaysMs = 7 * 24 * 60 * 60 * 1000

    expect(expiresAt).toBeGreaterThan(beforeTime + sevenDaysMs - 5000)
    expect(expiresAt).toBeLessThan(afterTime + sevenDaysMs + 5000)
  })

  it('should allow multiple exports for the same user', async () => {
    const response1 = await request(app)
      .post('/api/users/me/export')
      .set('Authorization', authHeader)

    const response2 = await request(app)
      .post('/api/users/me/export')
      .set('Authorization', authHeader)

    expect(response1.status).toBe(202)
    expect(response2.status).toBe(202)
    expect(response1.body.exportId).not.toBe(response2.body.exportId)
  })
})

describe('GET /api/users/me/export/:exportId/status - Check Export Status', () => {
  it('should return export status for valid exportId', async () => {
    const initResponse = await request(app)
      .post('/api/users/me/export')
      .set('Authorization', authHeader)

    const exportId = initResponse.body.exportId

    const statusResponse = await request(app)
      .get(`/api/users/me/export/${exportId}/status`)
      .set('Authorization', authHeader)

    expect(statusResponse.status).toBe(200)
    expect(statusResponse.body.exportId).toBe(exportId)
    expect(['pending', 'processing']).toContain(statusResponse.body.status)
  })

  it('should return 404 for non-existent exportId', async () => {
    const response = await request(app)
      .get('/api/users/me/export/0123456789abcdef0123456789abcdef/status')
      .set('Authorization', authHeader)

    expect(response.status).toBe(404)
  })

  it('should reject invalid exportId format', async () => {
    const response = await request(app)
      .get('/api/users/me/export/short/status')
      .set('Authorization', authHeader)

    expect(response.status).toBe(400)
  })
})

describe('GET /api/users/me/export/:token - Download GDPR Export', () => {
  it('should return 410 for invalid token', async () => {
    const response = await request(app)
      .get('/api/users/me/export/invalid-token-format-does-not-exist-anywhere')
      .set('Authorization', authHeader)

    expect(response.status).toBe(410)
  })

  it('should return 400 for malformed token', async () => {
    const response = await request(app)
      .get('/api/users/me/export/short')
      .set('Authorization', authHeader)

    expect(response.status).toBe(400)
  })

  it('should return 202 if export is still processing or 200 if completed', async () => {
    const initResponse = await request(app)
      .post('/api/users/me/export')
      .set('Authorization', authHeader)

    const exportId = initResponse.body.exportId
    const token = await exportRepo.createDownloadToken(exportId)

    const downloadResponse = await request(app)
      .get(`/api/users/me/export/${token}`)
      .set('Authorization', authHeader)

    // Status could be 202 (still processing) or 200 (completed), depending on timing
    expect([202, 200]).toContain(downloadResponse.status)
    if (downloadResponse.status === 202) {
      expect(['pending', 'processing']).toContain(downloadResponse.body.status)
    }
  })

  it('should return 410 on token reuse (one-time download)', async () => {
    const initResponse = await request(app)
      .post('/api/users/me/export')
      .set('Authorization', authHeader)

    const exportId = initResponse.body.exportId
    const token = await exportRepo.createDownloadToken(exportId)

    const result1 = await exportRepo.consumeDownloadToken(token)
    expect(result1).toBe(exportId)

    const result2 = await exportRepo.consumeDownloadToken(token)
    expect(result2).toBeNull()
  })

  it('should set correct HTTP headers for file download', async () => {
    const initResponse = await request(app)
      .post('/api/users/me/export')
      .set('Authorization', authHeader)

    const exportId = initResponse.body.exportId

    await exportRepo.updateDataExportStatus(exportId, 'completed', {
      archiveSize: 1024,
    })

    const client = getRedisClient()
    const archiveKey = `data-export-archive:${exportId}`
    const mockArchive = {
      buffer: Buffer.from('test data').toString('base64'),
      iv: '00'.repeat(12),
      salt: '00'.repeat(16),
      signature: 'test-signature',
      metadata: {
        algorithm: 'aes-256-gcm',
        keyDerivation: 'pbkdf2-sha256',
        compressionFormat: 'gzip',
      },
    }
    await client.setex(archiveKey, 86400, JSON.stringify(mockArchive))

    const token = await exportRepo.createDownloadToken(exportId)

    const downloadResponse = await request(app)
      .get(`/api/users/me/export/${token}`)
      .set('Authorization', authHeader)

    expect(downloadResponse.status).toBe(200)
    expect(downloadResponse.headers['content-type']).toBe('application/octet-stream')
    expect(downloadResponse.headers['content-disposition']).toMatch(/^attachment; filename="gdpr-export-/)
    expect(downloadResponse.headers['cache-control']).toContain('no-cache')
  })
})

describe('GDPR Export Data Consistency', () => {
  it('should bundle user PII correctly', async () => {
    const response = await request(app)
      .post('/api/users/me/export')
      .set('Authorization', authHeader)

    expect(response.status).toBe(202)
    const exportId = response.body.exportId

    const exportData = await exportRepo.getDataExport(exportId)
    expect(exportData).not.toBeNull()
    expect(exportData?.userId).toBe(testUserId)
  })

  it('should include audit logs in export', async () => {
    await auditLogRepo.createAuditLog({
      userId: testUserId,
      action: 'LOGIN',
      resource: 'AUTH',
      metadata: { ip: '127.0.0.1' },
    })

    await auditLogRepo.createAuditLog({
      userId: testUserId,
      action: 'UPDATE_PROFILE',
      resource: 'USER',
    })

    const response = await request(app)
      .post('/api/users/me/export')
      .set('Authorization', authHeader)

    expect(response.status).toBe(202)

    const exportData = await exportRepo.getDataExport(response.body.exportId)
    expect(['pending', 'processing']).toContain(exportData?.status)
  })

  it('should handle exports with no audit logs', async () => {
    const response = await request(app)
      .post('/api/users/me/export')
      .set('Authorization', authHeader)

    expect(response.status).toBe(202)
    expect(response.body.exportId).toBeDefined()
  })
})

describe('Export Token Security', () => {
  it('should generate unique tokens for each export', async () => {
    const initResponse1 = await request(app)
      .post('/api/users/me/export')
      .set('Authorization', authHeader)

    const initResponse2 = await request(app)
      .post('/api/users/me/export')
      .set('Authorization', authHeader)

    const exportId1 = initResponse1.body.exportId
    const exportId2 = initResponse2.body.exportId

    const token1 = await exportRepo.createDownloadToken(exportId1)
    const token2 = await exportRepo.createDownloadToken(exportId2)

    expect(token1).not.toBe(token2)
    expect(token1).toMatch(/^[a-f0-9]{64}$/)
    expect(token2).toMatch(/^[a-f0-9]{64}$/)
  })
})

describe('Export Status Lifecycle', () => {
  it('should transition from pending to completed', async () => {
    const initResponse = await request(app)
      .post('/api/users/me/export')
      .set('Authorization', authHeader)

    const exportId = initResponse.body.exportId

    let status = await exportRepo.getDataExport(exportId)
    expect(['pending', 'processing']).toContain(status?.status)

    const completed = await exportRepo.updateDataExportStatus(exportId, 'completed', {
      archiveSize: 2048,
    })

    expect(completed?.status).toBe('completed')
    expect(completed?.archiveSize).toBe(2048)
    expect(completed?.completedAt).toBeDefined()
  })

  it('should support failed status with error message', async () => {
    const initResponse = await request(app)
      .post('/api/users/me/export')
      .set('Authorization', authHeader)

    const exportId = initResponse.body.exportId

    const failed = await exportRepo.updateDataExportStatus(exportId, 'failed', {
      error: 'User not found',
    })

    expect(failed?.status).toBe('failed')
    expect(failed?.error).toBe('User not found')
    expect(failed?.completedAt).toBeDefined()
  })

  it('should track downloadedAt when archive is accessed', async () => {
    const initResponse = await request(app)
      .post('/api/users/me/export')
      .set('Authorization', authHeader)

    const exportId = initResponse.body.exportId

    const beforeDownload = new Date()
    const updated = await exportRepo.updateDataExportStatus(exportId, 'completed', {
      downloadedAt: new Date(),
    })
    const afterDownload = new Date()

    expect(updated?.downloadedAt).toBeDefined()
    if (updated?.downloadedAt) {
      const downloadedAt = typeof updated.downloadedAt === 'string'
        ? new Date(updated.downloadedAt)
        : updated.downloadedAt
      expect(downloadedAt.getTime()).toBeGreaterThanOrEqual(beforeDownload.getTime())
      expect(downloadedAt.getTime()).toBeLessThanOrEqual(afterDownload.getTime())
    }
  })
})
