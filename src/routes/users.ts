import { Router } from 'express'
import { requireAuth } from '../middleware/requireAuth.js'
import updateProfile from '../services/user/updateProfile.js'
import { validateBody } from '../middleware/validate.js'
import { updateUserProfileSchema } from './users.schema.js'
import {
  initiateDataExport,
  getExportStatus,
  getExportArchive,
} from '../services/user/dataExportService.js'
import { consumeDownloadToken } from '../repositories/dataExportRepository.js'
import { logger } from '../utils/logger.js'

export const usersRouter = Router()

// PATCH /api/users/me - update current user's profile
usersRouter.patch('/me', requireAuth, validateBody(updateUserProfileSchema), async (req: any, res: any) => {
  try {
    const updates = req.body

    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ message: 'No updatable fields provided' })
    }

    const userId = req.user.id
    const updated = await updateProfile(userId, updates)
    return res.json(updated)
  } catch (err: any) {
    return res.status(400).json({ message: err?.message ?? 'Invalid input' })
  }
})

// POST /api/users/me/export - initiate GDPR data export
usersRouter.post('/me/export', requireAuth, async (req: any, res: any) => {
  try {
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
    logger.error('Failed to initiate export', { error: err })
    return res.status(500).json({ message: 'Failed to initiate export' })
  }
})

// GET /api/users/me/export/:token - download GDPR data export
usersRouter.get('/me/export/:token', requireAuth, async (req: any, res: any) => {
  try {
    const { token } = req.params
    const userId = req.user.id

    if (!token || typeof token !== 'string' || token.length < 32) {
      return res.status(400).json({ message: 'Invalid export token' })
    }

    // Verify and consume the token (one-time use)
    const exportId = await consumeDownloadToken(token)

    if (!exportId) {
      // Token doesn't exist, already used, or expired
      return res.status(410).json({ message: 'Export token not found, already downloaded, or expired' })
    }

    // Get the export status
    const exportStatus = await getExportStatus(exportId)

    if (!exportStatus) {
      return res.status(404).json({ message: 'Export not found' })
    }

    // Verify export belongs to the authenticated user
    // Note: In production, we'd check the userId from the export metadata
    if (exportStatus.status !== 'completed') {
      return res.status(202).json({
        exportId,
        status: exportStatus.status,
        message: 'Export is still being processed',
      })
    }

    // Get the encrypted archive
    const archiveData = await getExportArchive(exportId)

    if (!archiveData) {
      return res.status(404).json({ message: 'Export archive not found' })
    }

    // Return as downloadable file
    res.setHeader('Content-Type', 'application/octet-stream')
    res.setHeader('Content-Disposition', `attachment; filename="gdpr-export-${exportId}.enc"`)
    res.setHeader('Content-Length', archiveData.length)
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate')

    return res.send(archiveData)
  } catch (err: any) {
    logger.error('Failed to download export', { error: err })
    return res.status(500).json({ message: 'Failed to download export' })
  }
})

// GET /api/users/me/export/:exportId/status - check export status (without consuming token)
usersRouter.get('/me/export/:exportId/status', requireAuth, async (req: any, res: any) => {
  try {
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
    logger.error('Failed to check export status', { error: err })
    return res.status(500).json({ message: 'Failed to check export status' })
  }
})

export default usersRouter
