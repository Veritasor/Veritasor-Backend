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
import { consumeDownloadToken, peekDownloadToken } from '../repositories/dataExportRepository.js'
import { logger } from '../utils/logger.js'
import { CachePolicies, setCacheControl } from '../utils/cacheControl.js'

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

    // Look up the export behind the token without consuming it, so owner
    // checks can fail closed without burning the caller's token.
    const exportId = await peekDownloadToken(token)

    if (!exportId) {
      // Token doesn't exist, already used, or expired
      return res.status(410).json({ message: 'Export token not found, already downloaded, or expired' })
    }

    // Get the export status for the authenticated user only.
    // Returns null for other users' exports so ids cannot be enumerated.
    const exportStatus = await getExportStatus(exportId, userId)

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

    if (await consumeDownloadToken(token) !== exportId) {
      return res.status(410).json({ message: 'Export token not found, already downloaded, or expired' })
    }

    // Get the encrypted archive
    const archiveData = await getExportArchive(exportId)

    if (!archiveData) {
      return res.status(404).json({ message: 'Export archive not found' })
    }

    // Only now that the caller is confirmed to be the owner do we consume
    // the one-time token.
    const consumedExportId = await consumeDownloadToken(token)
    if (!consumedExportId || consumedExportId !== exportId) {
      return res.status(410).json({ message: 'Export token not found, already downloaded, or expired' })
    }

    // Return as downloadable file
    res.setHeader('Content-Type', 'application/octet-stream')
    res.setHeader('Content-Disposition', `attachment; filename="gdpr-export-${exportId}.enc"`)
    res.setHeader('Content-Length', archiveData.length)
    setCacheControl(res, CachePolicies.DATA_EXPORT_DOWNLOAD)

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
    const userId = req.user.id

    if (!exportId || typeof exportId !== 'string' || exportId.length < 32) {
      return res.status(400).json({ message: 'Invalid export ID' })
    }

    const exportStatus = await getExportStatus(exportId, userId)

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
