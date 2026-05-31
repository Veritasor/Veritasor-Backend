import { Router } from 'express'
import { requireAuth } from '../middleware/requireAuth.js'
import { requirePermissions } from '../middleware/permissions.js'
import { IntegrationPermission } from '../types/permissions.js'
import { getAllUsers, updateUser, deleteUser, findUserById } from '../repositories/userRepository.js'
import { getAllAuditLogs, createAuditLog } from '../repositories/auditLogRepository.js'
import * as attestationRepository from '../repositories/attestationRepository.js'
import { db } from '../db/client.js'
import { getDeadLetter, deleteDeadLetter, computePayloadHash } from '../services/webhooks/deadLetterQueue.js'
import { handleRazorpayEvent } from '../services/webhooks/razorpayHandler.js'
import { logger } from '../utils/logger.js'

const adminRouter = Router()

const SENSITIVE_UPDATE_FIELDS = new Set(['passwordHash', 'resetToken', 'resetTokenExpiry'])

function normalizeUpdates(payload: unknown): Record<string, unknown> {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return {}
  }
  return payload as Record<string, unknown>
}

function getAuditUpdateFields(updates: Record<string, unknown>): string[] {
  return Object.keys(updates).filter(field => !SENSITIVE_UPDATE_FIELDS.has(field))
}

// All routes here require authentication
adminRouter.use(requireAuth)

/**
 * GET /api/v1/admin/stats
 * Get platform statistics
 */
adminRouter.get(
  '/stats',
  requirePermissions(IntegrationPermission.ADMIN_READ_STATS),
  async (req, res) => {
    try {
      const users = await getAllUsers()
      const attestations = await attestationRepository.listAll(db)
      
      const stats = {
        totalUsers: users.length,
        totalAttestations: attestations.length,
        adminCount: users.filter(u => u.role === 'admin').length,
        businessAdminCount: users.filter(u => u.role === 'business_admin').length,
        userCount: users.filter(u => u.role === 'user').length,
        recentAttestations: attestations.slice(-5),
      }
      
      res.json(stats)
    } catch (error: any) {
      res.status(500).json({ error: 'Internal Server Error', message: error.message })
    }
  }
)

/**
 * GET /api/v1/admin/users
 * List all users
 */
adminRouter.get(
  '/users',
  requirePermissions(IntegrationPermission.ADMIN_MANAGE_USERS),
  async (req, res) => {
    try {
      const users = await getAllUsers()
      res.json(users)
    } catch (error: any) {
      res.status(500).json({ error: 'Internal Server Error', message: error.message })
    }
  }
)

/**
 * PATCH /api/v1/admin/users/:id
 * Update user details or role
 */
adminRouter.patch(
  '/users/:id',
  requirePermissions(IntegrationPermission.ADMIN_MANAGE_USERS),
  async (req, res) => {
    const { id } = req.params
    const updates = normalizeUpdates(req.body)
    const updateFields = getAuditUpdateFields(updates)

    try {
      const user = await findUserById(id)
      if (!user) {
        await createAuditLog({
          userId: req.user!.id,
          action: 'UPDATE_USER',
          resource: 'user',
          resourceId: id,
          metadata: { outcome: 'not_found', updateFields },
        })
        return res.status(404).json({ error: 'Not Found', message: 'User not found' })
      }
      
      const updatedUser = await updateUser(id, updates)
      if (!updatedUser) {
        await createAuditLog({
          userId: req.user!.id,
          action: 'UPDATE_USER',
          resource: 'user',
          resourceId: id,
          metadata: { outcome: 'not_found', updateFields },
        })
        return res.status(404).json({ error: 'Not Found', message: 'User not found' })
      }
      
      await createAuditLog({
        userId: req.user!.id,
        action: 'UPDATE_USER',
        resource: 'user',
        resourceId: id,
        metadata: { outcome: 'success', updateFields }
      })
      
      res.json(updatedUser)
    } catch (error: any) {
      await createAuditLog({
        userId: req.user?.id ?? 'unknown',
        action: 'UPDATE_USER',
        resource: 'user',
        resourceId: id,
        metadata: { outcome: 'error' },
      })
      res.status(500).json({ error: 'Internal Server Error', message: error.message })
    }
  }
)

/**
 * DELETE /api/v1/admin/users/:id
 * Delete a user
 */
adminRouter.delete(
  '/users/:id',
  requirePermissions(IntegrationPermission.ADMIN_MANAGE_USERS),
  async (req, res) => {
    const { id } = req.params

    try {
      const user = await findUserById(id)
      if (!user) {
        await createAuditLog({
          userId: req.user!.id,
          action: 'DELETE_USER',
          resource: 'user',
          resourceId: id,
          metadata: { outcome: 'not_found' },
        })
        return res.status(404).json({ error: 'Not Found', message: 'User not found' })
      }
      
      const deleted = await deleteUser(id)
      if (!deleted) {
        await createAuditLog({
          userId: req.user!.id,
          action: 'DELETE_USER',
          resource: 'user',
          resourceId: id,
          metadata: { outcome: 'not_found' },
        })
        return res.status(404).json({ error: 'Not Found', message: 'User not found' })
      }
      
      await createAuditLog({
        userId: req.user!.id,
        action: 'DELETE_USER',
        resource: 'user',
        resourceId: id,
        metadata: { outcome: 'success' }
      })
      
      res.sendStatus(204)
    } catch (error: any) {
      await createAuditLog({
        userId: req.user?.id ?? 'unknown',
        action: 'DELETE_USER',
        resource: 'user',
        resourceId: id,
        metadata: { outcome: 'error' },
      })
      res.status(500).json({ error: 'Internal Server Error', message: error.message })
    }
  }
)

/**
 * GET /api/v1/admin/audit-logs
 * List all audit logs
 */
adminRouter.get(
  '/audit-logs',
  requirePermissions(IntegrationPermission.ADMIN_READ_AUDIT_LOGS),
  async (req, res) => {
    try {
      const logs = await getAllAuditLogs()
      res.json(logs)
    } catch (error: any) {
      res.status(500).json({ error: 'Internal Server Error', message: error.message })
    }
  }
)

/**
 * POST /api/v1/admin/webhooks/replay
 * Replay a failed webhook from the dead-letter queue
 */
adminRouter.post(
  '/webhooks/replay',
  requirePermissions(IntegrationPermission.ADMIN_MANAGE_USERS),
  async (req, res) => {
    const { provider, eventId, payload } = req.body

    if (!provider || !eventId || !payload) {
      return res.status(400).json({ error: 'Missing required fields: provider, eventId, payload' })
    }

    if (provider !== 'razorpay') {
      return res.status(400).json({ error: `Unsupported provider: ${provider}` })
    }

    try {
      const entry = await getDeadLetter(provider, eventId)
      if (!entry) {
        return res.status(404).json({ error: 'Dead letter entry not found' })
      }

      let computedHash: string
      try {
        computedHash = computePayloadHash(payload)
      } catch (err: any) {
        if (err.message === 'Payload too large') {
          return res.status(400).json({ error: 'Payload too large' })
        }
        throw err
      }

      if (computedHash !== entry.payload_hash) {
        return res.status(400).json({ error: 'Payload hash mismatch' })
      }

      // Process the payload by invoking the handler
      await handleRazorpayEvent(payload)

      // On successful processing, clear/delete the DLQ entry
      await deleteDeadLetter(provider, eventId)

      return res.json({ status: 'ok', message: 'Replay successful, entry cleared' })
    } catch (error: any) {
      logger.error('Admin webhook replay failed', { provider, eventId, error })
      return res.status(500).json({ error: 'Replay failed', message: error.message })
    }
  }
)

export default adminRouter
