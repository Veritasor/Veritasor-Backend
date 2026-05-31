import { Router } from 'express'
import { z } from 'zod'
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

const rolePromotionSchema = z.object({
  role: z.enum(['user', 'business_admin', 'admin']),
})

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
        metadata: { outcome: 'success', updateFields },
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
 * POST /api/v1/admin/users/:id/role
 * Promote or change a user's role through the guarded admin flow.
 */
adminRouter.post(
  '/users/:id/role',
  requirePermissions(IntegrationPermission.ADMIN_MANAGE_USERS),
  async (req, res) => {
    const { id } = req.params
    const parsed = rolePromotionSchema.safeParse(req.body)

    if (!parsed.success) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'Invalid role',
      })
    }

    const { role } = parsed.data
    const actorId = req.user!.id

    if (actorId === id) {
      await createAuditLog({
        userId: actorId,
        action: 'PROMOTE_USER_ROLE',
        resource: 'user',
        resourceId: id,
        metadata: {
          outcome: 'forbidden_self_promotion',
          actorId,
          targetUserId: id,
          newRole: role,
        },
      })

      return res.status(403).json({
        error: 'Forbidden',
        message: 'Self-promotion is not allowed',
      })
    }

    try {
      const targetUser = await findUserById(id)

      if (!targetUser) {
        await createAuditLog({
          userId: actorId,
          action: 'PROMOTE_USER_ROLE',
          resource: 'user',
          resourceId: id,
          metadata: {
            outcome: 'not_found',
            actorId,
            targetUserId: id,
            newRole: role,
          },
        })

        return res.status(404).json({
          error: 'Not Found',
          message: 'User not found',
        })
      }

      const previousRole = targetUser.role

      if (previousRole === role) {
        await createAuditLog({
          userId: actorId,
          action: 'PROMOTE_USER_ROLE',
          resource: 'user',
          resourceId: id,
          metadata: {
            outcome: 'noop',
            actorId,
            targetUserId: id,
            previousRole,
            newRole: role,
          },
        })

        return res.status(200).json(targetUser)
      }

      const updatedUser = await updateUser(id, { role })

      if (!updatedUser) {
        await createAuditLog({
          userId: actorId,
          action: 'PROMOTE_USER_ROLE',
          resource: 'user',
          resourceId: id,
          metadata: {
            outcome: 'not_found',
            actorId,
            targetUserId: id,
            previousRole,
            newRole: role,
          },
        })

        return res.status(404).json({
          error: 'Not Found',
          message: 'User not found',
        })
      }

      await createAuditLog({
        userId: actorId,
        action: 'PROMOTE_USER_ROLE',
        resource: 'user',
        resourceId: id,
        metadata: {
          outcome: 'success',
          actorId,
          targetUserId: id,
          previousRole,
          newRole: role,
        },
      })

      return res.status(200).json(updatedUser)
    } catch (error: any) {
      await createAuditLog({
        userId: actorId,
        action: 'PROMOTE_USER_ROLE',
        resource: 'user',
        resourceId: id,
        metadata: {
          outcome: 'error',
          actorId,
          targetUserId: id,
          newRole: role,
        },
      })

      return res.status(500).json({
        error: 'Internal Server Error',
        message: error.message,
      })
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
        metadata: { outcome: 'success' },
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

export default adminRouter
