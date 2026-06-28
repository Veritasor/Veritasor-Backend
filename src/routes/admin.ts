import { Router } from 'express'
import { z } from 'zod'
import { requireAuth } from '../middleware/requireAuth.js'
import { requirePermissions } from '../middleware/permissions.js'
import { IntegrationPermission } from '../types/permissions.js'
import { getAllUsers, updateUser, deleteUser, findUserById } from '../repositories/userRepository.js'
import { createAuditLog, queryAuditLogs } from '../repositories/auditLogRepository.js'
import { logger } from '../utils/logger.js'
import * as attestationRepository from '../repositories/attestationRepository.js'
import { db } from '../db/client.js'
import { getDeadLetter, deleteDeadLetter, computePayloadHash } from '../services/webhooks/deadLetterQueue.js'
import { handleRazorpayEvent } from '../services/webhooks/razorpayHandler.js'
import { revokeBatchAttestations } from '../services/attestation/revokeBatch.js'
import { logger } from '../utils/logger.js'
import { createRolePromotionRequest, findRolePromotionRequestById, updateRolePromotionRequest, findPendingRolePromotionRequestsForTarget } from '../repositories/rolePromotionRequestRepository.js'

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
 * POST /api/v1/admin/attestations/revoke-batch
 * Revoke multiple attestations in one call
 */
adminRouter.post(
  '/attestations/revoke-batch',
  requirePermissions(IntegrationPermission.ADMIN_MANAGE_USERS),
  async (req, res) => {
    const schema = z.object({
      attestationIds: z.array(z.string()).max(500)
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Bad Request', message: 'Invalid attestationIds array' });
    }

    try {
      const revoked = await revokeBatchAttestations(parsed.data.attestationIds, req.user!.id);
      res.json({ message: 'Batch revoked successfully', count: revoked.length });
    } catch (error: any) {
      res.status(500).json({ error: 'Internal Server Error', message: error.message });
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
const ALLOWED_AUDIT_ACTIONS = ['UPDATE_USER', 'PROMOTE_USER_ROLE', 'DELETE_USER', 'CREATE_ROLE_PROMOTION_REQUEST', 'APPROVE_ROLE_PROMOTION_REQUEST'] as const;

const createRolePromotionRequestSchema = z.object({
  targetUserId: z.string(),
  role: z.enum(['user', 'business_admin', 'admin']),
});

const auditLogsQuerySchema = z.object({
  actorId: z.string().optional(),
  action: z.string().optional().refine(val => val === undefined || (ALLOWED_AUDIT_ACTIONS as readonly string[]).includes(val), { message: 'Unrecognized action' }),
  resource: z.string().regex(/^[a-zA-Z0-9_-]{1,64}$/, { message: 'Invalid resource' }).optional(),
  from: z.string().optional().refine(s => !s || !Number.isNaN(Date.parse(s)), { message: 'Invalid from date' }),
  to: z.string().optional().refine(s => !s || !Number.isNaN(Date.parse(s)), { message: 'Invalid to date' }),
  limit: z.preprocess((v) => (v === undefined ? undefined : Number(v)), z.number().int().min(1).max(100).optional()).default(20),
  cursor: z.string().optional(),
})

adminRouter.get(
  '/audit-logs',
  requirePermissions(IntegrationPermission.ADMIN_READ_STATS),
  async (req, res) => {
    const parsed = auditLogsQuerySchema.safeParse(req.query)
    if (!parsed.success) {
      return res.status(400).json({ error: 'Bad Request', message: parsed.error.message })
    }

    const { actorId, action, resource, from, to, limit, cursor } = parsed.data as {
      actorId?: string
      action?: string
      resource?: string
      from?: string
      to?: string
      limit?: number
      cursor?: string
    }

    // Validate range
    if (from && to && new Date(from).getTime() > new Date(to).getTime()) {
      return res.status(400).json({ error: 'Bad Request', message: '`from` must be <= `to`' })
    }

    try {
      const q = {
        actorId,
        action,
        resource,
        from: from ? new Date(from) : undefined,
        to: to ? new Date(to) : undefined,
        limit,
        cursor,
      }

      const result = await queryAuditLogs(q)

      // Log query without sensitive filter values (actorId is allowed)
      logger.info({ event: 'admin_audit_logs_query', actorId: req.user?.id, filters: { action, resource, from: from ?? null, to: to ?? null, limit }, resultCount: result.data.length }, 'Admin audit logs query')

      res.json({ data: result.data, nextCursor: result.nextCursor, hasMore: result.hasMore })
    } catch (error: any) {
      res.status(500).json({ error: 'Internal Server Error', message: error.message })
    }
  }
)

/**
 * POST /api/v1/admin/role-requests
 * Create a role promotion request
 */
adminRouter.post(
  '/role-requests',
  requirePermissions(IntegrationPermission.ADMIN_MANAGE_USERS),
  async (req, res) => {
    const parsed = createRolePromotionRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Bad Request', message: parsed.error.message });
    }

    const { targetUserId, role } = parsed.data;
    const actorId = req.user!.id;

    try {
      const targetUser = await findUserById(targetUserId);
      if (!targetUser) {
        return res.status(404).json({ error: 'Not Found', message: 'Target user not found' });
      }

      const pendingRequests = await findPendingRolePromotionRequestsForTarget(targetUserId);
      if (pendingRequests.some(r => r.requestedRole === role)) {
        return res.status(409).json({ error: 'Conflict', message: 'Pending request for this role already exists' });
      }

      const request = await createRolePromotionRequest(targetUserId, role, actorId);
      
      await createAuditLog({
        userId: actorId,
        action: 'CREATE_ROLE_PROMOTION_REQUEST',
        resource: 'role_promotion_request',
        resourceId: request.id,
        metadata: { targetUserId, requestedRole: role }
      }, request);

      return res.status(201).json(request);
    } catch (error: any) {
      logger.error(error);
      return res.status(500).json({ error: 'Internal Server Error', message: error.message });
    }
  }
);

/**
 * POST /api/v1/admin/role-requests/:id/approve
 * Approve a role promotion request
 */
adminRouter.post(
  '/role-requests/:id/approve',
  requirePermissions(IntegrationPermission.ADMIN_MANAGE_USERS),
  async (req, res) => {
    const { id } = req.params;
    const actorId = req.user!.id;

    try {
      const request = await findRolePromotionRequestById(id);
      if (!request) {
        return res.status(404).json({ error: 'Not Found', message: 'Role promotion request not found' });
      }

      if (request.status !== 'pending') {
        return res.status(409).json({ error: 'Conflict', message: `Request is already ${request.status}` });
      }

      if (request.expiresAt < new Date()) {
        await updateRolePromotionRequest(id, { status: 'expired' });
        return res.status(409).json({ error: 'Conflict', message: 'Role promotion request has expired' });
      }

      if (request.requestedByAdminId === actorId) {
        await createAuditLog({
          userId: actorId,
          action: 'APPROVE_ROLE_PROMOTION_REQUEST',
          resource: 'role_promotion_request',
          resourceId: id,
          metadata: { outcome: 'forbidden_self_approval', requestId: id }
        });

        return res.status(403).json({ error: 'Forbidden', message: 'Self-approval is not allowed' });
      }

      const targetUser = await findUserById(request.targetUserId);
      if (!targetUser) {
        return res.status(404).json({ error: 'Not Found', message: 'Target user no longer exists' });
      }

      const updatedRequest = await updateRolePromotionRequest(id, {
        status: 'approved',
        approvedByAdminId: actorId,
        approvedAt: new Date()
      });

      if (!updatedRequest) {
        return res.status(500).json({ error: 'Internal Server Error', message: 'Failed to update request' });
      }

      await updateUser(request.targetUserId, { role: request.requestedRole });
      
      await createAuditLog({
        userId: actorId,
        action: 'APPROVE_ROLE_PROMOTION_REQUEST',
        resource: 'role_promotion_request',
        resourceId: id,
        metadata: {
          outcome: 'success',
          targetUserId: request.targetUserId,
          requestedRole: request.requestedRole,
          requestedByAdminId: request.requestedByAdminId
        }
      }, updatedRequest);

      return res.json(updatedRequest);
    } catch (error: any) {
      logger.error(error);
      return res.status(500).json({ error: 'Internal Server Error', message: error.message });
    }
  }
);

export default adminRouter
