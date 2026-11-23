import { Request, Router } from 'express'
import { z } from 'zod'
import { requireBusinessTierRolePromotionPermission, requirePermissions } from '../../middleware/permissions.js'
import { IntegrationPermission } from '../../types/permissions.js'
import { findUserById, promoteUserToBusinessAdmin, updateUser } from '../../repositories/userRepository.js'
import { createAuditLog } from '../../repositories/auditLogRepository.js'
import { logger } from '../../utils/logger.js'
import {
  createRolePromotionRequest,
  findRolePromotionRequestById,
  updateRolePromotionRequest,
  findPendingRolePromotionRequestsForTarget,
} from '../../repositories/rolePromotionRequestRepository.js'

const rolePromotionsRouter = Router()

const rolePromotionSchema = z.object({
  role: z.literal('business_admin'),
}).strict()

const createRolePromotionRequestSchema = z.object({
  targetUserId: z.string(),
  role: z.enum(['user', 'business_admin', 'admin']),
})

const PROMOTE_USER_ROLE_ACTION = 'PROMOTE_USER_ROLE'

type PromoteUserRoleAuditMetadata = {
  outcome: string
  actorId: string
  targetUserId: string
  previousRole?: string | null
  newRole?: string
  reason?: string
}

async function auditPromoteUserRole(
  actorId: string,
  targetUserId: string,
  metadata: PromoteUserRoleAuditMetadata,
): Promise<void> {
  await createAuditLog({
    userId: actorId,
    action: PROMOTE_USER_ROLE_ACTION,
    resource: 'user',
    resourceId: targetUserId,
    metadata,
  })
}

function getActorId(req: Request): string {
  return req.user?.id ?? req.user?.userId ?? 'unknown'
}

function isSelfPromotion(actorId: string, targetUserId: string): boolean {
  return actorId === targetUserId
}

/**
 * POST /api/v1/admin/users/:id/role
 * Promote a regular user to business_admin through the guarded admin flow.
 */
rolePromotionsRouter.post(
  '/users/:id/role',
  requireBusinessTierRolePromotionPermission,
  async (req, res) => {
    const { id } = req.params
    const parsed = rolePromotionSchema.safeParse(req.body)
    const actorId = getActorId(req)

    if (!parsed.success) {
      await auditPromoteUserRole(actorId, id, {
        outcome: 'invalid_input',
        actorId,
        targetUserId: id,
        reason: 'role must be business_admin',
      })

      return res.status(400).json({
        error: 'Bad Request',
        message: 'role must be business_admin',
      })
    }

    const { role } = parsed.data

    if (isSelfPromotion(actorId, id)) {
      await auditPromoteUserRole(actorId, id, {
        outcome: 'forbidden_self_promotion',
        actorId,
        targetUserId: id,
        newRole: role,
      })

      return res.status(403).json({
        error: 'Forbidden',
        message: 'Self-promotion is not allowed',
      })
    }

    try {
      const promotion = await promoteUserToBusinessAdmin(id)

      if (promotion.outcome === 'not_found') {
        await auditPromoteUserRole(actorId, id, {
          outcome: 'not_found',
          actorId,
          targetUserId: id,
          previousRole: null,
          newRole: promotion.newRole,
        })

        return res.status(404).json({
          error: 'Not Found',
          message: 'User not found',
        })
      }

      if (promotion.outcome === 'already_business_admin') {
        await auditPromoteUserRole(actorId, id, {
          outcome: 'noop',
          actorId,
          targetUserId: id,
          previousRole: promotion.previousRole,
          newRole: promotion.newRole,
        })

        return res.status(200).json(promotion.user)
      }

      if (promotion.outcome === 'invalid_current_role') {
        await auditPromoteUserRole(actorId, id, {
          outcome: 'conflict',
          actorId,
          targetUserId: id,
          previousRole: promotion.previousRole,
          newRole: promotion.newRole,
          reason: 'target user must currently have user role',
        })

        return res.status(409).json({
          error: 'Conflict',
          message: 'User cannot be promoted from current role',
        })
      }

      await auditPromoteUserRole(actorId, id, {
        outcome: 'success',
        actorId,
        targetUserId: id,
        previousRole: promotion.previousRole,
        newRole: promotion.newRole,
      })

      return res.status(200).json(promotion.user)
    } catch (error: any) {
      await auditPromoteUserRole(actorId, id, {
        outcome: 'error',
        actorId,
        targetUserId: id,
        newRole: role,
      })

      return res.status(500).json({
        error: 'Internal Server Error',
        message: error.message,
      })
    }
  }
)

/**
 * POST /api/v1/admin/role-requests
 * Create a role promotion request
 */
rolePromotionsRouter.post(
  '/role-requests',
  requirePermissions(IntegrationPermission.ADMIN_MANAGE_USERS),
  async (req, res) => {
    const parsed = createRolePromotionRequestSchema.safeParse(req.body)
    if (!parsed.success) {
      return res.status(400).json({ error: 'Bad Request', message: parsed.error.message })
    }

    const { targetUserId, role } = parsed.data
    const actorId = req.user!.id

    try {
      const targetUser = await findUserById(targetUserId)
      if (!targetUser) {
        return res.status(404).json({ error: 'Not Found', message: 'Target user not found' })
      }

      const pendingRequests = await findPendingRolePromotionRequestsForTarget(targetUserId)
      if (pendingRequests.some(r => r.requestedRole === role)) {
        return res.status(409).json({ error: 'Conflict', message: 'Pending request for this role already exists' })
      }

      const request = await createRolePromotionRequest(targetUserId, role, actorId)

      await createAuditLog({
        userId: actorId,
        action: 'CREATE_ROLE_PROMOTION_REQUEST',
        resource: 'role_promotion_request',
        resourceId: request.id,
        metadata: { targetUserId, requestedRole: role }
      }, request)

      return res.status(201).json(request)
    } catch (error: any) {
      logger.error(error)
      return res.status(500).json({ error: 'Internal Server Error', message: error.message })
    }
  }
)

/**
 * POST /api/v1/admin/role-requests/:id/approve
 * Approve a role promotion request
 */
rolePromotionsRouter.post(
  '/role-requests/:id/approve',
  requirePermissions(IntegrationPermission.ADMIN_MANAGE_USERS),
  async (req, res) => {
    const { id } = req.params
    const actorId = req.user!.id

    try {
      const request = await findRolePromotionRequestById(id)
      if (!request) {
        return res.status(404).json({ error: 'Not Found', message: 'Role promotion request not found' })
      }

      if (request.status !== 'pending') {
        return res.status(409).json({ error: 'Conflict', message: `Request is already ${request.status}` })
      }

      if (request.expiresAt < new Date()) {
        await updateRolePromotionRequest(id, { status: 'expired' })
        return res.status(409).json({ error: 'Conflict', message: 'Role promotion request has expired' })
      }

      if (request.requestedByAdminId === actorId) {
        await createAuditLog({
          userId: actorId,
          action: 'APPROVE_ROLE_PROMOTION_REQUEST',
          resource: 'role_promotion_request',
          resourceId: id,
          metadata: { outcome: 'forbidden_self_approval', requestId: id }
        })

        return res.status(403).json({ error: 'Forbidden', message: 'Self-approval is not allowed' })
      }

      const targetUser = await findUserById(request.targetUserId)
      if (!targetUser) {
        return res.status(404).json({ error: 'Not Found', message: 'Target user no longer exists' })
      }

      const updatedRequest = await updateRolePromotionRequest(id, {
        status: 'approved',
        approvedByAdminId: actorId,
        approvedAt: new Date()
      })

      if (!updatedRequest) {
        return res.status(500).json({ error: 'Internal Server Error', message: 'Failed to update request' })
      }

      await updateUser(request.targetUserId, { role: request.requestedRole })

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
      }, updatedRequest)

      return res.json(updatedRequest)
    } catch (error: any) {
      logger.error(error)
      return res.status(500).json({ error: 'Internal Server Error', message: error.message })
    }
  }
)

export default rolePromotionsRouter
