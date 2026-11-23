import { Router } from 'express'
import { z } from 'zod'
import { requirePermissions } from '../../middleware/permissions.js'
import { IntegrationPermission } from '../../types/permissions.js'
import { queryAuditLogs } from '../../repositories/auditLogRepository.js'
import { logger } from '../../utils/logger.js'

const auditLogsRouter = Router()

const ALLOWED_AUDIT_ACTIONS = [
  'UPDATE_USER',
  'PROMOTE_USER_ROLE',
  'DELETE_USER',
  'CREATE_ROLE_PROMOTION_REQUEST',
  'APPROVE_ROLE_PROMOTION_REQUEST',
  'RELEASE_QUARANTINED_WEBHOOK',
] as const

const auditLogsQuerySchema = z.object({
  actorId: z.string().optional(),
  action: z.string().optional().refine(val => val === undefined || (ALLOWED_AUDIT_ACTIONS as readonly string[]).includes(val), { message: 'Unrecognized action' }),
  resource: z.string().regex(/^[a-zA-Z0-9_-]{1,64}$/, { message: 'Invalid resource' }).optional(),
  from: z.string().optional().refine(s => !s || !Number.isNaN(Date.parse(s)), { message: 'Invalid from date' }),
  to: z.string().optional().refine(s => !s || !Number.isNaN(Date.parse(s)), { message: 'Invalid to date' }),
  limit: z.preprocess((v) => (v === undefined ? undefined : Number(v)), z.number().int().min(1).max(100).optional()).default(20),
  cursor: z.string().optional(),
})

/**
 * GET /api/v1/admin/audit-logs
 * List all audit logs
 */
auditLogsRouter.get(
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

export default auditLogsRouter
