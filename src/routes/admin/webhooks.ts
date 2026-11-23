import { Router } from 'express'
import { requirePermissions } from '../../middleware/permissions.js'
import { IntegrationPermission } from '../../types/permissions.js'
import { createAuditLog } from '../../repositories/auditLogRepository.js'
import {
  getDeadLetter,
  deleteDeadLetter,
  computePayloadHash,
  isQuarantined,
  listQuarantinedLetters,
  releaseQuarantinedLetter,
  purgeQuarantinedLetter,
  listDeadLetterShards,
} from '../../services/webhooks/deadLetterQueue.js'
import { handleRazorpayEvent } from '../../services/webhooks/razorpayHandler.js'
import { queryDeliveryReceipts } from '../../repositories/deliveryReceiptRepository.js'

const webhooksRouter = Router()

/**
 * GET /api/v1/admin/webhooks/receipts
 * List webhook delivery receipts with optional filters
 */
webhooksRouter.get(
  '/webhooks/receipts',
  requirePermissions(IntegrationPermission.ADMIN_READ_STATS),
  async (req, res) => {
    try {
      const businessId = typeof req.query.businessId === 'string' ? req.query.businessId : undefined
      const deliveryId = typeof req.query.deliveryId === 'string' ? req.query.deliveryId : undefined
      const subscriptionId = typeof req.query.subscriptionId === 'string' ? req.query.subscriptionId : undefined
      const limit = typeof req.query.limit === 'string' ? Math.min(parseInt(req.query.limit, 10) || 50, 100) : 50
      const cursor = typeof req.query.cursor === 'string' ? req.query.cursor : undefined

      const result = await queryDeliveryReceipts({ businessId, deliveryId, subscriptionId, limit, cursor })
      res.json(result)
    } catch (error: any) {
      res.status(500).json({ error: 'Internal Server Error', message: error.message })
    }
  }
)

/**
 * POST /api/v1/admin/webhooks/replay
 * Replay a dead-letter webhook payload
 */
webhooksRouter.post(
  '/webhooks/replay',
  requirePermissions(IntegrationPermission.ADMIN_MANAGE_USERS),
  async (req, res) => {
    const { provider, eventId, payload } = req.body || {}

    if (!provider || !eventId || !payload) {
      return res.status(400).json({ error: 'Missing required fields: provider, eventId, payload' })
    }

    if (provider !== 'razorpay') {
      return res.status(400).json({ error: 'Unsupported provider' })
    }

    try {
      const quarantined = await isQuarantined(provider, eventId)
      if (quarantined) {
        return res.status(400).json({
          error: 'Entry is quarantined as a poison pill and requires explicit release',
        })
      }

      const deadLetter = await getDeadLetter(provider, eventId)
      if (!deadLetter) {
        return res.status(404).json({ error: 'Dead letter entry not found' })
      }

      let computedHash: string
      try {
        computedHash = computePayloadHash(payload)
      } catch (err: any) {
        return res.status(400).json({ error: err.message ?? 'Invalid payload' })
      }

      if (computedHash !== deadLetter.payload_hash) {
        return res.status(400).json({ error: 'Payload hash mismatch' })
      }

      await handleRazorpayEvent(payload)
      await deleteDeadLetter(provider, eventId)

      return res.json({ status: 'ok', message: 'Replay successful, entry cleared' })
    } catch (error: any) {
      return res.status(500).json({ error: 'Replay failed', message: error.message })
    }
  }
)

/**
 * GET /api/v1/admin/webhooks/quarantine
 * List all quarantined webhook entries
 */
webhooksRouter.get(
  '/webhooks/quarantine',
  requirePermissions(IntegrationPermission.ADMIN_MANAGE_USERS),
  async (req, res) => {
    try {
      const provider = typeof req.query.provider === 'string' ? req.query.provider : undefined
      const integration = typeof req.query.integration === 'string' ? req.query.integration : undefined
      const quarantined = await listQuarantinedLetters(provider, integration)
      res.json({ data: quarantined })
    } catch (error: any) {
      res.status(500).json({ error: 'Internal Server Error', message: error.message })
    }
  }
)

/**
 * GET /api/v1/admin/webhooks/shards
 * List all DLQ shards and their entry counts
 */
webhooksRouter.get(
  '/webhooks/shards',
  requirePermissions(IntegrationPermission.ADMIN_READ_STATS),
  async (req, res) => {
    try {
      const shards = await listDeadLetterShards()
      res.json({ data: shards })
    } catch (error: any) {
      res.status(500).json({ error: 'Internal Server Error', message: error.message })
    }
  }
)

/**
 * POST /api/v1/admin/webhooks/quarantine/release
 * Release a quarantined webhook entry back for replay
 */
webhooksRouter.post(
  '/webhooks/quarantine/release',
  requirePermissions(IntegrationPermission.ADMIN_MANAGE_USERS),
  async (req, res) => {
    const { provider, eventId } = req.body || {}

    if (!provider || !eventId) {
      return res.status(400).json({ error: 'Missing required fields: provider, eventId' })
    }

    try {
      const released = await releaseQuarantinedLetter(provider, eventId, req.user!.id)
      if (!released) {
        return res.status(404).json({ error: 'Quarantined entry not found' })
      }

      await createAuditLog({
        userId: req.user!.id,
        action: 'RELEASE_QUARANTINED_WEBHOOK',
        resource: 'webhook_quarantine',
        resourceId: `${provider}:${eventId}`,
        metadata: { provider, eventId, outcome: 'success' },
      })

      res.json({ status: 'ok', message: 'Quarantined entry released successfully' })
    } catch (error: any) {
      res.status(500).json({ error: 'Internal Server Error', message: error.message })
    }
  }
)

/**
 * DELETE /api/v1/admin/webhooks/quarantine
 * Purge a quarantined webhook entry permanently
 */
webhooksRouter.delete(
  '/webhooks/quarantine',
  requirePermissions(IntegrationPermission.ADMIN_MANAGE_USERS),
  async (req, res) => {
    const { provider, eventId } = req.body || {}

    if (!provider || !eventId) {
      return res.status(400).json({ error: 'Missing required fields: provider, eventId' })
    }

    try {
      const purged = await purgeQuarantinedLetter(provider, eventId)
      if (!purged) {
        return res.status(404).json({ error: 'Quarantined entry not found' })
      }

      res.json({ status: 'ok', message: 'Quarantined entry purged successfully' })
    } catch (error: any) {
      res.status(500).json({ error: 'Internal Server Error', message: error.message })
    }
  }
)

export default webhooksRouter
