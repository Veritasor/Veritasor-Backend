import { Router } from 'express'
import { z } from 'zod'
import { requirePermissions } from '../../middleware/permissions.js'
import { IntegrationPermission } from '../../types/permissions.js'
import { revokeBatchAttestations } from '../../services/attestation/revokeBatch.js'

const attestationsRouter = Router()

/**
 * POST /api/v1/admin/attestations/revoke-batch
 * Revoke multiple attestations in one call
 */
attestationsRouter.post(
  '/attestations/revoke-batch',
  requirePermissions(IntegrationPermission.ADMIN_MANAGE_USERS),
  async (req, res) => {
    const schema = z.object({
      attestationIds: z.array(z.string()).max(500)
    })
    const parsed = schema.safeParse(req.body)
    if (!parsed.success) {
      return res.status(400).json({ error: 'Bad Request', message: 'Invalid attestationIds array' })
    }

    try {
      const revoked = await revokeBatchAttestations(parsed.data.attestationIds, req.user!.id)
      const count = Array.isArray(revoked) ? revoked.length : revoked.revoked.length
      res.json({ message: 'Batch revoked successfully', count })
    } catch (error: any) {
      res.status(500).json({ error: 'Internal Server Error', message: error.message })
    }
  }
)

export default attestationsRouter
