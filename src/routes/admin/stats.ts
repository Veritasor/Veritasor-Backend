import { Router } from 'express'
import { requirePermissions } from '../../middleware/permissions.js'
import { IntegrationPermission } from '../../types/permissions.js'
import { getAllUsers } from '../../repositories/userRepository.js'
import * as attestationRepository from '../../repositories/attestationRepository.js'
import { db } from '../../db/client.js'

const statsRouter = Router()

/**
 * GET /api/v1/admin/stats
 * Get platform statistics
 */
statsRouter.get(
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

export default statsRouter
