import { Router } from 'express'
import { requireAuth } from '../middleware/requireAuth.js'
import { requirePermissions } from '../middleware/permissions.js'
import { IntegrationPermission } from '../types/permissions.js'
import { getAllUsers, updateUser, deleteUser, findUserById } from '../repositories/userRepository.js'
import { getAllAuditLogs, createAuditLog } from '../repositories/auditLogRepository.js'
import * as attestationRepository from '../repositories/attestationRepository.js'
import { db } from '../db/client.js'

const adminRouter = Router()

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
    try {
      const { id } = req.params
      const updates = req.body
      
      const user = await findUserById(id)
      if (!user) {
        return res.status(404).json({ error: 'Not Found', message: 'User not found' })
      }
      
      const updatedUser = await updateUser(id, updates)
      
      await createAuditLog({
        userId: req.user!.id,
        action: 'UPDATE_USER',
        resource: 'user',
        resourceId: id,
        metadata: { updates }
      })
      
      res.json(updatedUser)
    } catch (error: any) {
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
    try {
      const { id } = req.params
      
      const user = await findUserById(id)
      if (!user) {
        return res.status(404).json({ error: 'Not Found', message: 'User not found' })
      }
      
      await deleteUser(id)
      
      await createAuditLog({
        userId: req.user!.id,
        action: 'DELETE_USER',
        resource: 'user',
        resourceId: id,
        metadata: { deletedUserEmail: user.email }
      })
      
      res.sendStatus(204)
    } catch (error: any) {
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
