import { Router } from 'express'
import { requirePermissions } from '../../middleware/permissions.js'
import { IntegrationPermission } from '../../types/permissions.js'
import { getAllUsers, updateUser, deleteUser, findUserById } from '../../repositories/userRepository.js'
import { createAuditLog } from '../../repositories/auditLogRepository.js'

const usersRouter = Router()

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

/**
 * GET /api/v1/admin/users
 * List all users
 */
usersRouter.get(
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
usersRouter.patch(
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
 * DELETE /api/v1/admin/users/:id
 * Delete a user
 */
usersRouter.delete(
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

export default usersRouter
