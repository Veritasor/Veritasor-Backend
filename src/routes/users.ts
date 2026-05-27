import { Router } from 'express'
import { requireAuth } from '../middleware/requireAuth.js'
import updateProfile from '../services/user/updateProfile.js'

export const usersRouter = Router()

// PATCH /api/users/me - update current user's profile
usersRouter.patch('/me', requireAuth, async (req: any, res: any) => {
  try {
    const body = req.body ?? {}

    // Validate allowed fields
    const allowed = ['name', 'profile']
    const updates: Record<string, any> = {}
    for (const k of allowed) {
      if (k in body) updates[k] = body[k]
    }

    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ message: 'No updatable fields provided' })
    }

    const userId = req.user.id
    const updated = await updateProfile(userId, updates)
    return res.json(updated)
  } catch (err: any) {
    return res.status(400).json({ message: err?.message ?? 'Invalid input' })
  }
})

export default usersRouter
