import { Router } from 'express'
import { requireAuth } from '../middleware/requireAuth.js'
import updateProfile from '../services/user/updateProfile.js'
import { validateBody } from '../middleware/validate.js'
import { updateUserProfileSchema } from './users.schema.js'

export const usersRouter = Router()

// PATCH /api/users/me - update current user's profile
usersRouter.patch('/me', requireAuth, validateBody(updateUserProfileSchema), async (req: any, res: any) => {
  try {
    const updates = req.body

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
