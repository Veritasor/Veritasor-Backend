import { Router, Request, Response } from 'express'
import { login } from '../services/auth/login.js'
import { refresh } from '../services/auth/refresh.js'
import { signup } from '../services/auth/signup.js'
import { forgotPassword } from '../services/auth/forgotPassword.js'
import { resetPassword } from '../services/auth/resetPassword.js'
import { me } from '../services/auth/me.js'
import { requireAuth } from '../middleware/requireAuth.js'

export const authRouter = Router()

/**
 * POST /api/v1/auth/login
 * Login with email and password
 */
authRouter.post('/login', async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body
    const result = await login({ email, password })
    res.json(result)
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Login failed'
    res.status(401).json({ error: message })
  }
})

/**
 * POST /api/v1/auth/refresh
 * Refresh access token using refresh token
 */
authRouter.post('/refresh', async (req: Request, res: Response) => {
  try {
    const { refreshToken } = req.body
    const result = await refresh({ refreshToken })
    res.json(result)
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Refresh failed'
    res.status(401).json({ error: message })
  }
})

/**
 * POST /api/v1/auth/signup
 * Create a new user account
 */
authRouter.post('/signup', async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body
    const result = await signup({ email, password })
    res.status(201).json(result)
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Signup failed'
    res.status(400).json({ error: message })
  }
})

/**
 * POST /api/v1/auth/forgot-password
 * Request password reset link
 */
authRouter.post('/forgot-password', async (req: Request, res: Response) => {
  try {
    const { email } = req.body
    const result = await forgotPassword({ email })
    res.json(result)
  } catch (error) {
    const message =
      error instanceof Error ? error.message : 'Forgot password request failed'
    res.status(400).json({ error: message })
  }
})

/**
 * POST /api/v1/auth/reset-password
 * Reset password with reset token
 */
authRouter.post('/reset-password', async (req: Request, res: Response) => {
  try {
    const { token, newPassword } = req.body
    const result = await resetPassword({ token, newPassword })
    res.json(result)
  } catch (error) {
    const message =
      error instanceof Error ? error.message : 'Password reset failed'
    res.status(400).json({ error: message })
  }
})

/**
 * GET /api/v1/auth/me
 * Get current user info (protected route)
 */
authRouter.get('/me', requireAuth, async (req: Request, res: Response) => {
  try {
    if (!req.user) {
      res.status(401).json({ error: 'User not authenticated' })
      return
    }
    const result = await me(req.user.id)
    res.json(result)
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Failed to get user'
    res.status(400).json({ error: message })
  }
})
