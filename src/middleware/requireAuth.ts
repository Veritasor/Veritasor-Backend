import { Request, Response, NextFunction } from 'express'
import { verifyToken } from '../utils/jwt.js'
import { findUserById } from '../repositories/userRepository.js'

/**
 * Middleware to verify JWT token from Authorization header
 * Attaches user to req.user if valid
 */
export async function requireAuth(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  const authHeader = req.headers.authorization

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Missing or invalid authorization header' })
    return
  }

  const token = authHeader.slice(7) // Remove 'Bearer ' prefix

  const payload = verifyToken(token)
  if (!payload) {
    res.status(401).json({ error: 'Invalid or expired token' })
    return
  }

  // Optionally verify user still exists
  const user = await findUserById(payload.userId)
  if (!user) {
    res.status(401).json({ error: 'User not found' })
    return
  }

  req.user = { id: payload.userId, email: payload.email }

  next()
}
