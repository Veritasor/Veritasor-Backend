import { Request, Response, NextFunction } from 'express'
import { verifyToken } from '../utils/jwt.js'

/**
 * Optional authentication middleware that attempts to authenticate requests
 * but allows unauthenticated requests to proceed.
 * 
 * Unlike requireAuth, this middleware:
 * - Never returns 401 responses
 * - Does not verify user exists in database
 * - Always calls next() regardless of authentication status
 * 
 * If a valid JWT token is present, req.user will be set.
 * If no token or invalid token, req.user remains undefined.
 */
export function optionalAuth(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  try {
    // Extract Authorization header
    const authHeader = req.headers.authorization

    // If no Authorization header or doesn't start with "Bearer ", proceed without auth
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      next()
      return
    }

    // Extract token by removing "Bearer " prefix (7 characters)
    const token = authHeader.slice(7)

    // Verify token using existing JWT verification logic
    const payload = verifyToken(token)

    // If token is valid, attach user to request
    if (payload) {
      req.user = {
        userId: payload.userId,
        email: payload.email,
      }
    }

    // Always proceed to next handler
    next()
  } catch (error) {
    // Handle any unexpected errors gracefully
    // Leave req.user undefined and proceed
    next()
  }
}
