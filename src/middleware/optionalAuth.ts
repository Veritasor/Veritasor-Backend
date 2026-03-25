import { Request, Response, NextFunction } from "express";
import { verifyToken } from "../utils/jwt.js";
import { findUserById } from "../repositories/userRepository.js";

// Extend Express Request to include user consistently across auth middlewares
declare global {
  namespace Express {
    interface Request {
      user?: {
        id: string;
        userId: string;
        email?: string;
      };
    }
  }
}

/**
 * Optional authentication middleware that attempts to authenticate requests
 * by verifying a JWT token in the Authorization header.
 *
 * Reliability & Consistency Improvements:
 * - Uses async/await to support database verification
 * - Verifies user existence in database if token is valid
 * - Clears req.user if database check fails
 * - Aligns with requireAuth naming conventions (id, userId)
 *
 * Security Assumptions:
 * - If no token is provided, request is treated as unauthenticated.
 * - If token is provided but invalid, request is treated as unauthenticated.
 * - If token is valid but user no longer exists in DB, request is treated as unauthenticated.
 * - This middleware NEVER returns 401 Unauthorized; use requireAuth for protected routes.
 *
 * @param req - Express Request object
 * @param res - Express Response object
 * @param next - Express NextFunction
 */
export async function optionalAuth(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  try {
    // Extract Authorization header
    const authHeader = req.headers.authorization;

    // If no Authorization header or doesn't start with "Bearer ", proceed without auth
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      next();
      return;
    }

    // Extract token by removing "Bearer " prefix (7 characters)
    const token = authHeader.slice(7);

    // Verify token using existing JWT verification logic
    const payload = verifyToken(token);

    // If token is valid, verify user existence and attach to request
    if (payload) {
      const user = await findUserById(payload.userId);

      if (user) {
        req.user = {
          id: user.id,
          userId: user.id,
          email: user.email,
        };
      } else {
        // Token was valid but user was not found (e.g., deleted)
        req.user = undefined;
      }
    }

    // Always proceed to next handler
    next();
  } catch (error) {
    // Handle any unexpected errors gracefully
    // Ensure req.user is undefined on error and proceed
    req.user = undefined;
    next();
  }
}
