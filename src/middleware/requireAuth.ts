import { Request, Response, NextFunction } from "express";
import { verifyToken } from "../utils/jwt.js";
import { findUserById } from "../repositories/userRepository.js";
import { AuthenticationError } from "../types/errors.js";

/**
 * Middleware to verify JWT token from Authorization header
 * Attaches user to req.user if valid
 */
export async function requireAuth(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return next(new AuthenticationError("Missing or invalid authorization header"));
  }

  const token = authHeader.slice(7); // Remove 'Bearer ' prefix

  const payload = verifyToken(token);
  if (!payload) {
    return next(new AuthenticationError("Invalid or expired token"));
  }

  // Optionally verify user still exists
  let user;
  try {
    user = await findUserById(payload.userId);
    if (!user) {
      return next(new AuthenticationError("User not found"));
    }
  } catch (err) {
    return next(err);
  }

  req.user = {
    id: payload.userId,
    userId: payload.userId,
    email: payload.email,
    role: user.role,
  };

  next();
}
