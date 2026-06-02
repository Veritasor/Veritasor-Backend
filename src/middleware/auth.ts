import { Request, Response, NextFunction } from "express";

declare global {
  namespace Express {
    interface Request {
      user?: {
        id: string;
        userId: string;
        email?: string;
        role?: 'user' | 'admin' | 'business_admin';
      };
    }
  }
}

import { AuthenticationError } from "../types/errors.js";

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  const userId = req.headers["x-user-id"] as string;
  if (!userId) {
    return next(new AuthenticationError());
  }
  req.user = { id: userId, userId, email: "" };
  next();
}
