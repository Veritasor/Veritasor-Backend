import { Request, Response, NextFunction } from 'express';

declare global {
  namespace Express {
    interface Request {

      user?: {
        id: string;
        userId: string;
        email?: string;
      };

      user?: { id: string; email?: string };

    }
  }
}

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  const userId = req.headers['x-user-id'] as string;
  if (!userId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  req.user = { id: userId, userId };
  req.user = { userId: userId, email: '' };
  next();
}
