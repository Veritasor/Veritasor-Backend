import { Request, Response, NextFunction } from 'express';

export function simpleAuth(req: Request, res: Response, next: NextFunction) {
  const userId = req.headers['x-user-id'] as string;
  if (!userId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  req.user = { userId, email: '' };
  next();
}