import { Request, Response, NextFunction } from 'express';

interface RateLimiterOptions {
  windowMs?: number;
  max?: number;
}

interface RateLimitRecord {
  count: number;
  resetTime: number;
}

// Simple in-memory store for rate limiting
const store = new Map<string, RateLimitRecord>();

// Cleanup interval to prevent memory leaks by removing expired records
setInterval(() => {
  const now = Date.now();
  for (const [key, record] of store.entries()) {
    if (now > record.resetTime) {
      store.delete(key);
    }
  }
}, 60 * 1000).unref(); // Run every minute, unref so it doesn't block Node exit

export const rateLimiter = (options: RateLimiterOptions = {}) => {
  // Use provided options or default to env variables / sane defaults
  // e.g. 15 minutes window, 100 maximum requests per window
  const windowMs = options.windowMs ?? parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000', 10);
  const max = options.max ?? parseInt(process.env.RATE_LIMIT_MAX || '100', 10);

  return (req: Request, res: Response, next: NextFunction): void => {
    // Determine the identifier (user ID if authenticated, otherwise IP address)
    // Add type cast to 'any' for req.user to avoid typescript issues
    const user = (req as any).user;
    
    let identifier: string;
    if (user && user.userId) {
      identifier = `user:${user.userId}`;
    } else {
      identifier = `ip:${req.ip || req.socket.remoteAddress || 'unknown'}`;
    }

    const now = Date.now();
    let record = store.get(identifier);

    // If no record exists or the current window has expired, reset the counter
    if (!record || now > record.resetTime) {
      record = { count: 0, resetTime: now + windowMs };
      store.set(identifier, record);
    }

    // Increment request count
    record.count++;

    // Check if limits exceeded
    if (record.count > max) {
      res.status(429).json({ error: 'Too many requests, please try again later.' });
      return;
    }

    next();
  };
};
