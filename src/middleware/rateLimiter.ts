import { Request, Response, NextFunction } from "express";

type RateLimiterBucketResolver = string | ((req: Request) => string);

interface RateLimiterOptions {
  windowMs?: number;
  max?: number;
  bucket?: RateLimiterBucketResolver;
}

interface RateLimitRecord {
  count: number;
  resetTime: number;
}

const DEFAULT_WINDOW_MS = 15 * 60 * 1000;
const DEFAULT_MAX = 100;
const store = new Map<string, RateLimitRecord>();

function parsePositiveInteger(value: string | undefined, fallback: number): number {
  const parsed = Number.parseInt(value ?? "", 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function getClientIdentifier(req: Request): string {
  if (req.user?.userId) {
    return `user:${req.user.userId}`;
  }

  const forwardedFor = req.headers["x-forwarded-for"];
  if (typeof forwardedFor === "string" && forwardedFor.trim().length > 0) {
    return `ip:${forwardedFor.split(",")[0].trim()}`;
  }

  return `ip:${req.ip || req.socket.remoteAddress || "unknown"}`;
}

function getDefaultBucket(req: Request): string {
  const routePath = req.route?.path;
  const normalizedRoute = typeof routePath === "string" ? routePath : req.path || req.originalUrl || "unknown";
  return `${req.method}:${req.baseUrl || ""}${normalizedRoute}`;
}

function resolveBucket(req: Request, bucket: RateLimiterBucketResolver | undefined): string {
  if (typeof bucket === "function") {
    const resolved = bucket(req).trim();
    return resolved.length > 0 ? resolved : getDefaultBucket(req);
  }

  if (typeof bucket === "string" && bucket.trim().length > 0) {
    return bucket.trim();
  }

  return getDefaultBucket(req);
}

function applyRateLimitHeaders(
  res: Response,
  bucket: string,
  max: number,
  record: RateLimitRecord,
  now: number,
): void {
  const retryAfterSeconds = Math.max(1, Math.ceil((record.resetTime - now) / 1000));
  const remaining = Math.max(0, max - record.count);

  res.setHeader("Retry-After", retryAfterSeconds.toString());
  res.setHeader("X-RateLimit-Bucket", bucket);
  res.setHeader("X-RateLimit-Limit", max.toString());
  res.setHeader("X-RateLimit-Remaining", remaining.toString());
  res.setHeader("X-RateLimit-Reset", record.resetTime.toString());
}

export function cleanupRateLimiterStore(now = Date.now()): void {
  for (const [key, record] of store.entries()) {
    if (now > record.resetTime) {
      store.delete(key);
    }
  }
}

setInterval(() => {
  cleanupRateLimiterStore();
}, 60 * 1000).unref();

/**
 * Create an in-memory rate limiter with optional route-level buckets.
 *
 * Bucketed limits isolate sensitive routes from one another so abuse against
 * one endpoint does not consume the request budget for a different endpoint.
 */
export const rateLimiter = (options: RateLimiterOptions = {}) => {
  const windowMs = options.windowMs ?? parsePositiveInteger(process.env.RATE_LIMIT_WINDOW_MS, DEFAULT_WINDOW_MS);
  const max = options.max ?? parsePositiveInteger(process.env.RATE_LIMIT_MAX, DEFAULT_MAX);

  return (req: Request, res: Response, next: NextFunction): void => {
    const bucket = resolveBucket(req, options.bucket);
    const identifier = getClientIdentifier(req);
    const key = `${bucket}:${identifier}`;
    const now = Date.now();

    let record = store.get(key);
    if (!record || now > record.resetTime) {
      record = { count: 0, resetTime: now + windowMs };
      store.set(key, record);
    }

    record.count += 1;
    applyRateLimitHeaders(res, bucket, max, record, now);

    if (record.count > max) {
      res.status(429).json({ error: "Too many requests, please try again later." });
      return;
    }

    next();
  };
};

export function resetRateLimiterStore(): void {
  store.clear();
}
