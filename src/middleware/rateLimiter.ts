import { Request, Response, NextFunction } from "express";
import { logger } from "../utils/logger.js";

type RateLimiterBucketResolver = string | ((req: Request) => string);

/**
 * Algorithm options for the rate limiter.
 *
 * - `"fixed"` (default): counts requests within a fixed calendar window.
 *   Simple and cheap, but allows a burst of up to `2 * max` requests
 *   across a window boundary.
 *
 * - `"sliding"`: counts requests in a rolling window that ends at the
 *   current instant.  No boundary burst is possible; every window is
 *   exactly `windowMs` wide no matter when it is measured.  Use this for
 *   sensitive buckets such as `auth:login` and `auth:forgot-password`.
 */
type RateLimiterAlgorithm = "fixed" | "sliding";

interface RateLimiterOptions {
  windowMs?: number;
  max?: number;
  bucket?: RateLimiterBucketResolver;
  /**
   * Rate-limiting algorithm to use.
   * Defaults to `"fixed"` for backward compatibility.
   */
  algorithm?: RateLimiterAlgorithm;
}

// --- Fixed-window store ---

interface RateLimitRecord {
  count: number;
  resetTime: number;
}

const store = new Map<string, RateLimitRecord>();

// --- Sliding-window store ---

/**
 * Each entry is a sorted list of request timestamps (ms since epoch) within
 * the current sliding window. Old timestamps are pruned on every access so
 * memory stays bounded to at most `max + 1` entries per key.
 */
const slidingStore = new Map<string, number[]>();

// --- Helpers ---

const DEFAULT_WINDOW_MS = 15 * 60 * 1000;
const DEFAULT_MAX = 100;

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
  count: number,
  resetTime: number,
  now: number,
): void {
  const retryAfterSeconds = Math.max(1, Math.ceil((resetTime - now) / 1000));
  const remaining = Math.max(0, max - count);

  res.setHeader("Retry-After", retryAfterSeconds.toString());
  res.setHeader("X-RateLimit-Bucket", bucket);
  res.setHeader("X-RateLimit-Limit", max.toString());
  res.setHeader("X-RateLimit-Remaining", remaining.toString());
  res.setHeader("X-RateLimit-Reset", resetTime.toString());
}

// --- Public cleanup / reset helpers ---

export function cleanupRateLimiterStore(now = Date.now()): void {
  for (const [key, record] of store.entries()) {
    if (now > record.resetTime) {
      store.delete(key);
    }
  }
}

export function cleanupSlidingStore(now = Date.now(), windowMs = DEFAULT_WINDOW_MS): void {
  const cutoff = now - windowMs;
  for (const [key, timestamps] of slidingStore.entries()) {
    const pruned = timestamps.filter((t) => t > cutoff);
    if (pruned.length === 0) {
      slidingStore.delete(key);
    } else {
      slidingStore.set(key, pruned);
    }
  }
}

setInterval(() => {
  cleanupRateLimiterStore();
  cleanupSlidingStore();
}, 60 * 1000).unref();

/**
 * Create an in-memory rate limiter with optional route-level buckets.
 *
 * Bucketed limits isolate sensitive routes from one another so abuse against
 * one endpoint does not consume the request budget for a different endpoint.
 *
 * ### Algorithms
 *
 * **Fixed window** (`algorithm: "fixed"`, default)
 * Requests are counted inside a fixed calendar window that resets every
 * `windowMs` milliseconds. A client can legally send up to `2 * max`
 * requests across a single window boundary (one full window's worth just
 * before the reset and another just after). Choose this for general-purpose
 * routes where a short burst is acceptable.
 *
 * **Sliding window** (`algorithm: "sliding"`)
 * Counts only the requests that arrived within the last `windowMs`
 * milliseconds, measured from *now*. This eliminates the boundary burst: no
 * matter when a client makes its requests the effective limit is always
 * exactly `max` per `windowMs`. Use this for sensitive buckets such as
 * `auth:login` and `auth:forgot-password`.
 */
export const rateLimiter = (options: RateLimiterOptions = {}) => {
  const windowMs = options.windowMs ?? parsePositiveInteger(process.env.RATE_LIMIT_WINDOW_MS, DEFAULT_WINDOW_MS);
  const max = options.max ?? parsePositiveInteger(process.env.RATE_LIMIT_MAX, DEFAULT_MAX);
  const algorithm: RateLimiterAlgorithm = options.algorithm ?? "fixed";

  return (req: Request, res: Response, next: NextFunction): void => {
    const bucket = resolveBucket(req, options.bucket);
    const identifier = getClientIdentifier(req);
    const key = `${bucket}:${identifier}`;
    const now = Date.now();

    if (algorithm === "sliding") {
      // --- Sliding-window path ---
      const cutoff = now - windowMs;
      const timestamps = (slidingStore.get(key) ?? []).filter((t) => t > cutoff);

      // Record this request
      timestamps.push(now);
      slidingStore.set(key, timestamps);

      const count = timestamps.length;
      // Reset time = oldest timestamp in the window + windowMs (when it will fall off)
      const resetTime = timestamps[0] + windowMs;

      applyRateLimitHeaders(res, bucket, max, count, resetTime, now);

      if (count > max) {
        logger.warn(
          `Rate limit exceeded for bucket "${bucket}" and identifier "${identifier}".`,
          JSON.stringify({
            bucket,
            identifier,
            count,
            max,
            windowMs,
            algorithm: "sliding",
            timestamp: new Date(now).toISOString(),
          }),
        );
        res.status(429).json({ error: "Too many requests, please try again later." });
        return;
      }

      next();
      return;
    }

    // --- Fixed-window path (default, backward compatible) ---
    let record = store.get(key);
    if (!record || now > record.resetTime) {
      record = { count: 0, resetTime: now + windowMs };
      store.set(key, record);
    }

    record.count += 1;
    applyRateLimitHeaders(res, bucket, max, record.count, record.resetTime, now);

    if (record.count > max) {
      logger.warn(
        `Rate limit exceeded for bucket "${bucket}" and identifier "${identifier}".`,
        JSON.stringify({
          bucket,
          identifier,
          count: record.count,
          max,
          windowMs,
          algorithm: "fixed",
          timestamp: new Date(now).toISOString(),
        }),
      );
      res.status(429).json({ error: "Too many requests, please try again later." });
      return;
    }

    next();
  };
};

export function resetRateLimiterStore(): void {
  store.clear();
  slidingStore.clear();
}
