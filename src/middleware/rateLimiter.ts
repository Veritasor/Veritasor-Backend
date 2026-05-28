import { Request, Response, NextFunction } from "express";
import { logger } from "../utils/logger.js";
import { rateLimitRejections } from "../metrics.js";

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

export interface RateLimitRecord {
  count: number;
  resetTime: number;
}

export interface RateLimitStore {
  increment(key: string, windowMs: number): Promise<RateLimitRecord> | RateLimitRecord;
}

export class MemoryStore implements RateLimitStore {
  private store = new Map<string, RateLimitRecord>();

  increment(key: string, windowMs: number): RateLimitRecord {
    const now = Date.now();
    let record = this.store.get(key);
    if (!record || now > record.resetTime) {
      record = { count: 0, resetTime: now + windowMs };
      this.store.set(key, record);
    }

    record.count += 1;
    return record;
  }

  cleanup(now = Date.now()): void {
    for (const [key, record] of this.store.entries()) {
      if (now > record.resetTime) {
        this.store.delete(key);
      }
    }
  }

  reset(): void {
    this.store.clear();
  }
}

export class RedisStore implements RateLimitStore {
  constructor(private client: any) {}

  async increment(key: string, windowMs: number): Promise<RateLimitRecord> {
    const now = Date.now();
    
    // Execute atomic Lua script
    const [count, pttl] = await this.client.eval(
      `local current = redis.call('INCR', KEYS[1])
       if current == 1 then
         redis.call('PEXPIRE', KEYS[1], ARGV[1])
       end
       return {current, redis.call('PTTL', KEYS[1])}`,
      {
        keys: [key],
        arguments: [windowMs.toString()],
      }
    );

    // Calculate resetTime from the actual TTL returned by Redis
    const remainingTtl = pttl > 0 ? pttl : windowMs;
    return {
      count: Number(count),
      resetTime: now + remainingTtl,
    };
  }
}

const DEFAULT_WINDOW_MS = 15 * 60 * 1000;
const DEFAULT_MAX = 100;

export const memoryStore = new MemoryStore();
let storePromise: Promise<RateLimitStore> | null = null;

export function getStore(): Promise<RateLimitStore> {
  if (!storePromise) {
    storePromise = (async () => {
      const redisUrl = process.env.REDIS_URL;
      if (!redisUrl) {
        return memoryStore;
      }
      try {
        // @ts-expect-error redis is an optional dependency
        const redisModule = await import("redis");
        const client = redisModule.createClient({ url: redisUrl });
        
        client.on("error", (err: any) => {
          logger.error("Redis connection error in rate limiter store:", err);
        });

        await client.connect();
        logger.info("Rate limiter initialized with Redis store.");
        return new RedisStore(client);
      } catch (err) {
        logger.error("Failed to initialize Redis rate limiter store, falling back to memory:", err);
        return memoryStore;
      }
    })();
  }
  return storePromise;
}

export function resetStorePromise(): void {
  storePromise = null;
}

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
  memoryStore.cleanup(now);
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
 * Create a rate limiter with optional route-level buckets.
 * Supports Redis store backing with in-memory fallback.
 */
export const rateLimiter = (options: RateLimiterOptions = {}) => {
  const windowMs = options.windowMs ?? parsePositiveInteger(process.env.RATE_LIMIT_WINDOW_MS, DEFAULT_WINDOW_MS);
  const max = options.max ?? parsePositiveInteger(process.env.RATE_LIMIT_MAX, DEFAULT_MAX);
  const algorithm: RateLimiterAlgorithm = options.algorithm ?? "fixed";

  return (req: Request, res: Response, next: NextFunction): void => {
    const bucket = resolveBucket(req, options.bucket);
    const identifier = getClientIdentifier(req);
    const key = `rate-limit:${bucket}:${identifier}`;
    const now = Date.now();

    // Check synchronously if we are using the in-memory store
    if (!process.env.REDIS_URL) {
      try {
        const record = memoryStore.increment(key, windowMs);
        applyRateLimitHeaders(res, bucket, max, record, now);

        if (record.count > max) {
          logger.warn(
            `Rate limit exceeded for bucket "${bucket}" and identifier "${identifier}".`,
            JSON.stringify({
              bucket,
              identifier,
              count: record.count,
              max,
              windowMs,
              timestamp: new Date(now).toISOString(),
            })
          );
          rateLimitRejections.inc({ bucket });
          res.status(429).json({ error: "Too many requests, please try again later." });
          return;
        }

        next();
      } catch (err) {
        logger.error("Critical error in rateLimiter middleware (sync):", err);
        next();
      }
      return;
    }

    // Otherwise, async Redis path
    getStore()
      .then((store) => store.increment(key, windowMs))
      .catch((err) => {
        logger.error(`Rate limit store failed for key ${key}, falling back to memory:`, err);
        return memoryStore.increment(key, windowMs);
      })
      .then((record) => {
        applyRateLimitHeaders(res, bucket, max, record, now);

        if (record.count > max) {
          logger.warn(
            `Rate limit exceeded for bucket "${bucket}" and identifier "${identifier}".`,
            JSON.stringify({
              bucket,
              identifier,
              count: record.count,
              max,
              windowMs,
              timestamp: new Date(now).toISOString(),
            })
          );
          rateLimitRejections.inc({ bucket });
          res.status(429).json({ error: "Too many requests, please try again later." });
          return;
        }

        next();
      })
      .catch((err) => {
        logger.error("Critical error in rateLimiter middleware (async):", err);
        next();
      });
  };
};

export function resetRateLimiterStore(): void {
  memoryStore.reset();
}
