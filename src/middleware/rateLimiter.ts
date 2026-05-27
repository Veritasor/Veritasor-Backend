import { Request, Response, NextFunction } from "express";
import { logger } from "../utils/logger.js";

type RateLimiterBucketResolver = string | ((req: Request) => string);

interface RateLimiterOptions {
  windowMs?: number;
  max?: number;
  bucket?: RateLimiterBucketResolver;
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
  memoryStore.cleanup(now);
}

setInterval(() => {
  cleanupRateLimiterStore();
}, 60 * 1000).unref();

/**
 * Create a rate limiter with optional route-level buckets.
 * Supports Redis store backing with in-memory fallback.
 */
export const rateLimiter = (options: RateLimiterOptions = {}) => {
  const windowMs = options.windowMs ?? parsePositiveInteger(process.env.RATE_LIMIT_WINDOW_MS, DEFAULT_WINDOW_MS);
  const max = options.max ?? parsePositiveInteger(process.env.RATE_LIMIT_MAX, DEFAULT_MAX);

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
