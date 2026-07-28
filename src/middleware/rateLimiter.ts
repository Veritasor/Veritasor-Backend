import { Request, Response, NextFunction } from "express";
import { randomUUID } from "node:crypto";
import { logger } from "../utils/logger.js";
import { rateLimitRejections, redisClusterRedirectionsTotal } from "../metrics.js";
import {
  getRedisClient,
  hashTag,
  redisCircuitBreaker,
  parseClusterRedirectionError,
  resolveTargetClient,
} from "../redis.js";


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

const DEFAULT_MAX_REDIRECTIONS = 5;

export class RedisStore implements RateLimitStore {
  constructor(
    private client: ReturnType<typeof getRedisClient>,
    private maxRedirections: number = DEFAULT_MAX_REDIRECTIONS,
  ) {}

  async increment(key: string, windowMs: number): Promise<RateLimitRecord> {
    const now = Date.now();
    let targetClient: any = this.client;
    let redirectionCount = 0;
    const visitedTargets = new Set<string>();

    while (true) {
      try {
        const result = await redisCircuitBreaker.execute(() =>
          targetClient.eval(
            `local current = redis.call('INCR', KEYS[1])
             if current == 1 then
               redis.call('PEXPIRE', KEYS[1], ARGV[1])
             end
             return {current, redis.call('PTTL', KEYS[1])}`,
            1,           // numkeys
            key,         // KEYS[1]
            windowMs     // ARGV[1]
          )
        ) as [number, number];

        const [count, pttl] = result;
        const remainingTtl = pttl > 0 ? pttl : windowMs;
        return {
          count: Number(count),
          resetTime: now + remainingTtl,
        };
      } catch (err) {
        const redirect = parseClusterRedirectionError(err);
        if (redirect && redirectionCount < this.maxRedirections) {
          redirectionCount++;

          const targetKey = `${redirect.type}:${redirect.targetAddress}`;
          if (visitedTargets.has(targetKey)) {
            throw new Error(
              `RedisStore: infinite redirection loop detected for key "${key}" to ${redirect.targetAddress}`
            );
          }
          visitedTargets.add(targetKey);

          redisClusterRedirectionsTotal.inc({
            type: redirect.type.toLowerCase() as "moved" | "ask",
            store: "fixed",
          });

          if (redirect.type === "MOVED" && typeof (this.client as any).refreshSlotsCache === "function") {
            await (this.client as any).refreshSlotsCache().catch(() => {});
          }

          targetClient = await resolveTargetClient(this.client, redirect);
          continue;
        }

        throw err;
      }
    }
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Full-jitter exponential backoff, capped, for retrying a WATCH-aborted
 * transaction. Jitter (not a fixed delay) avoids every contending client
 * retrying in lockstep and re-colliding.
 */


function jitterBackoffMs(attempt: number, baseMs = 5, capMs = 50): number {
  const exp = Math.min(capMs, baseMs * 2 ** attempt);
  return Math.random() * exp;
}

const DEFAULT_MAX_WATCH_RETRIES = 10;

/**
 * Sliding-window rate limiter backed by a Redis sorted set (the "sliding
 * log" pattern): each request adds its own timestamp as a member, entries
 * older than the window are pruned, and the set's cardinality is the count.
 *
 * Pruning, adding, and counting are three separate Redis commands, so they
 * are wrapped in WATCH/MULTI/EXEC: if another client mutates this exact key
 * between WATCH and EXEC, ioredis returns `null` from `exec()` and we retry
 * with jittered backoff, up to `maxRetries`, to guard against an abort loop
 * under heavy contention on a single hot key.
 *
 * Single-key transaction, so this is Redis Cluster-safe without any hash
 * tagging — WATCH/MULTI/EXEC only requires same-slot keys, and there is
 * only ever one key involved here.
 */
export class SlidingWindowRedisStore implements RateLimitStore {
  constructor(
    private client: ReturnType<typeof getRedisClient>,
    private maxRetries: number = DEFAULT_MAX_WATCH_RETRIES,
    private maxRedirections: number = DEFAULT_MAX_REDIRECTIONS,
  ) {}

  async increment(key: string, windowMs: number): Promise<RateLimitRecord> {
    const now = Date.now();
    const windowStart = now - windowMs;
    // A unique member per request, even if two requests land in the same
    // millisecond, so ZADD never silently collapses two requests into one
    // sorted-set entry.
    const member = `${now}-${randomUUID()}`;

    let targetClient: any = this.client;
    let redirectionCount = 0;
    const visitedTargets = new Set<string>();

    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      try {
        if (typeof targetClient.watch === "function") {
          await targetClient.watch(key);
        }

        const multi = targetClient.multi();
        multi.zremrangebyscore(key, 0, windowStart);
        multi.zadd(key, now, member);
        multi.zcard(key);
        multi.pexpire(key, windowMs);

        const results = await multi.exec();

        if (results === null) {
          // WATCH detected a concurrent write to this key between WATCH
          // and EXEC — someone else's transaction won the race. Back off
          // with jitter and retry rather than looping tightly.
          await sleep(jitterBackoffMs(attempt));
          continue;
        }

        if (Array.isArray(results)) {
          for (const res of results) {
            if (Array.isArray(res) && res[0]) {
              const redirectInResult = parseClusterRedirectionError(res[0]);
              if (redirectInResult) {
                throw res[0];
              }
            }
          }
        }

        const [zcardErr, count] = results[2] as [Error | null, number];
        if (zcardErr) throw zcardErr;

        return { count: Number(count), resetTime: now + windowMs };
      } catch (err) {
        if (typeof targetClient.unwatch === "function") {
          await targetClient.unwatch().catch(() => {});
        }

        const redirect = parseClusterRedirectionError(err);
        if (redirect && redirectionCount < this.maxRedirections) {
          redirectionCount++;

          const targetKey = `${redirect.type}:${redirect.targetAddress}`;
          if (visitedTargets.has(targetKey)) {
            throw new Error(
              `SlidingWindowRedisStore: infinite redirection loop detected for key "${key}" to ${redirect.targetAddress}`
            );
          }
          visitedTargets.add(targetKey);

          redisClusterRedirectionsTotal.inc({
            type: redirect.type.toLowerCase() as "moved" | "ask",
            store: "sliding",
          });

          if (redirect.type === "MOVED" && typeof (this.client as any).refreshSlotsCache === "function") {
            await (this.client as any).refreshSlotsCache().catch(() => {});
          }

          targetClient = await resolveTargetClient(this.client, redirect);
          attempt--;
          continue;
        }

        if (attempt === this.maxRetries) throw err;
      }
    }

    throw new Error(
      `SlidingWindowRedisStore: exceeded ${this.maxRetries} retries due to repeated WATCH aborts for key "${key}"`,
    );
  }
}

const slidingStore = new Map<string, number[]>();

/**
 * In-memory equivalent of the sliding-log algorithm, so "sliding" behaves
 * identically whether or not Redis is configured (single process, so no
 * WATCH/MULTI/EXEC is needed — the whole operation already runs
 * synchronously and atomically with respect to Node's single-threaded
 * event loop).
 */
export class SlidingWindowMemoryStore implements RateLimitStore {
  constructor(private store: Map<string, number[]> = slidingStore) {}

  increment(key: string, windowMs: number): RateLimitRecord {
    const now = Date.now();
    const windowStart = now - windowMs;
    const timestamps = (this.store.get(key) ?? []).filter((t) => t > windowStart);
    timestamps.push(now);
    this.store.set(key, timestamps);
    return { count: timestamps.length, resetTime: now + windowMs };
  }

  reset(): void {
    this.store.clear();
  }
}

export const slidingWindowMemoryStore = new SlidingWindowMemoryStore();

const DEFAULT_WINDOW_MS = 15 * 60 * 1000;
const DEFAULT_MAX = 100;

export const memoryStore = new MemoryStore();
const storePromises = new Map<RateLimiterAlgorithm, Promise<RateLimitStore>>();

export function getStore(algorithm: RateLimiterAlgorithm = "fixed"): Promise<RateLimitStore> {
  let storePromise = storePromises.get(algorithm);
  if (!storePromise) {
    storePromise = (async () => {
      const hasRedis = process.env.REDIS_URL || process.env.REDIS_CLUSTER_NODES;
      const fallback = algorithm === "sliding" ? slidingWindowMemoryStore : memoryStore;
      if (!hasRedis) {
        return fallback;
      }
      try {
        const client = getRedisClient();
        // Wait for ready before serving traffic
        await new Promise<void>((resolve, reject) => {
          if ((client as any).status === "ready") return resolve();
          client.once("ready", resolve);
          client.once("error", reject);
        });
        logger.info(`Rate limiter initialized with Redis store (algorithm: ${algorithm}).`);
        return algorithm === "sliding" ? new SlidingWindowRedisStore(client) : new RedisStore(client);
      } catch (err) {
        logger.error("Failed to initialize Redis rate limiter store, falling back to memory:", err);
        return fallback;
      }
    })();
    storePromises.set(algorithm, storePromise);
  }
  return storePromise;
}

export function resetStorePromise(): void {
  storePromises.clear();
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
    if (!process.env.REDIS_URL && !process.env.REDIS_CLUSTER_NODES) {
      try {
        const record =
          algorithm === "sliding"
            ? slidingWindowMemoryStore.increment(key, windowMs)
            : memoryStore.increment(key, windowMs);

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
    getStore(algorithm)
      .then((store) => store.increment(key, windowMs))
      .catch((err) => {
        logger.error(`Rate limit store failed for key ${key}, falling back to memory:`, err);
        return algorithm === "sliding"
          ? slidingWindowMemoryStore.increment(key, windowMs)
          : memoryStore.increment(key, windowMs);
      })
      .then((record) => {
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
  slidingWindowMemoryStore.reset();
}