/**
 * Redis client factory.
 *
 * Returns a single `Redis` instance when only REDIS_URL is set, or a
 * `Cluster` instance when REDIS_CLUSTER_NODES is set (comma-separated
 * list of host:port pairs). Cluster mode is preferred when both vars
 * are present.
 *
 * ioredis handles MOVED and ASK redirects automatically, so callers
 * do not need to do anything special during slot resharding.
 *
 * Health probe
 * ─────────────
 * Call `redisHealthProbe()` to get a fast "ok" / "error:<msg>" string
 * suitable for a readiness endpoint. It does a single PING with a 1 s
 * timeout and never throws.
 */

import IORedis from "ioredis";
import { Cluster } from "ioredis";
import type { Redis } from "ioredis";
import { logger } from "./utils/logger.js";

export type RedisClient = Redis | Cluster;

let _client: RedisClient | null = null;

/**
 * Parse REDIS_CLUSTER_NODES into the array ioredis Cluster expects.
 * Input: "host1:7000,host2:7001,host3:7002"
 */
function parseClusterNodes(raw: string): { host: string; port: number }[] {
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => {
      const lastColon = s.lastIndexOf(":");
      const host = s.slice(0, lastColon);
      const port = Number(s.slice(lastColon + 1));
      return { host, port };
    });
}

/**
 * Build and cache the Redis / Cluster client.
 * Subsequent calls return the same instance.
 */
export function getRedisClient(): RedisClient {
  if (_client) return _client;

  const clusterNodes = process.env.REDIS_CLUSTER_NODES;
  const redisUrl = process.env.REDIS_URL;

  if (clusterNodes) {
    const nodes = parseClusterNodes(clusterNodes);
    _client = new Cluster(nodes, {
      redisOptions: { tls: process.env.REDIS_TLS === "true" ? {} : undefined },
      // Let ioredis follow MOVED/ASK automatically.
      enableReadyCheck: true,
      clusterRetryStrategy: (times) => Math.min(times * 100, 2000),
    });
  } else if (redisUrl) {
    // ioredis default export is both the constructor value and the Redis type
    const RedisConstructor = IORedis as unknown as new (url: string, opts: object) => Redis;
    _client = new RedisConstructor(redisUrl, {
      tls: process.env.REDIS_TLS === "true" ? {} : undefined,
      enableReadyCheck: true,
      retryStrategy: (times: number) => Math.min(times * 100, 2000),
      maxRetriesPerRequest: 3,
    });
  } else {
    throw new Error("No Redis configuration: set REDIS_URL or REDIS_CLUSTER_NODES");
  }

  (_client as RedisClient).on("error", (err: Error) => logger.error("[redis] client error", err));

  return _client as RedisClient;
}

/**
 * Reset the cached client (test helper — do not use in production code).
 */
export function resetRedisClient(): void {
  _client = null;
}

/**
 * Send a PING to Redis and return "ok" or "error:<message>".
 * Never throws; safe to call from health / readiness endpoints.
 */
export async function redisHealthProbe(): Promise<"ok" | `error:${string}`> {
  try {
    const client = getRedisClient();
    const result = await Promise.race<string>([
      client.ping() as Promise<string>,
      new Promise<string>((_, reject) =>
        setTimeout(() => reject(new Error("ping timeout")), 1000)
      ),
    ]);
    return result === "PONG" ? "ok" : `error:unexpected ping response: ${result}`;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return `error:${msg}`;
  }
}

/**
 * Wrap a key with a hash tag so keys for the same business always land
 * on the same cluster slot. E.g. "rate-limit:{biz-123}:ip:1.2.3.4".
 *
 * Only the part inside `{}` determines the slot, so different key
 * types (rate-limit, idempotency) for the same businessId will share
 * a slot without colliding.
 */
export function hashTag(businessId: string): string {
  return `{${businessId}}`;
}
