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
import { redisCircuitBreakerState, redisCircuitBreakerFailuresTotal } from "./metrics.js";

export type RedisClient = Redis | Cluster;

let _client: RedisClient | null = null;
let _readonlyClient: RedisClient | null = null;

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
 * Build and cache a readonly Redis / Cluster client (routes reads to replicas in cluster mode).
 */
export function getReadonlyRedisClient(): RedisClient {
  if (_readonlyClient) return _readonlyClient;

  const clusterNodes = process.env.REDIS_CLUSTER_NODES;
  const redisUrl = process.env.REDIS_URL;

  if (clusterNodes) {
    const nodes = parseClusterNodes(clusterNodes);
    _readonlyClient = new Cluster(nodes, {
      redisOptions: { tls: process.env.REDIS_TLS === "true" ? {} : undefined },
      enableReadyCheck: true,
      clusterRetryStrategy: (times) => Math.min(times * 100, 2000),
      scaleReads: "slave",
    });
    (_readonlyClient as RedisClient).on("error", (err: Error) => logger.error("[redis] readonly client error", err));
  } else if (redisUrl) {
    // Single node Redis doesn't have a cluster topology to route to replicas automatically
    // via scaleReads, so fallback to the primary client.
    _readonlyClient = getRedisClient();
  } else {
    throw new Error("No Redis configuration: set REDIS_URL or REDIS_CLUSTER_NODES");
  }

  return _readonlyClient as RedisClient;
}

/**
 * Reset the cached client (test helper — do not use in production code).
 */
export function resetRedisClient(): void {
  _client = null;
  _readonlyClient = null;
}

/**
 * Send a PING to Redis and return "ok" or "error:<message>".
 * Never throws; safe to call from health / readiness endpoints.
 */
export async function redisHealthProbe(): Promise<"ok" | `error:${string}`> {
  try {
    if (redisCircuitBreaker.getState() === CircuitState.OPEN) {
      return "error:Circuit breaker is OPEN";
    }

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

/**
 * Circuit Breaker state
 */
export enum CircuitState {
  CLOSED = 0,
  OPEN = 1,
  HALF_OPEN = 2,
}

export interface CircuitBreakerOptions {
  failureThreshold: number;
  resetTimeoutMs: number;
}

export class RedisCircuitBreakerError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RedisCircuitBreakerError";
  }
}

/**
 * Client-side circuit breaker to prevent write thrashing during Redis cluster split-brain events.
 */
export class RedisCircuitBreaker {
  private state: CircuitState = CircuitState.CLOSED;
  private failures = 0;
  private nextAttemptMs = 0;
  private failureThreshold: number;
  private resetTimeoutMs: number;

  constructor(options?: Partial<CircuitBreakerOptions>) {
    this.failureThreshold = options?.failureThreshold ?? 5;
    this.resetTimeoutMs = options?.resetTimeoutMs ?? 10000;
    this.updateMetrics();
  }

  private updateMetrics(): void {
    redisCircuitBreakerState.set(this.state);
  }

  private transition(newState: CircuitState): void {
    this.state = newState;
    this.updateMetrics();
    if (newState === CircuitState.CLOSED) {
      this.failures = 0;
      this.nextAttemptMs = 0;
    } else if (newState === CircuitState.OPEN) {
      this.nextAttemptMs = Date.now() + this.resetTimeoutMs;
    }
  }

  /**
   * Execute a Redis operation through the circuit breaker.
   * If the circuit is OPEN, it either fails fast or returns the fallback result.
   */
  async execute<T>(
    operation: () => Promise<T>,
    fallback?: () => Promise<T> | T
  ): Promise<T> {
    if (this.state === CircuitState.OPEN) {
      if (Date.now() >= this.nextAttemptMs) {
        // Transition to half-open to test the connection
        this.transition(CircuitState.HALF_OPEN);
      } else {
        // Fail fast
        if (fallback) {
          return fallback();
        }
        throw new RedisCircuitBreakerError("Redis circuit breaker is OPEN");
      }
    }

    // In HALF_OPEN state, only allow one probe? Actually, a simple approach is letting
    // calls through and the first one will determine success/failure.
    // If we want strict half-open storm prevention, we could track if a probe is in flight,
    // but the issue says "Half-open storm prevention".
    // Let's implement half-open storm prevention by failing fast for other requests while probing.

    if (this.state === CircuitState.HALF_OPEN) {
      if (this.nextAttemptMs > Date.now()) {
        // We set nextAttemptMs to a future time when a probe starts so others fail fast
        if (fallback) return fallback();
        throw new RedisCircuitBreakerError("Redis circuit breaker is HALF_OPEN (probe in flight)");
      }
      // Set nextAttemptMs to a small future time to debounce multiple probes
      this.nextAttemptMs = Date.now() + this.resetTimeoutMs;
    }

    try {
      const result = await operation();
      if (this.state === CircuitState.HALF_OPEN) {
        this.transition(CircuitState.CLOSED);
      } else if (this.state === CircuitState.CLOSED) {
        this.failures = 0; // reset on success
      }
      return result;
    } catch (err) {
      this.recordFailure();
      throw err;
    }
  }

  private recordFailure(): void {
    redisCircuitBreakerFailuresTotal.inc();
    
    if (this.state === CircuitState.HALF_OPEN) {
      // Probe failed, go back to OPEN
      this.transition(CircuitState.OPEN);
      return;
    }
    
    if (this.state === CircuitState.CLOSED) {
      this.failures++;
      if (this.failures >= this.failureThreshold) {
        this.transition(CircuitState.OPEN);
      }
    }
  }

  /**
   * Reset the circuit breaker (for tests).
   */
  reset(): void {
    this.transition(CircuitState.CLOSED);
  }
  
  getState(): CircuitState {
    return this.state;
  }
}

export const redisCircuitBreaker = new RedisCircuitBreaker();
