import { config } from "../../config/index.js";
import { getRedisClient } from "../../redis.js";
import {
  integrationRetryTotal,
  integrationRetryBudgetExhaustedTotal,
  integrationRetryBudgetRemaining,
} from "../../metrics.js";

/** Default number of outbound retries allowed per window when config is absent. */
export const DEFAULT_RETRY_BUDGET_MAX_RETRIES = 50;

/** Default sliding-window size (ms) for the global outbound retry budget. */
export const DEFAULT_RETRY_BUDGET_WINDOW_MS = 60_000;

interface RetryBudgetSettings {
  maxRetries: number;
  windowMs: number;
}

/**
 * Read the optional `integrations.retryBudget` config block.
 *
 * The block is not part of the base config object, so it is read defensively:
 * an absent block must fall back to the documented defaults instead of
 * dereferencing `undefined`.
 */
function retryBudgetSettings(): RetryBudgetSettings {
  const integrations = (
    config as { integrations?: { retryBudget?: Partial<RetryBudgetSettings> } }
  ).integrations;
  return {
    maxRetries: integrations?.retryBudget?.maxRetries ?? DEFAULT_RETRY_BUDGET_MAX_RETRIES,
    windowMs: integrations?.retryBudget?.windowMs ?? DEFAULT_RETRY_BUDGET_WINDOW_MS,
  };
}

export class GlobalRetryBudgetExceededError extends Error {
  public readonly code = "GLOBAL_RETRY_BUDGET_EXCEEDED";
  public readonly currentRetryCount: number;
  public readonly budgetLimit: number;
  /** Size of the window the exhausted budget was measured over, in ms. */
  public readonly windowMs: number;

  constructor(
    currentRetryCount: number,
    budgetLimit: number,
    windowMs: number = DEFAULT_RETRY_BUDGET_WINDOW_MS,
  ) {
    super(
      `Global outbound retry budget exhausted: ${currentRetryCount}/${budgetLimit} retries in the last ${windowMs / 1000} seconds.`,
    );
    this.name = "GlobalRetryBudgetExceededError";
    this.currentRetryCount = currentRetryCount;
    this.budgetLimit = budgetLimit;
    this.windowMs = windowMs;
  }
}

export class GlobalOutboundRetryBudget {
  private readonly redisKey = "retry-budget:global";
  private readonly windowMs: number;
  private readonly maxRetries: number;
  private readonly localAttempts: number[] = [];

  constructor(maxRetries?: number, windowMs?: number) {
    const defaults = retryBudgetSettings();
    const defaultMax = defaults.maxRetries;
    const defaultWindow = defaults.windowMs;

    this.maxRetries = maxRetries ?? defaultMax;
    this.windowMs = windowMs ?? defaultWindow;

    if (this.maxRetries < 0) {
      throw new Error("Global outbound retry budget maxRetries must be non-negative");
    }
    if (this.windowMs <= 0) {
      throw new Error("Global outbound retry budget windowMs must be positive");
    }
    this.updateRemainingMetric(this.maxRetries);
  }

  /**
   * Check whether a retry is permitted under the global cap.
   */
  async canRetry(provider = "unknown", operation = "unknown"): Promise<boolean> {
    const currentCount = await this.getRetryCount();
    const allowed = currentCount < this.maxRetries;
    const remaining = Math.max(0, this.maxRetries - (allowed ? currentCount : this.maxRetries));

    this.updateRemainingMetric(remaining);

    if (!allowed) {
      integrationRetryBudgetExhaustedTotal.inc({ provider, operation });
    }

    return allowed;
  }

  /**
   * Record a retry attempt if budget permits.
   * Throws GlobalRetryBudgetExceededError if budget is exhausted.
   */
  async recordRetry(provider = "unknown", operation = "unknown"): Promise<void> {
    const allowed = await this.canRetry(provider, operation);
    if (!allowed) {
      const count = await this.getRetryCount();
      throw new GlobalRetryBudgetExceededError(count, this.maxRetries, this.windowMs);
    }

    const now = Date.now();
    let redisSaved = false;

    try {
      if (process.env.REDIS_URL || process.env.REDIS_CLUSTER_NODES) {
        const client = getRedisClient();
        const member = `${now}:${Math.random().toString(36).substring(2, 10)}`;
        await client.zadd(this.redisKey, now, member);
        await client.pexpire(this.redisKey, this.windowMs);
        redisSaved = true;
      }
    } catch {
      // Fallback to local memory if Redis errors out
    }

    if (!redisSaved) {
      this.localPrune(now);
      this.localAttempts.push(now);
    }

    integrationRetryTotal.inc({ provider, operation });

    const newCount = await this.getRetryCount();
    const remaining = Math.max(0, this.maxRetries - newCount);
    this.updateRemainingMetric(remaining);
  }

  /**
   * Returns current count of retries in active window.
   */
  async getRetryCount(): Promise<number> {
    const now = Date.now();
    const cutoff = now - this.windowMs;

    try {
      if (process.env.REDIS_URL || process.env.REDIS_CLUSTER_NODES) {
        const client = getRedisClient();
        await client.zremrangebyscore(this.redisKey, 0, cutoff);
        const count = await client.zcard(this.redisKey);
        return count;
      }
    } catch {
      // Fallback to local memory
    }

    this.localPrune(now);
    return this.localAttempts.length;
  }

  /**
   * Returns remaining available retries in active window.
   */
  async getRemainingBudget(): Promise<number> {
    const count = await this.getRetryCount();
    const remaining = Math.max(0, this.maxRetries - count);
    this.updateRemainingMetric(remaining);
    return remaining;
  }

  /**
   * Reset retry budget stores (useful for test isolation).
   */
  async reset(): Promise<void> {
    this.localAttempts.length = 0;
    try {
      if (process.env.REDIS_URL || process.env.REDIS_CLUSTER_NODES) {
        const client = getRedisClient();
        await client.del(this.redisKey);
      }
    } catch {
      // Ignore Redis errors during reset
    }
    this.updateRemainingMetric(this.maxRetries);
  }

  private localPrune(now = Date.now()): void {
    const cutoff = now - this.windowMs;
    while (this.localAttempts.length > 0 && this.localAttempts[0] < cutoff) {
      this.localAttempts.shift();
    }
  }

  private updateRemainingMetric(remaining: number): void {
    integrationRetryBudgetRemaining.set(remaining);
  }
}

export const globalOutboundRetryBudget = new GlobalOutboundRetryBudget();
