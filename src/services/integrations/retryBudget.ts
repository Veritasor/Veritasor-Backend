import { config } from "../../config/index.js";
import { getRedisClient } from "../../redis.js";
import {
  integrationRetryTotal,
  integrationRetryBudgetExhaustedTotal,
  integrationRetryBudgetRemaining,
} from "../../metrics.js";

export class GlobalRetryBudgetExceededError extends Error {
  public readonly code = "GLOBAL_RETRY_BUDGET_EXCEEDED";
  public readonly currentRetryCount: number;
  public readonly budgetLimit: number;

  constructor(currentRetryCount: number, budgetLimit: number) {
    super(
      `Global outbound retry budget exhausted: ${currentRetryCount}/${budgetLimit} retries in the last ${config.integrations.retryBudget.windowMs / 1000} seconds.`,
    );
    this.name = "GlobalRetryBudgetExceededError";
    this.currentRetryCount = currentRetryCount;
    this.budgetLimit = budgetLimit;
  }
}

export class GlobalOutboundRetryBudget {
  private readonly redisKey = "retry-budget:global";
  private readonly windowMs: number;
  private readonly maxRetries: number;
  private readonly localAttempts: number[] = [];

  constructor(maxRetries?: number, windowMs?: number) {
    const defaultMax = config.integrations?.retryBudget?.maxRetries ?? 50;
    const defaultWindow = config.integrations?.retryBudget?.windowMs ?? 60_000;

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
      throw new GlobalRetryBudgetExceededError(count, this.maxRetries);
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
