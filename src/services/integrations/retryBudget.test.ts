import { describe, it, expect, beforeEach, vi } from "vitest";
import {
  GlobalOutboundRetryBudget,
  GlobalRetryBudgetExceededError,
  globalOutboundRetryBudget,
} from "./retryBudget.js";
import * as redisModule from "../../redis.js";

describe("GlobalOutboundRetryBudget", () => {
  let budget: GlobalOutboundRetryBudget;

  beforeEach(async () => {
    delete process.env.REDIS_URL;
    delete process.env.REDIS_CLUSTER_NODES;
    budget = new GlobalOutboundRetryBudget(5, 1000);
    await budget.reset();
    await globalOutboundRetryBudget.reset();
  });

  it("initializes with configured budget capacity", async () => {
    const remaining = await budget.getRemainingBudget();
    expect(remaining).toBe(5);
  });

  it("throws error for invalid constructor parameters", () => {
    expect(() => new GlobalOutboundRetryBudget(-1, 1000)).toThrow(
      "Global outbound retry budget maxRetries must be non-negative",
    );
    expect(() => new GlobalOutboundRetryBudget(5, 0)).toThrow(
      "Global outbound retry budget windowMs must be positive",
    );
  });

  it("allows retries up to maxRetries limit", async () => {
    for (let i = 0; i < 5; i++) {
      expect(await budget.canRetry("stripe", "test")).toBe(true);
      await budget.recordRetry("stripe", "test");
    }

    expect(await budget.canRetry("stripe", "test")).toBe(false);
    expect(await budget.getRemainingBudget()).toBe(0);
  });

  it("throws GlobalRetryBudgetExceededError when recordRetry exceeds budget", async () => {
    for (let i = 0; i < 5; i++) {
      await budget.recordRetry("shopify", "oauth");
    }

    await expect(budget.recordRetry("shopify", "oauth")).rejects.toThrow(
      GlobalRetryBudgetExceededError,
    );

    try {
      await budget.recordRetry("shopify", "oauth");
    } catch (err: any) {
      expect(err).toBeInstanceOf(GlobalRetryBudgetExceededError);
      expect(err.code).toBe("GLOBAL_RETRY_BUDGET_EXCEEDED");
      expect(err.currentRetryCount).toBe(5);
      expect(err.budgetLimit).toBe(5);
    }
  });

  it("prunes expired retries after windowMs elapses", async () => {
    vi.useFakeTimers();
    try {
      const now = Date.now();
      vi.setSystemTime(now);

      const timedBudget = new GlobalOutboundRetryBudget(2, 500);
      await timedBudget.reset();

      await timedBudget.recordRetry("razorpay", "connect");
      await timedBudget.recordRetry("razorpay", "connect");
      expect(await timedBudget.canRetry("razorpay", "connect")).toBe(false);

      // Advance time beyond 500ms window
      vi.setSystemTime(now + 600);

      expect(await timedBudget.canRetry("razorpay", "connect")).toBe(true);
      expect(await timedBudget.getRemainingBudget()).toBe(2);
    } finally {
      vi.useRealTimers();
    }
  });

  it("resets budget cleanly", async () => {
    await budget.recordRetry("stripe", "connect");
    await budget.recordRetry("stripe", "connect");
    expect(await budget.getRemainingBudget()).toBe(3);

    await budget.reset();
    expect(await budget.getRemainingBudget()).toBe(5);
  });

  it("interacts with Redis when REDIS_URL is configured", async () => {
    process.env.REDIS_URL = "redis://localhost:6379";
    let storedCount = 0;
    const mockClient = {
      zremrangebyscore: vi.fn().mockImplementation(async () => {}),
      zcard: vi.fn().mockImplementation(async () => storedCount),
      zadd: vi.fn().mockImplementation(async () => {
        storedCount++;
      }),
      pexpire: vi.fn().mockImplementation(async () => {}),
      del: vi.fn().mockImplementation(async () => {
        storedCount = 0;
      }),
    };

    vi.spyOn(redisModule, "getRedisClient").mockReturnValue(mockClient as any);

    const redisBudget = new GlobalOutboundRetryBudget(3, 1000);
    await redisBudget.reset();

    expect(await redisBudget.getRetryCount()).toBe(0);
    await redisBudget.recordRetry("stripe", "test");
    expect(mockClient.zadd).toHaveBeenCalled();
    expect(mockClient.pexpire).toHaveBeenCalled();

    await redisBudget.reset();
    expect(mockClient.del).toHaveBeenCalled();

    vi.restoreAllMocks();
  });

  it("falls back gracefully when Redis throws an error", async () => {
    process.env.REDIS_URL = "redis://localhost:6379";
    const mockClient = {
      zremrangebyscore: vi.fn().mockRejectedValue(new Error("Redis connection lost")),
      zcard: vi.fn().mockRejectedValue(new Error("Redis connection lost")),
      zadd: vi.fn().mockRejectedValue(new Error("Redis connection lost")),
      pexpire: vi.fn().mockRejectedValue(new Error("Redis connection lost")),
      del: vi.fn().mockRejectedValue(new Error("Redis connection lost")),
    };

    vi.spyOn(redisModule, "getRedisClient").mockReturnValue(mockClient as any);

    const fallbackBudget = new GlobalOutboundRetryBudget(2, 1000);
    await fallbackBudget.reset();

    // Should fallback to local memory without throwing
    expect(await fallbackBudget.canRetry("shopify", "test")).toBe(true);
    await fallbackBudget.recordRetry("shopify", "test");
    expect(await fallbackBudget.getRemainingBudget()).toBe(1);

    vi.restoreAllMocks();
  });
});
