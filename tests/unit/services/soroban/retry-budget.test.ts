import { beforeEach, describe, expect, it, vi } from "vitest";
import { config } from "../../../../src/config/index.js";
import {
  SorobanRetryBudget,
  SorobanRetryBudgetExceededError,
  sorobanRetryBudget,
  fullJitter,
  getBackoffConfig,
  type BackoffConfig,
} from "../../../../src/services/soroban/retry-budget.js";
import {
  metricsRegistry,
  sorobanRetryBudgetExhaustedTotal,
  sorobanRetryTotal,
} from "../../../../src/metrics.js";
import { executeSorobanRequest } from "../../../../src/services/soroban/client.js";

beforeEach(async () => {
  await metricsRegistry.resetMetrics();
  sorobanRetryBudget.reset();
  vi.useRealTimers();
  // Clear any env vars set in tests
  delete process.env.SOROBAN_BACKOFF_BASE_MS;
  delete process.env.SOROBAN_BACKOFF_MAX_MS;
});

describe("fullJitter — exponential backoff with jitter", () => {
  describe("basic behavior", () => {
    it("returns 0 when random returns 0", () => {
      const delay = fullJitter(0, 200, 30000, () => 0);
      expect(delay).toBe(0);
    });

    it("returns floor(random * min(base * 2^attempt, cap))", () => {
      // attempt=0: cap = min(200 * 1, 30000) = 200
      // random=0.5: floor(0.5 * 200) = 100
      const delay = fullJitter(0, 200, 30000, () => 0.5);
      expect(delay).toBe(100);
    });

    it("returns nearly-capped value with random near 1", () => {
      // attempt=0: cap = 200
      // random=0.9999: floor(0.9999 * 200) = 199
      const delay = fullJitter(0, 200, 30000, () => 0.9999);
      expect(delay).toBe(199);
    });

    it("doubles the cap on each attempt (exponential growth)", () => {
      const r = () => 0.9;
      const d0 = fullJitter(0, 200, 30000, r); // ~180 (0.9 * 200)
      const d1 = fullJitter(1, 200, 30000, r); // ~360 (0.9 * 400)
      const d2 = fullJitter(2, 200, 30000, r); // ~720 (0.9 * 800)

      expect(d0).toBeLessThan(d1);
      expect(d1).toBeLessThan(d2);
      expect(d0).toBeCloseTo(180, 0);
      expect(d1).toBeCloseTo(360, 0);
      expect(d2).toBeCloseTo(720, 0);
    });

    it("never exceeds capMs regardless of attempt", () => {
      const r = () => 0.9999;
      for (let attempt = 0; attempt <= 20; attempt++) {
        const delay = fullJitter(attempt, 200, 30000, r);
        expect(delay).toBeLessThanOrEqual(30000);
      }
    });

    it("produces different values with Math.random", () => {
      const delays = Array.from({ length: 50 }, () =>
        fullJitter(3, 200, 30000),
      );
      // With 50 attempts and random delays, should have variety
      const uniqueDelays = new Set(delays);
      expect(uniqueDelays.size).toBeGreaterThan(10);
    });
  });

  describe("deterministic with seeded RNG", () => {
    it("produces same result with same seed", () => {
      // Simple linear congruential RNG for reproducibility
      let seed1 = 42;
      const seededRandom1 = () => {
        seed1 = (seed1 * 1664525 + 1013904223) >>> 0;
        return seed1 / 0xffffffff;
      };

      let seed2 = 42;
      const seededRandom2 = () => {
        seed2 = (seed2 * 1664525 + 1013904223) >>> 0;
        return seed2 / 0xffffffff;
      };

      const d1 = fullJitter(5, 200, 30000, seededRandom1);
      const d2 = fullJitter(5, 200, 30000, seededRandom2);

      expect(d1).toBe(d2);
    });

    it("produces different result with different seed", () => {
      let seed1 = 42;
      const rng1 = () => {
        seed1 = (seed1 * 1664525 + 1013904223) >>> 0;
        return seed1 / 0xffffffff;
      };

      let seed2 = 123;
      const rng2 = () => {
        seed2 = (seed2 * 1664525 + 1013904223) >>> 0;
        return seed2 / 0xffffffff;
      };

      const d1 = fullJitter(5, 200, 30000, rng1);
      const d2 = fullJitter(5, 200, 30000, rng2);

      expect(d1).not.toBe(d2);
    });
  });

  describe("input validation", () => {
    it("throws RangeError for negative attempt", () => {
      expect(() => fullJitter(-1, 200, 30000)).toThrow(RangeError);
      expect(() => fullJitter(-1, 200, 30000)).toThrow(/attempt/i);
    });

    it("throws RangeError for NaN attempt", () => {
      expect(() => fullJitter(NaN, 200, 30000)).toThrow(RangeError);
    });

    it("throws RangeError for Infinity attempt", () => {
      expect(() => fullJitter(Infinity, 200, 30000)).toThrow(RangeError);
    });

    it("throws RangeError for baseMs <= 0", () => {
      expect(() => fullJitter(0, 0, 30000)).toThrow(RangeError);
      expect(() => fullJitter(0, -1, 30000)).toThrow(RangeError);
      expect(() => fullJitter(0, -100, 30000)).toThrow(RangeError);
    });

    it("throws RangeError for baseMs = NaN", () => {
      expect(() => fullJitter(0, NaN, 30000)).toThrow(RangeError);
    });

    it("throws RangeError for baseMs = Infinity", () => {
      expect(() => fullJitter(0, Infinity, 30000)).toThrow(RangeError);
    });

    it("throws RangeError for capMs <= 0", () => {
      expect(() => fullJitter(0, 200, 0)).toThrow(RangeError);
      expect(() => fullJitter(0, 200, -1)).toThrow(RangeError);
      expect(() => fullJitter(0, 200, -1000)).toThrow(RangeError);
    });

    it("throws RangeError for capMs = NaN", () => {
      expect(() => fullJitter(0, 200, NaN)).toThrow(RangeError);
    });

    it("throws RangeError for capMs = Infinity", () => {
      // Infinity is technically valid as a number, but we reject it
      expect(() => fullJitter(0, 200, Infinity)).toThrow(RangeError);
    });

    it("handles attempt=0 (first retry) correctly", () => {
      // attempt=0: exponential = 200 * 2^0 = 200
      // With random=1 (boundary), floor(1 * 200) could be 199 or 200
      // depending on floating point
      const delay = fullJitter(0, 200, 30000, () => 1);
      expect(delay).toBeLessThanOrEqual(200);
      expect(delay).toBeGreaterThanOrEqual(0);
    });

    it("respects cap with large base * 2^attempt", () => {
      // attempt=10: 200 * 2^10 = 204,800 >> 30,000 cap
      // floor(0.9999 * 30000) ≈ 29997
      const delay = fullJitter(10, 200, 30000, () => 0.9999);
      expect(delay).toBeLessThanOrEqual(30000);
      expect(delay).toBeGreaterThan(20000);
    });

    it("handles very large attempts without overflow", () => {
      // attempt=100: 2^100 is huge, but should cap at 30000
      const delay = fullJitter(100, 200, 30000, () => 0.5);
      expect(delay).toBeLessThanOrEqual(15000);
    });
  });

  describe("getBackoffConfig — environment configuration", () => {
    it("reads SOROBAN_BACKOFF_BASE_MS from env", () => {
      process.env.SOROBAN_BACKOFF_BASE_MS = "500";
      const config = getBackoffConfig();
      expect(config.baseMs).toBe(500);
    });

    it("reads SOROBAN_BACKOFF_MAX_MS from env", () => {
      process.env.SOROBAN_BACKOFF_MAX_MS = "60000";
      const config = getBackoffConfig();
      expect(config.maxMs).toBe(60000);
    });

    it("reads both BASE and MAX from env", () => {
      process.env.SOROBAN_BACKOFF_BASE_MS = "300";
      process.env.SOROBAN_BACKOFF_MAX_MS = "45000";
      const config = getBackoffConfig();
      expect(config.baseMs).toBe(300);
      expect(config.maxMs).toBe(45000);
    });

    it("uses default 200ms base when env not set", () => {
      delete process.env.SOROBAN_BACKOFF_BASE_MS;
      const config = getBackoffConfig();
      expect(config.baseMs).toBe(200);
    });

    it("uses default 30000ms cap when env not set", () => {
      delete process.env.SOROBAN_BACKOFF_MAX_MS;
      const config = getBackoffConfig();
      expect(config.maxMs).toBe(30000);
    });

    it("throws error if baseMs is non-positive", () => {
      process.env.SOROBAN_BACKOFF_BASE_MS = "0";
      expect(() => getBackoffConfig()).toThrow(/positive/i);
    });

    it("throws error if maxMs is non-positive", () => {
      process.env.SOROBAN_BACKOFF_MAX_MS = "-100";
      expect(() => getBackoffConfig()).toThrow(/positive/i);
    });

    it("throws error if baseMs > maxMs", () => {
      process.env.SOROBAN_BACKOFF_BASE_MS = "50000";
      process.env.SOROBAN_BACKOFF_MAX_MS = "30000";
      expect(() => getBackoffConfig()).toThrow(/not exceed/i);
    });

    it("throws error if baseMs is NaN", () => {
      process.env.SOROBAN_BACKOFF_BASE_MS = "abc";
      expect(() => getBackoffConfig()).toThrow(/positive/i);
    });

    it("throws error if maxMs is NaN", () => {
      process.env.SOROBAN_BACKOFF_MAX_MS = "xyz";
      expect(() => getBackoffConfig()).toThrow(/positive/i);
    });
  });
});

describe("Soroban retry budget tracker", () => {
  it("increments soroban_retry_total on each retry with the correct operation label", async () => {
    const budget = new SorobanRetryBudget(3);

    budget.recordRetry("getAccount");
    budget.recordRetry("sendTransaction");

    const metrics = await metricsRegistry.getMetricsAsJSON();
    const counter = metrics.find((m) => m.name === "soroban_retry_total");
    expect(counter).toBeDefined();
    const values = counter!.values as Array<{
      labels: Record<string, string>;
      value: number;
    }>;
    expect(values.find((v) => v.labels.operation === "getAccount")?.value).toBe(
      1,
    );
    expect(
      values.find((v) => v.labels.operation === "sendTransaction")?.value,
    ).toBe(1);
  });

  it("returns false once maxRetries is reached within the window", () => {
    const budget = new SorobanRetryBudget(2);

    expect(budget.canRetry()).toBe(true);
    budget.recordRetry("getAccount");
    expect(budget.canRetry()).toBe(true);
    budget.recordRetry("getAccount");
    expect(budget.canRetry()).toBe(false);
  });

  it("drops retries older than 60 seconds and restores budget", () => {
    vi.useFakeTimers();
    const budget = new SorobanRetryBudget(2);

    budget.recordRetry("getAccount");
    vi.advanceTimersByTime(30_000);
    budget.recordRetry("getAccount");
    expect(budget.canRetry()).toBe(false);

    vi.advanceTimersByTime(31_000);
    expect(budget.canRetry()).toBe(true);
  });

  it("increments soroban_retry_budget_exhausted_total when budget is exhausted", async () => {
    const budget = new SorobanRetryBudget(1);
    budget.recordRetry("getAccount");

    expect(budget.canRetry()).toBe(false);

    const metrics = await metricsRegistry.getMetricsAsJSON();
    const counter = metrics.find((m) =>
      m.name === "soroban_retry_budget_exhausted_total"
    );
    expect(counter).toBeDefined();
    const total = (counter!.values as Array<{ value: number }>)[0]?.value;
    expect(total).toBe(1);
  });

  it("throws SorobanRetryBudgetExceededError when retry budget is exceeded during executeSorobanRequest", async () => {
    sorobanRetryBudget.reset();
    for (let i = 0; i < 20; i += 1) {
      sorobanRetryBudget.recordRetry("getAccount");
    }

    const execute = vi
      .fn<() => Promise<string>>()
      .mockRejectedValue(new Error("network error"));

    await expect(
      executeSorobanRequest({
        operationName: "getAccount",
        execute,
        policy: {
          timeoutMs: 50,
          maxRetries: 1,
          retryBaseDelayMs: 1,
          retryMaxDelayMs: 1,
          retryJitterRatio: 0,
          circuitBreakerThreshold: 5,
          circuitBreakerResetMs: 30_000,
        },
        sleep: async () => undefined,
      }),
    ).rejects.toThrow(SorobanRetryBudgetExceededError);

    await expect(
      executeSorobanRequest({
        operationName: "getAccount",
        execute,
        policy: {
          timeoutMs: 50,
          maxRetries: 1,
          retryBaseDelayMs: 1,
          retryMaxDelayMs: 1,
          retryJitterRatio: 0,
          circuitBreakerThreshold: 5,
          circuitBreakerResetMs: 30_000,
        },
        sleep: async () => undefined,
      }),
    ).rejects.toMatchObject({ code: "SOROBAN_RETRY_BUDGET_EXCEEDED" });

    const metrics = await metricsRegistry.getMetricsAsJSON();
    const counter = metrics.find((m) =>
      m.name === "soroban_retry_budget_exhausted_total"
    );
    expect(counter).toBeDefined();
    expect((counter!.values as Array<{ value: number }>)[0]?.value).toBeGreaterThanOrEqual(1);
  });

  it("does not affect budget state for a healthy request with zero retries", async () => {
    const execute = vi.fn().mockResolvedValue("ok");

    const result = await executeSorobanRequest({
      operationName: "getAccount",
      execute,
      policy: {
        timeoutMs: 50,
        maxRetries: 3,
        retryBaseDelayMs: 1,
        retryMaxDelayMs: 1,
        retryJitterRatio: 0,
        circuitBreakerThreshold: 5,
        circuitBreakerResetMs: 30_000,
      },
    });

    expect(result).toBe("ok");
    expect(execute).toHaveBeenCalledTimes(1);

    const metrics = await metricsRegistry.getMetricsAsJSON();
    const retryTotalMetric = metrics.find((m) => m.name === "soroban_retry_total");
    const exhaustedMetric = metrics.find((m) =>
      m.name === "soroban_retry_budget_exhausted_total"
    );
    expect(retryTotalMetric).toBeDefined();
    expect(retryTotalMetric?.values).toEqual([]);
    expect(exhaustedMetric).toBeDefined();
    expect(exhaustedMetric?.values?.[0]?.value).toBe(0);
    expect(sorobanRetryBudget.getRetryCount()).toBe(0);
  });

  it("getRetryCount returns current count within window", () => {
    vi.useFakeTimers();
    const budget = new SorobanRetryBudget(10);

    expect(budget.getRetryCount()).toBe(0);
    budget.recordRetry("op1");
    expect(budget.getRetryCount()).toBe(1);
    budget.recordRetry("op2");
    expect(budget.getRetryCount()).toBe(2);

    vi.advanceTimersByTime(61_000);
    expect(budget.getRetryCount()).toBe(0);
  });

  it("reset clears all attempts", () => {
    vi.useFakeTimers();
    const budget = new SorobanRetryBudget(10);

    budget.recordRetry("op");
    budget.recordRetry("op");
    expect(budget.getRetryCount()).toBe(2);

    budget.reset();
    expect(budget.getRetryCount()).toBe(0);
    expect(budget.canRetry()).toBe(true);
  });

  it("constructor throws error for negative maxRetries", () => {
    expect(() => new SorobanRetryBudget(-1)).toThrow(
      /maxRetries must be non-negative/,
    );
  });

  it("allows maxRetries=0 (disables all retries)", () => {
    const budget = new SorobanRetryBudget(0);
    expect(budget.canRetry()).toBe(false);
  });
});

describe("exponential backoff in executeSorobanRequest", () => {
  it("uses fullJitter for calculating retry delays", async () => {
    vi.useFakeTimers();
    const delays: number[] = [];

    const execute = vi
      .fn()
      .mockRejectedValueOnce(new Error("timeout"))
      .mockResolvedValue("success");

    const mockSleep = vi.fn((delayMs: number) => {
      delays.push(delayMs);
      return Promise.resolve();
    });

    await executeSorobanRequest({
      operationName: "test",
      execute,
      policy: {
        timeoutMs: 100,
        maxRetries: 2,
        retryBaseDelayMs: 200,
        retryMaxDelayMs: 1000,
        retryJitterRatio: 0.2,
        circuitBreakerThreshold: 5,
        circuitBreakerResetMs: 30_000,
      },
      sleep: mockSleep,
      random: () => 0.5, // Deterministic
    });

    expect(delays).toHaveLength(1);
    // With fullJitter(0, 200, 1000, () => 0.5):
    // exponential = 200 * 2^0 = 200
    // capped = min(200, 1000) = 200
    // delay = floor(0.5 * 200) = 100
    expect(delays[0]).toBe(100);
  });

  it("increases delays exponentially across attempts", async () => {
    vi.useFakeTimers();
    const delays: number[] = [];

    const execute = vi
      .fn()
      .mockRejectedValueOnce(new Error("timeout"))
      .mockRejectedValueOnce(new Error("timeout"))
      .mockResolvedValue("success");

    const mockSleep = vi.fn((delayMs: number) => {
      delays.push(delayMs);
      return Promise.resolve();
    });

    await executeSorobanRequest({
      operationName: "test",
      execute,
      policy: {
        timeoutMs: 100,
        maxRetries: 3,
        retryBaseDelayMs: 100,
        retryMaxDelayMs: 5000,
        retryJitterRatio: 0.2,
        circuitBreakerThreshold: 5,
        circuitBreakerResetMs: 30_000,
      },
      sleep: mockSleep,
      random: () => 0.8, // Deterministic
    });

    expect(delays).toHaveLength(2);
    // First retry: fullJitter(0, 100, 5000, 0.8) = floor(0.8 * 100) = 80
    // Second retry: fullJitter(1, 100, 5000, 0.8) = floor(0.8 * 200) = 160
    expect(delays[0]).toBe(80);
    expect(delays[1]).toBe(160);
    expect(delays[1]).toBeGreaterThan(delays[0]);
  });

  it("caps delays at retryMaxDelayMs", async () => {
    vi.useFakeTimers();
    const delays: number[] = [];

    const execute = vi
      .fn()
      .mockRejectedValueOnce(new Error("timeout"))
      .mockResolvedValue("success");

    const mockSleep = vi.fn((delayMs: number) => {
      delays.push(delayMs);
      return Promise.resolve();
    });

    await executeSorobanRequest({
      operationName: "test",
      execute,
      policy: {
        timeoutMs: 100,
        maxRetries: 10,
        retryBaseDelayMs: 100,
        retryMaxDelayMs: 500,
        retryJitterRatio: 0.2,
        circuitBreakerThreshold: 5,
        circuitBreakerResetMs: 30_000,
      },
      sleep: mockSleep,
      random: () => 0.9999, // Near max
    });

    expect(delays).toHaveLength(1);
    // Even with high attempt numbers, should be capped
    expect(delays[0]).toBeLessThanOrEqual(500);
  });

  it("injects custom random function for deterministic testing", async () => {
    vi.useFakeTimers();
    const delays: number[] = [];

    const mockRandom = vi.fn(() => 0.25);
    const execute = vi
      .fn()
      .mockRejectedValueOnce(new Error("timeout"))
      .mockResolvedValue("success");

    const mockSleep = vi.fn((delayMs: number) => {
      delays.push(delayMs);
      return Promise.resolve();
    });

    await executeSorobanRequest({
      operationName: "test",
      execute,
      policy: {
        timeoutMs: 100,
        maxRetries: 2,
        retryBaseDelayMs: 200,
        retryMaxDelayMs: 2000,
        retryJitterRatio: 0.2,
        circuitBreakerThreshold: 5,
        circuitBreakerResetMs: 30_000,
      },
      sleep: mockSleep,
      random: mockRandom,
    });

    // Random function should have been called
    expect(mockRandom).toHaveBeenCalled();
    expect(delays).toHaveLength(1);
    expect(delays[0]).toBe(50); // floor(0.25 * 200)
  });
});

