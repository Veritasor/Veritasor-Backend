import { beforeEach, describe, expect, it, vi } from "vitest";
import { config } from "../../../../src/config/index.js";
import {
  SorobanRetryBudget,
  SorobanRetryBudgetExceededError,
  sorobanRetryBudget,
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
});

describe("Soroban retry budget tracker", () => {
  it("increments soroban_retry_total on each retry with the correct operation label", async () => {
    const budget = new SorobanRetryBudget(3);

    budget.recordRetry("getAccount");
    budget.recordRetry("sendTransaction");

    const metrics = await metricsRegistry.getMetricsAsJSON();
    const counter = metrics.find((m) => m.name === "soroban_retry_total");
    expect(counter).toBeDefined();
    const values = counter!.values as Array<{ labels: Record<string, string>; value: number }>;
    expect(values.find((v) => v.labels.operation === "getAccount")?.value).toBe(1);
    expect(values.find((v) => v.labels.operation === "sendTransaction")?.value).toBe(1);
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
    const counter = metrics.find((m) => m.name === "soroban_retry_budget_exhausted_total");
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
    const counter = metrics.find((m) => m.name === "soroban_retry_budget_exhausted_total");
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
    const exhaustedMetric = metrics.find((m) => m.name === "soroban_retry_budget_exhausted_total");
    expect(retryTotalMetric).toBeDefined();
    expect(retryTotalMetric?.values).toEqual([]);
    expect(exhaustedMetric).toBeDefined();
    expect(exhaustedMetric?.values?.[0]?.value).toBe(0);
    expect(sorobanRetryBudget.getRetryCount()).toBe(0);
  });
});
