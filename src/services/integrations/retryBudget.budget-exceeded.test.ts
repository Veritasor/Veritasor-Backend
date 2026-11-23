import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

import {
  DEFAULT_RETRY_BUDGET_MAX_RETRIES,
  DEFAULT_RETRY_BUDGET_WINDOW_MS,
  GlobalOutboundRetryBudget,
  GlobalRetryBudgetExceededError,
} from "./retryBudget.js";
import {
  integrationRetryBudgetExhaustedTotal,
  integrationRetryBudgetRemaining,
} from "../../metrics.js";

/**
 * Regression coverage for the `GlobalRetryBudgetExceededError` failure surface.
 *
 * The error is raised from `GlobalOutboundRetryBudget.recordRetry` on the hot
 * outbound path. It used to build its message from `config.integrations.retryBudget`,
 * a config block that is never defined, so raising the error threw
 * `TypeError: Cannot read properties of undefined (reading 'retryBudget')`
 * instead of the exhaustion signal callers branch on.
 */
describe("GlobalOutboundRetryBudget — error contract", () => {
  beforeEach(() => {
    delete process.env.REDIS_URL;
    delete process.env.REDIS_CLUSTER_NODES;
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it("constructs GlobalRetryBudgetExceededError without touching optional config", () => {
    const err = new GlobalRetryBudgetExceededError(7, 5, 2_000);
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(GlobalRetryBudgetExceededError);
    expect(err.name).toBe("GlobalRetryBudgetExceededError");
    expect(err.code).toBe("GLOBAL_RETRY_BUDGET_EXCEEDED");
    expect(err.currentRetryCount).toBe(7);
    expect(err.budgetLimit).toBe(5);
    expect(err.windowMs).toBe(2_000);
    expect(err.message).toBe(
      "Global outbound retry budget exhausted: 7/5 retries in the last 2 seconds.",
    );
  });

  it("defaults the reported window to the documented default", () => {
    const err = new GlobalRetryBudgetExceededError(1, 1);
    expect(err.windowMs).toBe(DEFAULT_RETRY_BUDGET_WINDOW_MS);
    expect(err.message).toContain(
      `${DEFAULT_RETRY_BUDGET_WINDOW_MS / 1000} seconds`,
    );
  });

  it("reports the exhausted budget's own window when recordRetry rejects", async () => {
    const budget = new GlobalOutboundRetryBudget(2, 1_500);
    await budget.reset();
    await budget.recordRetry("stripe", "charge");
    await budget.recordRetry("stripe", "charge");

    const err = await budget.recordRetry("stripe", "charge").catch((e) => e);
    expect(err).toBeInstanceOf(GlobalRetryBudgetExceededError);
    expect(err.currentRetryCount).toBe(2);
    expect(err.budgetLimit).toBe(2);
    expect(err.windowMs).toBe(1_500);
    expect(err.message).toBe(
      "Global outbound retry budget exhausted: 2/2 retries in the last 1.5 seconds.",
    );
  });

  it("counts the failed attempt towards the exhaustion metric only when rejected", async () => {
    const exhausted = vi.spyOn(integrationRetryBudgetExhaustedTotal, "inc");
    const remaining = vi.spyOn(integrationRetryBudgetRemaining, "set");

    const budget = new GlobalOutboundRetryBudget(1, 1_000);
    await budget.reset();

    await budget.recordRetry("shopify", "oauth");
    expect(exhausted).not.toHaveBeenCalled();

    await expect(budget.recordRetry("shopify", "oauth")).rejects.toBeInstanceOf(
      GlobalRetryBudgetExceededError,
    );
    expect(exhausted).toHaveBeenCalledWith({ provider: "shopify", operation: "oauth" });
    expect(remaining).toHaveBeenLastCalledWith(0);
  });
});

describe("GlobalOutboundRetryBudget — constructor validation", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("rejects negative maxRetries with a plain Error carrying no budget code", () => {
    let caught: unknown;
    try {
      new GlobalOutboundRetryBudget(-1, 1_000);
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(Error);
    expect(caught).not.toBeInstanceOf(GlobalRetryBudgetExceededError);
    expect((caught as GlobalRetryBudgetExceededError).code).toBeUndefined();
    expect((caught as Error).message).toBe(
      "Global outbound retry budget maxRetries must be non-negative",
    );
  });

  it("rejects a non-positive windowMs (zero and negative)", () => {
    expect(() => new GlobalOutboundRetryBudget(5, 0)).toThrow(
      "Global outbound retry budget windowMs must be positive",
    );
    expect(() => new GlobalOutboundRetryBudget(5, -1)).toThrow(
      "Global outbound retry budget windowMs must be positive",
    );
  });

  it("checks maxRetries before windowMs so the first defect is reported", () => {
    expect(() => new GlobalOutboundRetryBudget(-1, 0)).toThrow(
      "Global outbound retry budget maxRetries must be non-negative",
    );
  });

  it("accepts the boundary values maxRetries=0 and windowMs=1", async () => {
    const zeroBudget = new GlobalOutboundRetryBudget(0, 1);
    await zeroBudget.reset();
    expect(await zeroBudget.getRetryCount()).toBe(0);
    expect(await zeroBudget.canRetry("stripe", "charge")).toBe(false);
    expect(await zeroBudget.getRemainingBudget()).toBe(0);

    const err = await zeroBudget.recordRetry("stripe", "charge").catch((e) => e);
    expect(err).toBeInstanceOf(GlobalRetryBudgetExceededError);
    expect(err.currentRetryCount).toBe(0);
    expect(err.budgetLimit).toBe(0);
    expect(err.windowMs).toBe(1);
  });

  it("falls back to the documented defaults when no overrides are supplied", async () => {
    const budget = new GlobalOutboundRetryBudget();
    await budget.reset();
    expect(await budget.getRemainingBudget()).toBe(DEFAULT_RETRY_BUDGET_MAX_RETRIES);
  });
});

describe("GlobalOutboundRetryBudget — window boundaries", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("keeps an attempt recorded exactly at the window cutoff", async () => {
    vi.useFakeTimers();
    const start = 1_000_000;
    vi.setSystemTime(start);

    const budget = new GlobalOutboundRetryBudget(2, 1_000);
    await budget.reset();
    await budget.recordRetry("stripe", "charge");

    // cutoff == the attempt timestamp: `localPrune` uses a strict `<` compare,
    // so the attempt is still inside the window.
    vi.setSystemTime(start + 1_000);
    expect(await budget.getRetryCount()).toBe(1);
    expect(await budget.getRemainingBudget()).toBe(1);

    // One millisecond later the attempt falls outside the window.
    vi.setSystemTime(start + 1_001);
    expect(await budget.getRetryCount()).toBe(0);
    expect(await budget.getRemainingBudget()).toBe(2);
  });

  it("prunes and re-allows retries once the window has fully elapsed", async () => {
    vi.useFakeTimers();
    const start = 5_000_000;
    vi.setSystemTime(start);

    const budget = new GlobalOutboundRetryBudget(1, 500);
    await budget.reset();
    await budget.recordRetry("razorpay", "connect");
    expect(await budget.canRetry("razorpay", "connect")).toBe(false);

    vi.setSystemTime(start + 501);
    expect(await budget.canRetry("razorpay", "connect")).toBe(true);
    await budget.recordRetry("razorpay", "connect");
    expect(await budget.getRetryCount()).toBe(1);
  });

  it("keeps a healthy budget observable through reset after exhaustion", async () => {
    const budget = new GlobalOutboundRetryBudget(3, 1_000);
    await budget.reset();
    await budget.recordRetry("stripe", "charge");
    await budget.recordRetry("stripe", "charge");
    await budget.recordRetry("stripe", "charge");
    expect(await budget.canRetry("stripe", "charge")).toBe(false);

    await budget.reset();
    expect(await budget.getRetryCount()).toBe(0);
    expect(await budget.getRemainingBudget()).toBe(3);
    expect(await budget.canRetry("stripe", "charge")).toBe(true);
  });
});
