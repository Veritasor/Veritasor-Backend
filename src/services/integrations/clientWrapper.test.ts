import { describe, it, expect, beforeEach, vi } from "vitest";
import { executeWithRetry } from "./clientWrapper.js";
import { globalOutboundRetryBudget, GlobalRetryBudgetExceededError } from "./retryBudget.js";

describe("clientWrapper executeWithRetry", () => {
  beforeEach(async () => {
    await globalOutboundRetryBudget.reset();
  });

  afterEach(() => {
    // Restore the spies FIRST: the delay-schedule cases install their spy on
    // top of the fake clock, so restoring after `useRealTimers()` would put the
    // fake `setTimeout` back and hang every later test in this file.
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it("returns result on first attempt if successful", async () => {
    const fn = vi.fn().mockResolvedValue(new Response("ok", { status: 200 }));
    const response = await executeWithRetry(fn, {
      provider: "stripe",
      operation: "test",
      maxRetries: 3,
      baseDelayMs: 1,
      jitter: false,
    });

    expect(response.status).toBe(200);
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it("retries on transient HTTP 500 error when budget permits", async () => {
    const fn = vi
      .fn()
      .mockResolvedValueOnce(new Response("error", { status: 500 }))
      .mockResolvedValueOnce(new Response("ok", { status: 200 }));

    const response = await executeWithRetry(fn, {
      provider: "stripe",
      operation: "test",
      maxRetries: 3,
      baseDelayMs: 1,
      jitter: false,
    });

    expect(response.status).toBe(200);
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it("retries on thrown network error when budget permits", async () => {
    const fn = vi
      .fn()
      .mockRejectedValueOnce(new Error("Network error"))
      .mockResolvedValueOnce(new Response("ok", { status: 200 }));

    const response = await executeWithRetry(fn, {
      provider: "shopify",
      operation: "test",
      maxRetries: 3,
      baseDelayMs: 1,
      jitter: false,
    });

    expect(response.status).toBe(200);
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it("throws GlobalRetryBudgetExceededError when global retry budget is exhausted", async () => {
    // Deplete global retry budget
    const count = await globalOutboundRetryBudget.getRemainingBudget();
    for (let i = 0; i < count; i++) {
      await globalOutboundRetryBudget.recordRetry("test", "exhaust");
    }

    const fn = vi.fn().mockResolvedValue(new Response("error", { status: 500 }));

    await expect(
      executeWithRetry(fn, {
        provider: "razorpay",
        operation: "test",
        maxRetries: 3,
        baseDelayMs: 1,
        jitter: false,
      }),
    ).rejects.toThrow(GlobalRetryBudgetExceededError);

    // Initial attempt runs, but retry attempt fails before executing second attempt
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it("stops retrying when maxRetries is reached", async () => {
    const fn = vi.fn().mockResolvedValue(new Response("error", { status: 500 }));

    const response = await executeWithRetry(fn, {
      provider: "shopify",
      operation: "test",
      maxRetries: 2,
      baseDelayMs: 1,
      jitter: false,
    });

    expect(response.status).toBe(500);
    expect(fn).toHaveBeenCalledTimes(3); // 1 initial + 2 retries
  });

  it("respects custom shouldRetry predicate", async () => {
    const fn = vi.fn().mockResolvedValue(new Response("custom error", { status: 400 }));

    const response = await executeWithRetry(fn, {
      provider: "razorpay",
      operation: "test",
      maxRetries: 3,
      baseDelayMs: 1,
      jitter: false,
      shouldRetry: (res) => res?.status === 400,
    });

    // Custom predicate retried 400
    expect(fn).toHaveBeenCalledTimes(4); // 1 initial + 3 retries
    expect(response.status).toBe(400);
  });

  // ── Focused coverage: default predicate, delay schedule, budget accounting ──
  //
  // The cases above use `jitter: false` with `baseDelayMs: 1` and a custom
  // `shouldRetry`, so they never exercise DEFAULT_SHOULD_RETRY's 429 branch,
  // the jitter branch, the `maxDelayMs` cap, or any assertion about the delay
  // schedule / global-budget bookkeeping. The tests below close those gaps.

  describe("default retry predicate", () => {
    it("retries HTTP 429 (not just 5xx) and consumes exactly one budget unit", async () => {
      const fn = vi
        .fn()
        .mockResolvedValueOnce(new Response("slow down", { status: 429 }))
        .mockResolvedValueOnce(new Response("ok", { status: 200 }));

      const response = await executeWithRetry(fn, {
        provider: "stripe",
        operation: "rate-limit",
        maxRetries: 2,
        baseDelayMs: 1,
        jitter: false,
      });

      // Covers the `response.status === 429` half of DEFAULT_SHOULD_RETRY.
      expect(response.status).toBe(200);
      expect(fn).toHaveBeenCalledTimes(2);
      expect(await globalOutboundRetryBudget.getRetryCount()).toBe(1);
    });

    it("does not retry a non-429 4xx response and consumes no budget", async () => {
      const fn = vi.fn().mockResolvedValue(new Response("not found", { status: 404 }));

      const response = await executeWithRetry(fn, {
        provider: "stripe",
        operation: "missing",
        maxRetries: 3,
        baseDelayMs: 1,
        jitter: false,
      });

      // Covers the `return false` fall-through for a response that is neither
      // 5xx nor 429, i.e. the `!isFailure → return result` path.
      expect(response.status).toBe(404);
      expect(fn).toHaveBeenCalledTimes(1);
      expect(await globalOutboundRetryBudget.getRetryCount()).toBe(0);
    });

    it("returns a nullish result as-is without ever consulting shouldRetry", async () => {
      const shouldRetry = vi.fn(() => true);
      const fn = vi.fn().mockResolvedValue(null);

      const result = await executeWithRetry(fn, {
        provider: "stripe",
        operation: "no-response",
        maxRetries: 3,
        baseDelayMs: 1,
        jitter: false,
        shouldRetry,
      });

      // Pins the `result !== null` short-circuit in the isFailure expression:
      // even an always-retry predicate must not turn a nullish result into a
      // retryable failure, and no budget is consumed.
      expect(result).toBeNull();
      expect(fn).toHaveBeenCalledTimes(1);
      expect(shouldRetry).not.toHaveBeenCalled();
      expect(await globalOutboundRetryBudget.getRetryCount()).toBe(0);
    });
  });

  describe("maxRetries boundary", () => {
    it("maxRetries: 0 returns the first failed response without touching the budget", async () => {
      const fn = vi.fn().mockResolvedValue(new Response("error", { status: 500 }));

      const response = await executeWithRetry(fn, {
        provider: "razorpay",
        operation: "no-retries",
        maxRetries: 0,
        baseDelayMs: 1,
        jitter: false,
      });

      // Covers `attempt >= maxRetries` when attempt === 0 (no retry is even
      // considered) and the `return result` exit for a predicate-failed result.
      expect(response.status).toBe(500);
      expect(fn).toHaveBeenCalledTimes(1);
      expect(await globalOutboundRetryBudget.getRetryCount()).toBe(0);
    });

    it("maxRetries: 0 rethrows the original error rather than a wrapped one", async () => {
      const originalError = new Error("connection reset");
      const fn = vi.fn().mockRejectedValue(originalError);

      await expect(
        executeWithRetry(fn, {
          provider: "razorpay",
          operation: "no-retries-throw",
          maxRetries: 0,
          baseDelayMs: 1,
          jitter: false,
        }),
      ).rejects.toBe(originalError);

      expect(fn).toHaveBeenCalledTimes(1);
      expect(await globalOutboundRetryBudget.getRetryCount()).toBe(0);
    });
  });

  describe("delay schedule", () => {
    it("jitter: false yields exact exponential backoff and the maxDelayMs cap binds", async () => {
      vi.useFakeTimers();
      const delaySpy = vi.spyOn(globalThis, "setTimeout");
      const fn = vi.fn().mockResolvedValue(new Response("error", { status: 500 }));

      const pending = executeWithRetry(fn, {
        provider: "shopify",
        operation: "backoff",
        maxRetries: 3,
        baseDelayMs: 100,
        maxDelayMs: 250,
        jitter: false,
      });
      await vi.advanceTimersByTimeAsync(10_000);

      const response = await pending;
      expect(response.status).toBe(500);
      expect(fn).toHaveBeenCalledTimes(4);

      // attempt 1 → 100, attempt 2 → 200, attempt 3 → min(250, 400) = 250.
      expect(delaySpy.mock.calls.map((call) => call[1])).toEqual([100, 200, 250]);
    });

    it("jitter: true multiplies the capped backoff by 0.5 + Math.random() * 0.5", async () => {
      vi.useFakeTimers();
      const delaySpy = vi.spyOn(globalThis, "setTimeout");
      const randomSpy = vi.spyOn(Math, "random").mockReturnValue(0);
      const fn = vi.fn().mockResolvedValue(new Response("error", { status: 500 }));
      const options = {
        provider: "shopify",
        operation: "jitter",
        maxRetries: 3,
        baseDelayMs: 100,
        maxDelayMs: 250,
        jitter: true,
      };

      // Math.random() === 0 → factor exactly 0.5, the lower edge of the window.
      const lowerBoundRun = executeWithRetry(fn, options);
      await vi.advanceTimersByTimeAsync(10_000);
      await lowerBoundRun;
      expect(delaySpy.mock.calls.map((call) => call[1])).toEqual([50, 100, 125]);

      // Math.random() === 1 → factor exactly 1, the upper edge, which equals
      // the plain capped schedule (the cap still binds on the third attempt).
      delaySpy.mockClear();
      randomSpy.mockReturnValue(1);
      const upperBoundRun = executeWithRetry(fn, options);
      await vi.advanceTimersByTimeAsync(10_000);
      await upperBoundRun;
      expect(delaySpy.mock.calls.map((call) => call[1])).toEqual([100, 200, 250]);
    });
  });

  describe("budget accounting", () => {
    it("a successful first call consumes no budget and never consults it", async () => {
      const canRetrySpy = vi.spyOn(globalOutboundRetryBudget, "canRetry");
      const before = await globalOutboundRetryBudget.getRemainingBudget();
      const fn = vi.fn().mockResolvedValue(new Response("ok", { status: 200 }));

      await executeWithRetry(fn, {
        provider: "stripe",
        operation: "happy-path",
        maxRetries: 3,
        baseDelayMs: 1,
        jitter: false,
      });

      expect(fn).toHaveBeenCalledTimes(1);
      expect(canRetrySpy).not.toHaveBeenCalled();
      expect(await globalOutboundRetryBudget.getRemainingBudget()).toBe(before);
      expect(await globalOutboundRetryBudget.getRetryCount()).toBe(0);
    });

    it("rethrows the original error after exhausting retries and spends exactly maxRetries", async () => {
      const originalError = new Error("upstream down");
      const fn = vi.fn().mockRejectedValue(originalError);

      await expect(
        executeWithRetry(fn, {
          provider: "shopify",
          operation: "always-down",
          maxRetries: 2,
          baseDelayMs: 1,
          jitter: false,
        }),
      ).rejects.toBe(originalError);

      // Covers the final-attempt `throw err` (original, unwrapped) and that the
      // budget is decremented once per retry actually attempted.
      expect(fn).toHaveBeenCalledTimes(3);
      expect(await globalOutboundRetryBudget.getRetryCount()).toBe(2);
    });

    it("forwards provider/operation, checks the budget before sleeping, and reports the count when exhausted", async () => {
      vi.useFakeTimers();
      const delaySpy = vi.spyOn(globalThis, "setTimeout");
      const canRetrySpy = vi.spyOn(globalOutboundRetryBudget, "canRetry");
      const recordSpy = vi.spyOn(globalOutboundRetryBudget, "recordRetry");

      const limit = await globalOutboundRetryBudget.getRemainingBudget();
      for (let i = 0; i < limit; i++) {
        await globalOutboundRetryBudget.recordRetry("seed", "seed");
      }
      canRetrySpy.mockClear();
      recordSpy.mockClear();

      const fn = vi.fn().mockResolvedValue(new Response("error", { status: 500 }));

      let caught: unknown;
      try {
        await executeWithRetry(fn, {
          provider: "razorpay",
          operation: "payout",
          maxRetries: 3,
          baseDelayMs: 1,
          jitter: false,
        });
      } catch (error) {
        caught = error;
      }

      expect(caught).toBeInstanceOf(GlobalRetryBudgetExceededError);
      const budgetError = caught as GlobalRetryBudgetExceededError;
      expect(budgetError.code).toBe("GLOBAL_RETRY_BUDGET_EXCEEDED");
      expect(budgetError.currentRetryCount).toBe(limit);
      expect(budgetError.budgetLimit).toBe(50);

      // Only the initial attempt ran: the budget veto short-circuits the retry.
      expect(fn).toHaveBeenCalledTimes(1);

      // First (and only wrapper-initiated) check carries the caller's identifiers.
      expect(canRetrySpy.mock.calls[0]).toEqual(["razorpay", "payout"]);
      // recordRetry is attempted exactly once on the exhaustion path...
      expect(recordSpy).toHaveBeenCalledTimes(1);
      expect(recordSpy).toHaveBeenCalledWith("razorpay", "payout");
      // ...and the budget check runs BEFORE the backoff sleep, which never runs.
      expect(delaySpy).not.toHaveBeenCalled();
    });
  });
});
