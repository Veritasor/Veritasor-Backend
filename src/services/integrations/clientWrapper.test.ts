import { describe, it, expect, beforeEach, vi } from "vitest";
import { executeWithRetry } from "./clientWrapper.js";
import { globalOutboundRetryBudget, GlobalRetryBudgetExceededError } from "./retryBudget.js";

describe("clientWrapper executeWithRetry", () => {
  beforeEach(async () => {
    await globalOutboundRetryBudget.reset();
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
});
