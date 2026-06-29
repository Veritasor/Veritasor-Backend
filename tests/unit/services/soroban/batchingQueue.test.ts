import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { BatchingQueue } from "../../../../src/services/soroban/batchingQueue.js";
import { metricsRegistry, sorobanBatchSize } from "../../../../src/metrics.js";

describe("BatchingQueue", () => {
  beforeEach(async () => {
    await metricsRegistry.resetMetrics();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("rejects invalid configuration", () => {
    expect(
      () =>
        new BatchingQueue(async () => [], {
          maxBatchSize: 0,
        }),
    ).toThrow("maxBatchSize must be at least 1");

    expect(
      () =>
        new BatchingQueue(async () => [], {
          minFlushMs: 500,
          maxFlushMs: 100,
        }),
    ).toThrow("minFlushMs must be less than or equal to maxFlushMs");

    expect(
      () =>
        new BatchingQueue(async () => [], {
          maxBatchSize: 20,
          backpressureThreshold: 10,
        }),
    ).toThrow("backpressureThreshold must be greater than or equal to maxBatchSize");
  });

  it("flushes immediately when max batch size is reached", async () => {
    const handler = vi.fn(async (items: number[]) => items.map((value) => value * 2));
    const queue = new BatchingQueue(handler, {
      maxBatchSize: 2,
      minFlushMs: 1000,
      maxFlushMs: 1000,
      backpressureThreshold: 10,
    });

    const first = queue.enqueue(1);
    const second = queue.enqueue(2);

    await expect(Promise.all([first, second])).resolves.toEqual([2, 4]);
    expect(handler).toHaveBeenCalledTimes(1);
    expect(handler.mock.calls[0][1]).toBe("size");

    const metrics = await metricsRegistry.getMetricsAsJSON();
    const histogram = metrics.find((m) => m.name === "soroban_batch_size");
    expect(histogram?.values.some((v) => v.value === 2)).toBe(true);
  });

  it("flushes on latency when the adaptive window expires", async () => {
    const handler = vi.fn(async (items: string[]) => items.map((value) => value.toUpperCase()));
    const queue = new BatchingQueue(handler, {
      maxBatchSize: 10,
      minFlushMs: 100,
      maxFlushMs: 200,
      backpressureThreshold: 20,
    });

    const resultPromise = queue.enqueue("hello");
    await vi.advanceTimersByTimeAsync(200);

    await expect(resultPromise).resolves.toBe("HELLO");
    expect(handler.mock.calls[0][1]).toBe("latency");
    sorobanBatchSize.observe({ reason: "latency" }, 1);
  });

  it("flushes on backpressure when queue depth exceeds threshold", async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });

    const handler = vi.fn(async (items: number[]) => {
      await gate;
      return items;
    });

    const queue = new BatchingQueue(handler, {
      maxBatchSize: 3,
      minFlushMs: 10_000,
      maxFlushMs: 10_000,
      backpressureThreshold: 3,
    });

    const p1 = queue.enqueue(1);
    const p2 = queue.enqueue(2);
    const p3 = queue.enqueue(3);

    await vi.advanceTimersByTimeAsync(0);
    expect(handler).toHaveBeenCalledTimes(1);
    expect(handler.mock.calls[0][1]).toBe("backpressure");

    release();
    await expect(Promise.all([p1, p2, p3])).resolves.toEqual([1, 2, 3]);
  });

  it("shrinks the adaptive flush window under sustained load", async () => {
    const handler = vi.fn(async (items: number[]) => items);
    const queue = new BatchingQueue(handler, {
      maxBatchSize: 100,
      minFlushMs: 50,
      maxFlushMs: 500,
      backpressureThreshold: 200,
    });

    expect(queue.flushWindowMs).toBe(500);

    for (let i = 0; i < 10; i++) {
      void queue.enqueue(i);
    }

    expect(queue.flushWindowMs).toBeLessThan(500);
    expect(queue.flushWindowMs).toBeGreaterThanOrEqual(50);
  });

  it("resolves and rejects items independently within the same batch", async () => {
    const queue = new BatchingQueue(async () => [
      "ok",
      { error: new Error("leaf failed") },
      "also-ok",
    ], {
      maxBatchSize: 3,
      minFlushMs: 1000,
      maxFlushMs: 1000,
      backpressureThreshold: 10,
    });

    const ok1 = queue.enqueue("a");
    const bad = queue.enqueue("b");
    const ok2 = queue.enqueue("c");

    await expect(ok1).resolves.toBe("ok");
    await expect(ok2).resolves.toBe("also-ok");
    await expect(bad).rejects.toThrow("leaf failed");
  });

  it("drains remaining items on shutdown", async () => {
    const handler = vi.fn(async (items: number[]) => items);
    const queue = new BatchingQueue(handler, {
      maxBatchSize: 10,
      minFlushMs: 10_000,
      maxFlushMs: 10_000,
      backpressureThreshold: 20,
    });

    const pending = queue.enqueue(42);
    await queue.drain();

    await expect(pending).resolves.toBe(42);
    expect(handler.mock.calls[0][1]).toBe("shutdown");
  });

  it("rejects all items when the flush handler throws", async () => {
    const queue = new BatchingQueue(async () => {
      throw new Error("rpc down");
    }, {
      maxBatchSize: 2,
      minFlushMs: 1000,
      maxFlushMs: 1000,
      backpressureThreshold: 10,
    });

    const first = queue.enqueue(1);
    const second = queue.enqueue(2);

    await expect(first).rejects.toThrow("rpc down");
    await expect(second).rejects.toThrow("rpc down");
  });
});
