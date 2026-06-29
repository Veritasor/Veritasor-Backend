import { sorobanBatchSize } from "../../metrics.js";

export type FlushReason = "size" | "latency" | "backpressure" | "shutdown";

export type BatchingQueueConfig = {
  /** Maximum items coalesced into one flush. */
  maxBatchSize: number;
  /** Shortest adaptive flush window (ms) under sustained load. */
  minFlushMs: number;
  /** Longest adaptive flush window (ms) under idle load. */
  maxFlushMs: number;
  /** Queue depth that forces an immediate flush. */
  backpressureThreshold: number;
};

export type QueuedItem<T> = {
  payload: T;
  resolve: (value: unknown) => void;
  reject: (error: unknown) => void;
  enqueuedAt: number;
};

export type BatchFlushHandler<T, R> = (
  items: T[],
  reason: FlushReason,
) => Promise<Array<R | { error: unknown }>>;

const DEFAULT_CONFIG: BatchingQueueConfig = {
  maxBatchSize: 20,
  minFlushMs: 50,
  maxFlushMs: 500,
  backpressureThreshold: 100,
};

/**
 * Generic batching queue with size, latency, and backpressure flush triggers.
 *
 * The flush window adapts to arrival rate: sustained traffic shrinks the window
 * toward `minFlushMs`; idle periods expand it toward `maxFlushMs`.
 */
export class BatchingQueue<T, R = unknown> {
  private readonly config: BatchingQueueConfig;
  private readonly flushHandler: BatchFlushHandler<T, R>;
  private readonly sleep: (ms: number) => Promise<void>;

  private queue: QueuedItem<T>[] = [];
  private flushTimer: ReturnType<typeof setTimeout> | null = null;
  private currentFlushWindowMs: number;
  private flushing = false;
  private pendingFlush: Promise<void> | null = null;
  private recentArrivals: number[] = [];

  constructor(
    flushHandler: BatchFlushHandler<T, R>,
    config: Partial<BatchingQueueConfig> = {},
    sleep: (ms: number) => Promise<void> = (ms) =>
      new Promise((resolve) => setTimeout(resolve, ms)),
  ) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.flushHandler = flushHandler;
    this.sleep = sleep;
    this.currentFlushWindowMs = this.config.maxFlushMs;

    if (this.config.maxBatchSize < 1) {
      throw new Error("maxBatchSize must be at least 1");
    }
    if (this.config.minFlushMs > this.config.maxFlushMs) {
      throw new Error("minFlushMs must be less than or equal to maxFlushMs");
    }
    if (this.config.backpressureThreshold < this.config.maxBatchSize) {
      throw new Error(
        "backpressureThreshold must be greater than or equal to maxBatchSize",
      );
    }
  }

  /** Number of items waiting to be flushed. */
  get depth(): number {
    return this.queue.length;
  }

  /** Current adaptive flush window in milliseconds. */
  get flushWindowMs(): number {
    return this.currentFlushWindowMs;
  }

  /**
   * Enqueues an item and returns a promise resolved when its batch flush completes.
   */
  enqueue(payload: T): Promise<R> {
    return new Promise<R>((resolve, reject) => {
      this.queue.push({
        payload,
        resolve: resolve as (value: unknown) => void,
        reject,
        enqueuedAt: Date.now(),
      });

      this.recordArrival();

      if (this.queue.length >= this.config.backpressureThreshold) {
        void this.triggerFlush("backpressure");
        return;
      }

      if (this.queue.length >= this.config.maxBatchSize) {
        void this.triggerFlush("size");
        return;
      }

      this.scheduleLatencyFlush();
    });
  }

  /** Flushes remaining items; used during graceful shutdown. */
  async drain(): Promise<void> {
    if (this.queue.length === 0) {
      return;
    }
    await this.triggerFlush("shutdown");
  }

  private recordArrival(): void {
    const now = Date.now();
    this.recentArrivals.push(now);
    const cutoff = now - 1000;
    while (this.recentArrivals.length > 0 && this.recentArrivals[0] < cutoff) {
      this.recentArrivals.shift();
    }
    this.adaptFlushWindow();
  }

  /**
   * Adapts the flush window based on arrivals in the last second.
   * High traffic -> shorter window; low traffic -> longer window.
   */
  adaptFlushWindow(): void {
    const arrivalsPerSecond = this.recentArrivals.length;
    const { minFlushMs, maxFlushMs, maxBatchSize } = this.config;

    if (arrivalsPerSecond === 0) {
      this.currentFlushWindowMs = maxFlushMs;
      return;
    }

    const loadRatio = Math.min(1, arrivalsPerSecond / maxBatchSize);
    this.currentFlushWindowMs = Math.round(
      maxFlushMs - loadRatio * (maxFlushMs - minFlushMs),
    );
  }

  private scheduleLatencyFlush(): void {
    if (this.flushTimer !== null) {
      return;
    }

    const windowMs = this.currentFlushWindowMs;
    this.flushTimer = setTimeout(() => {
      this.flushTimer = null;
      void this.triggerFlush("latency");
    }, windowMs);
  }

  private clearFlushTimer(): void {
    if (this.flushTimer !== null) {
      clearTimeout(this.flushTimer);
      this.flushTimer = null;
    }
  }

  private async triggerFlush(reason: FlushReason): Promise<void> {
    if (this.pendingFlush) {
      await this.pendingFlush;
      if (this.queue.length === 0) {
        return;
      }
    }

    if (this.queue.length === 0) {
      return;
    }

    this.pendingFlush = this.flush(reason);
    try {
      await this.pendingFlush;
    } finally {
      this.pendingFlush = null;
    }
  }

  private async flush(reason: FlushReason): Promise<void> {
    if (this.flushing) {
      return;
    }

    this.clearFlushTimer();
    this.flushing = true;

    try {
      while (this.queue.length > 0) {
        const batchSize = Math.min(this.queue.length, this.config.maxBatchSize);
        const batch = this.queue.splice(0, batchSize);

        sorobanBatchSize.observe({ reason }, batch.length);

        let results: Array<R | { error: unknown }>;
        try {
          results = await this.flushHandler(
            batch.map((item) => item.payload),
            reason,
          );
        } catch (error) {
          for (const item of batch) {
            item.reject(error);
          }
          continue;
        }

        if (results.length !== batch.length) {
          const mismatchError = new Error(
            `Batch flush handler returned ${results.length} results for ${batch.length} items`,
          );
          for (const item of batch) {
            item.reject(mismatchError);
          }
          continue;
        }

        for (let i = 0; i < batch.length; i++) {
          const result = results[i];
          if (
            result !== null &&
            typeof result === "object" &&
            "error" in result &&
            result.error !== undefined
          ) {
            batch[i].reject(result.error);
          } else {
            batch[i].resolve(result as R);
          }
        }
      }
    } finally {
      this.flushing = false;
    }
  }
}
