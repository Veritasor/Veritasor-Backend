/**
 * @file batchingQueue.ts
 * @description Adaptive flush-window batch queue for Soroban attestation
 * submissions.  Batches multiple submissions into a single flush cycle
 * when traffic spikes occur.
 *
 * ## Flush triggers
 * The queue flushes when *any* of the following conditions is met:
 *
 * 1. **Size** – queue depth reaches `maxBatchSize`.
 * 2. **Latency** – the oldest item has been waiting longer than
 *    `maxLatencyMs` (adaptive flush window).
 * 3. **Backpressure** – queue depth reaches `backpressureThreshold`
 *    (typically > maxBatchSize) indicating the consumer is falling behind.
 *
 * ## Per-item error isolation
 * Each item in a flush batch is resolved/rejected independently. A single
 * failing leaf does **not** roll back the whole batch.
 *
 * ## Metrics
 * - `soroban_batch_size` histogram – items per flush cycle
 * - `soroban_batch_flush_total` counter – flush cycles by trigger
 * - `soroban_batch_item_errors_total` counter – individual item failures
 * - `soroban_batch_queue_depth` gauge – current queue depth
 */

import { logger } from '../../utils/logger.js';
import {
  sorobanBatchSize,
  sorobanBatchFlushTotal,
  sorobanBatchItemErrorsTotal,
  sorobanBatchQueueDepth,
} from '../../metrics.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** The reason a flush cycle was initiated. */
export type FlushTrigger = 'size' | 'latency' | 'backpressure' | 'manual';

/**
 * A single item waiting in the batch queue.
 *
 * @typeParam T – payload type carried by the item.
 */
export type BatchingQueueItem<T> = {
  /** Caller-supplied payload. */
  payload: T;
  /**
   * Monotonic timestamp (ms) when the item was enqueued.
   * Used to compute wait latency and trigger latency-based flushes.
   */
  enqueuedAt: number;
  /** Per-item resolve callback. */
  resolve: (value: unknown) => void;
  /** Per-item reject callback. */
  reject: (reason?: unknown) => void;
};

/**
 * Configuration for the adaptive batch queue.
 *
 * All fields have safe defaults; override via the constructor or env vars.
 */
export type BatchingQueueConfig = {
  /**
   * Maximum number of items per flush batch. When the queue reaches this
   * depth a size-triggered flush fires.
   */
  maxBatchSize: number;
  /**
   * Maximum time (ms) an item may sit in the queue before a latency-triggered
   * flush fires.  This is the "adaptive flush window".
   */
  maxLatencyMs: number;
  /**
   * Backpressure threshold – when the queue reaches this depth the consumer
   * is considered overloaded and a flush is forced immediately, even if
   * maxBatchSize has not been reached.
   *
   * Must be >= maxBatchSize.  Defaults to `maxBatchSize * 2`.
   */
  backpressureThreshold: number;
  /**
   * Minimum interval (ms) between consecutive flushes to avoid flush storms
   * during sustained high throughput.  A flush requested within this window
   * is deferred until the cooldown expires.
   */
  flushCooldownMs: number;
};

const DEFAULT_BATCHING_QUEUE_CONFIG: BatchingQueueConfig = {
  maxBatchSize: 50,
  maxLatencyMs: 5000,
  backpressureThreshold: 100,
  flushCooldownMs: 100,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Resolves batching-queue configuration from environment variables with
 * fallback to defaults.
 */
export function resolveBatchingQueueConfig(
  overrides?: Partial<BatchingQueueConfig>,
): BatchingQueueConfig {
  const base: BatchingQueueConfig = {
    maxBatchSize: parsePositiveIntEnv(
      'SOROBAN_BATCH_MAX_SIZE',
      DEFAULT_BATCHING_QUEUE_CONFIG.maxBatchSize,
    ),
    maxLatencyMs: parsePositiveIntEnv(
      'SOROBAN_BATCH_MAX_LATENCY_MS',
      DEFAULT_BATCHING_QUEUE_CONFIG.maxLatencyMs,
    ),
    backpressureThreshold: parsePositiveIntEnv(
      'SOROBAN_BATCH_BACKPRESSURE_THRESHOLD',
      DEFAULT_BATCHING_QUEUE_CONFIG.backpressureThreshold,
    ),
    flushCooldownMs: parsePositiveIntEnv(
      'SOROBAN_BATCH_FLUSH_COOLDOWN_MS',
      DEFAULT_BATCHING_QUEUE_CONFIG.flushCooldownMs,
    ),
  };

  // Ensure backpressure >= maxBatchSize
  if (base.backpressureThreshold < base.maxBatchSize) {
    base.backpressureThreshold = base.maxBatchSize;
  }

  return { ...base, ...overrides };
}

function parsePositiveIntEnv(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined) return fallback;
  const val = Number.parseInt(raw.trim(), 10);
  if (!Number.isInteger(val) || val <= 0) {
    logger.warn(
      { envVar: name, raw },
      'batching-queue: invalid positive integer env, using fallback',
    );
    return fallback;
  }
  return val;
}

// ---------------------------------------------------------------------------
// BatchingQueue class
// ---------------------------------------------------------------------------

/**
 * Adaptive-flush-window batch queue for Soroban submissions.
 *
 * Items are enqueued via {@link enqueue} and processed in batches via the
 * caller-supplied `flush` callback passed to the constructor.
 *
 * Flushes are triggered by:
 * - Queue depth reaching `maxBatchSize` (size trigger).
 * - Oldest item waiting longer than `maxLatencyMs` (latency trigger).
 * - Queue depth reaching `backpressureThreshold` (backpressure trigger).
 * - Explicit call to {@link flushNow} (manual trigger).
 *
 * A flush cooldown prevents flush storms during sustained high throughput.
 *
 * @example
 * ```ts
 * const queue = new BatchingQueue<MyPayload>({
 *   maxBatchSize: 50,
 *   maxLatencyMs: 5000,
 * }, async (items) => {
 *   for (const item of items) {
 *     try {
 *       const result = await processItem(item.payload);
 *       item.resolve(result);
 *     } catch (err) {
 *       item.reject(err);
 *     }
 *   }
 * });
 *
 * // Enqueue items
 * const result = await queue.enqueue(myPayload);
 * ```
 */
export class BatchingQueue<T = unknown> {
  private queue: BatchingQueueItem<T>[] = [];
  private latencyTimer: ReturnType<typeof setTimeout> | null = null;
  private lastFlushTime = 0;
  private flushing = false;
  private _pendingFlush: Promise<number> = Promise.resolve(0);
  private readonly config: BatchingQueueConfig;
  private readonly flushFn: (items: BatchingQueueItem<T>[]) => Promise<void>;

  /**
   * @param config  - Queue configuration (max batch size, latency, backpressure).
   * @param flushFn - Async callback invoked with the batch of items to process.
   *                  The callback MUST handle per-item resolve/reject – it must
   *                  NOT throw as that would cause unhandled rejections.
   */
  constructor(
    config: Partial<BatchingQueueConfig> | undefined,
    flushFn: (items: BatchingQueueItem<T>[]) => Promise<void>,
  ) {
    this.config = resolveBatchingQueueConfig(config);
    this.flushFn = flushFn;
  }

  // -------------------------------------------------------------------------
  // Public API
  // -------------------------------------------------------------------------

  /**
   * Enqueues a payload and returns a promise that resolves when the item is
   * processed in a flush batch.
   *
   * The promise is resolved/rejected by the flush callback – not by the
   * queue itself.  This gives the caller full control over per-item semantics.
   *
   * @param payload - The attestation submission params to batch.
   * @returns A promise that resolves with the flush callback's result for this item.
   */
  enqueue<R = unknown>(payload: T): Promise<R> {
    return new Promise<R>((resolve, reject) => {
      const item: BatchingQueueItem<T> = {
        payload,
        enqueuedAt: Date.now(),
        resolve: resolve as (value: unknown) => void,
        reject,
      };

      this.queue.push(item);
      this.updateQueueDepthMetric();

      logger.debug(
        { queueDepth: this.queue.length, maxBatchSize: this.config.maxBatchSize },
        'batching-queue: item enqueued',
      );

      // Schedule latency-based flush if this is the first item
      if (this.queue.length === 1) {
        this.scheduleLatencyFlush();
      }

      // Check immediate flush triggers
      this.checkTriggers();
    });
  }

  /**
   * Forces an immediate flush, bypassing cooldown and latency timers.
   *
   * Returns the number of items that were flushed (may be 0 if the queue
   * is empty or a flush is already in progress).
   */
  async flushNow(): Promise<number> {
    return this.doFlush('manual');
  }

  /**
   * Returns the current queue depth.
   */
  get depth(): number {
    return this.queue.length;
  }

  /**
   * Returns the current configuration (read-only snapshot).
   */
  getConfig(): Readonly<BatchingQueueConfig> {
    return { ...this.config };
  }

  /**
   * Returns the oldest item's wait time in ms, or 0 if the queue is empty.
   */
  oldestWaitMs(): number {
    if (this.queue.length === 0) return 0;
    return Date.now() - this.queue[0].enqueuedAt;
  }

  /**
   * Drains the queue without processing, rejecting all pending items.
   * Useful for graceful shutdown.
   *
   * @param reason - Error passed to each item's reject callback.
   */
  drain(reason?: unknown): void {
    this.clearLatencyTimer();
    const items = this.queue.splice(0);
    this.updateQueueDepthMetric();

    for (const item of items) {
      item.reject(reason ?? new Error('BatchingQueue drained'));
    }
  }

  /**
   * Waits for any in-flight flush to complete.
   * Useful in tests to ensure all flush side-effects have settled.
   */
  async waitForPendingFlush(): Promise<void> {
    await this._pendingFlush;
  }

  /**
   * Resets internal state.  Useful in tests.
   */
  reset(): void {
    this.clearLatencyTimer();
    this.queue = [];
    this.lastFlushTime = 0;
    this.flushing = false;
    this.updateQueueDepthMetric();
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  /**
   * Checks all flush triggers and fires a flush if any are met.
   */
  private checkTriggers(): void {
    if (this.flushing) return;

    const depth = this.queue.length;

    // Backpressure trigger (checked first – highest priority)
    if (depth >= this.config.backpressureThreshold) {
      this._pendingFlush = this.doFlush('backpressure');
      return;
    }

    // Size trigger
    if (depth >= this.config.maxBatchSize) {
      this._pendingFlush = this.doFlush('size');
      return;
    }
  }

  /**
   * Schedules a latency-based flush based on the oldest item's age.
   *
   * If the oldest item has already exceeded maxLatencyMs, flush is
   * triggered immediately.  Otherwise a timer is set for the remaining
   * time.
   */
  private scheduleLatencyFlush(): void {
    this.clearLatencyTimer();

    if (this.queue.length === 0) return;

    const oldestAge = Date.now() - this.queue[0].enqueuedAt;
    const remaining = this.config.maxLatencyMs - oldestAge;

    if (remaining <= 0) {
      // Already overdue – flush on next tick to allow batch coalescing
      this.latencyTimer = setTimeout(() => {
        this.latencyTimer = null;
        if (this.queue.length > 0 && !this.flushing) {
          this._pendingFlush = this.doFlush('latency');
        }
      }, 0);
      return;
    }

    this.latencyTimer = setTimeout(() => {
      this.latencyTimer = null;
      if (this.queue.length > 0 && !this.flushing) {
        this._pendingFlush = this.doFlush('latency');
      }
    }, remaining);
  }

  /**
   * Executes a flush cycle for the given trigger.
   *
   * Items are batched up to `maxBatchSize` (or all available if fewer).
   * The flush callback handles per-item resolve/reject – a single failure
   * does not poison the batch.
   */
  private async doFlush(trigger: FlushTrigger): Promise<number> {
    if (this.flushing || this.queue.length === 0) return 0;

    // Cooldown check (skip for backpressure – safety override)
    if (trigger !== 'backpressure' && trigger !== 'manual') {
      const sinceLastFlush = Date.now() - this.lastFlushTime;
      if (sinceLastFlush < this.config.flushCooldownMs) {
        // Defer to cooldown expiry
        setTimeout(() => {
          if (this.queue.length > 0 && !this.flushing) {
            this._pendingFlush = this.doFlush(trigger);
          }
        }, this.config.flushCooldownMs - sinceLastFlush);
        return 0;
      }
    }

    this.flushing = true;
    this.clearLatencyTimer();

    // Drain the batch
    const batchSize = Math.min(this.config.maxBatchSize, this.queue.length);
    const batch = this.queue.splice(0, batchSize);
    this.updateQueueDepthMetric();

    this.lastFlushTime = Date.now();

    // Record metrics
    sorobanBatchSize.observe(batch.length);
    sorobanBatchFlushTotal.inc({ trigger });

    logger.info(
      {
        trigger,
        batchSize,
        remainingDepth: this.queue.length,
        oldestWaitMs: batch.length > 0 ? Date.now() - batch[0].enqueuedAt : 0,
      },
      'batching-queue: flushing batch',
    );

    try {
      await this.flushFn(batch);
    } catch (err) {
      // The flush callback should not throw, but if it does, reject all items
      logger.error(
        { trigger, batchSize, error: err instanceof Error ? err.message : String(err) },
        'batching-queue: flush callback threw – rejecting all items in batch',
      );
      sorobanBatchItemErrorsTotal.inc(batch.length);
      for (const item of batch) {
        item.reject(err);
      }
    } finally {
      this.flushing = false;

      // Re-schedule latency flush if items remain
      if (this.queue.length > 0) {
        this.scheduleLatencyFlush();
      }

      // Check if new items arrived during flush and need immediate processing
      this.checkTriggers();
    }

    return batch.length;
  }

  private clearLatencyTimer(): void {
    if (this.latencyTimer !== null) {
      clearTimeout(this.latencyTimer);
      this.latencyTimer = null;
    }
  }

  private updateQueueDepthMetric(): void {
    sorobanBatchQueueDepth.set(this.queue.length);
  }
}
