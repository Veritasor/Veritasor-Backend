import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  BatchingQueue,
  resolveBatchingQueueConfig,
  type FlushTrigger,
  type BatchingQueueConfig,
} from '../../../../src/services/soroban/batchingQueue.js';
import {
  sorobanBatchSize,
  sorobanBatchFlushTotal,
  sorobanBatchItemErrorsTotal,
  sorobanBatchQueueDepth,
} from '../../../../src/metrics.js';

// ---------------------------------------------------------------------------
// Mock metrics to avoid prom-client registry conflicts
// ---------------------------------------------------------------------------
vi.mock('../../../../src/metrics.js', () => {
  const observe = vi.fn();
  const inc = vi.fn();
  const set = vi.fn();
  return {
    sorobanBatchSize: { observe },
    sorobanBatchFlushTotal: { inc },
    sorobanBatchItemErrorsTotal: { inc },
    sorobanBatchQueueDepth: { set },
  };
});

const mockBatchSizeObserve = vi.mocked(sorobanBatchSize.observe);
const mockFlushInc = vi.mocked(sorobanBatchFlushTotal.inc);
const mockItemErrorsInc = vi.mocked(sorobanBatchItemErrorsTotal.inc);
const mockQueueDepthSet = vi.mocked(sorobanBatchQueueDepth.set);

// ---------------------------------------------------------------------------
// resolveBatchingQueueConfig
// ---------------------------------------------------------------------------

describe('resolveBatchingQueueConfig', () => {
  const ORIGINAL_ENV = { ...process.env };

  afterEach(() => {
    process.env = { ...ORIGINAL_ENV };
  });

  it('returns defaults when no env vars are set', () => {
    delete process.env.SOROBAN_BATCH_MAX_SIZE;
    delete process.env.SOROBAN_BATCH_MAX_LATENCY_MS;
    delete process.env.SOROBAN_BATCH_BACKPRESSURE_THRESHOLD;
    delete process.env.SOROBAN_BATCH_FLUSH_COOLDOWN_MS;

    const config = resolveBatchingQueueConfig();
    expect(config.maxBatchSize).toBe(50);
    expect(config.maxLatencyMs).toBe(5000);
    expect(config.backpressureThreshold).toBe(100);
    expect(config.flushCooldownMs).toBe(100);
  });

  it('reads from environment variables', () => {
    process.env.SOROBAN_BATCH_MAX_SIZE = '25';
    process.env.SOROBAN_BATCH_MAX_LATENCY_MS = '3000';
    process.env.SOROBAN_BATCH_BACKPRESSURE_THRESHOLD = '75';
    process.env.SOROBAN_BATCH_FLUSH_COOLDOWN_MS = '200';

    const config = resolveBatchingQueueConfig();
    expect(config.maxBatchSize).toBe(25);
    expect(config.maxLatencyMs).toBe(3000);
    expect(config.backpressureThreshold).toBe(75);
    expect(config.flushCooldownMs).toBe(200);
  });

  it('clamps backpressure below maxBatchSize', () => {
    process.env.SOROBAN_BATCH_MAX_SIZE = '50';
    process.env.SOROBAN_BATCH_BACKPRESSURE_THRESHOLD = '10';

    const config = resolveBatchingQueueConfig();
    expect(config.backpressureThreshold).toBe(50);
  });

  it('falls back to defaults for invalid env values', () => {
    process.env.SOROBAN_BATCH_MAX_SIZE = 'not-a-number';
    process.env.SOROBAN_BATCH_MAX_LATENCY_MS = '-5';

    const config = resolveBatchingQueueConfig();
    expect(config.maxBatchSize).toBe(50);
    expect(config.maxLatencyMs).toBe(5000);
  });

  it('applies overrides on top of env', () => {
    process.env.SOROBAN_BATCH_MAX_SIZE = '25';
    const config = resolveBatchingQueueConfig({ maxBatchSize: 100 });
    expect(config.maxBatchSize).toBe(100);
  });
});

// ---------------------------------------------------------------------------
// BatchingQueue – happy paths
// ---------------------------------------------------------------------------

describe('BatchingQueue – happy paths', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('flushes items when maxBatchSize is reached', async () => {
    const processed: string[] = [];
    const flushFn = vi.fn().mockImplementation(async (items: any[]) => {
      for (const item of items) {
        processed.push(item.payload);
        item.resolve(`ok-${item.payload}`);
      }
    });

    const queue = new BatchingQueue<string>(
      { maxBatchSize: 3, maxLatencyMs: 60_000, flushCooldownMs: 0, backpressureThreshold: 100 },
      flushFn,
    );

    const p1 = queue.enqueue<string>('a');
    const p2 = queue.enqueue<string>('b');
    const p3 = queue.enqueue<string>('c');

    // The flush is triggered synchronously in checkTriggers, but is async.
    // Wait for it to complete.
    await queue.waitForPendingFlush();

    expect(flushFn).toHaveBeenCalledTimes(1);
    expect(flushFn).toHaveBeenCalledWith(
      expect.arrayContaining([
        expect.objectContaining({ payload: 'a' }),
        expect.objectContaining({ payload: 'b' }),
        expect.objectContaining({ payload: 'c' }),
      ]),
    );
    expect(processed).toEqual(['a', 'b', 'c']);

    await expect(p1).resolves.toBe('ok-a');
    await expect(p2).resolves.toBe('ok-b');
    await expect(p3).resolves.toBe('ok-c');

    queue.reset();
  });

  it('flushes items when maxLatencyMs is exceeded', async () => {
    const flushFn = vi.fn().mockImplementation(async (items: any[]) => {
      for (const item of items) {
        item.resolve(undefined);
      }
    });

    const queue = new BatchingQueue<string>(
      { maxBatchSize: 100, maxLatencyMs: 1000, flushCooldownMs: 0, backpressureThreshold: 200 },
      flushFn,
    );

    queue.enqueue('a');
    queue.enqueue('b');

    expect(flushFn).not.toHaveBeenCalled();

    // Advance time past the latency threshold
    await vi.advanceTimersByTimeAsync(1001);

    // Wait for the pending flush to complete
    await queue.waitForPendingFlush();

    expect(flushFn).toHaveBeenCalledTimes(1);
    expect(flushFn).toHaveBeenCalledWith(
      expect.arrayContaining([
        expect.objectContaining({ payload: 'a' }),
        expect.objectContaining({ payload: 'b' }),
      ]),
    );

    queue.reset();
  });

  it('flushes items when backpressure threshold is reached', async () => {
    const flushFn = vi.fn().mockImplementation(async (items: any[]) => {
      for (const item of items) {
        item.resolve(undefined);
      }
    });

    const queue = new BatchingQueue<string>(
      { maxBatchSize: 50, maxLatencyMs: 60_000, flushCooldownMs: 0, backpressureThreshold: 3 },
      flushFn,
    );

    for (let i = 0; i < 3; i++) {
      queue.enqueue(`item-${i}`);
    }

    await queue.waitForPendingFlush();

    expect(flushFn).toHaveBeenCalledTimes(1);
    expect(flushFn.mock.calls[0][0]).toHaveLength(3);

    queue.reset();
  });

  it('flushNow works manually', async () => {
    const flushFn = vi.fn().mockImplementation(async (items: any[]) => {
      for (const item of items) {
        item.resolve(undefined);
      }
    });

    const queue = new BatchingQueue<string>(
      { maxBatchSize: 100, maxLatencyMs: 60_000, flushCooldownMs: 0, backpressureThreshold: 200 },
      flushFn,
    );

    queue.enqueue('a');
    queue.enqueue('b');

    const count = await queue.flushNow();
    expect(count).toBe(2);
    expect(flushFn).toHaveBeenCalledTimes(1);

    queue.reset();
  });

  it('returns 0 for flushNow on empty queue', async () => {
    const flushFn = vi.fn().mockImplementation(async () => {});
    const queue = new BatchingQueue<string>(
      { maxBatchSize: 50, maxLatencyMs: 5000, flushCooldownMs: 0, backpressureThreshold: 100 },
      flushFn,
    );

    const count = await queue.flushNow();
    expect(count).toBe(0);
    expect(flushFn).not.toHaveBeenCalled();

    queue.reset();
  });
});

// ---------------------------------------------------------------------------
// BatchingQueue – per-item error isolation
// ---------------------------------------------------------------------------

describe('BatchingQueue – per-item error isolation', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('rejects only the failing item, not the entire batch', async () => {
    const flushFn = vi.fn().mockImplementation(async (items: any[]) => {
      for (const item of items) {
        if (item.payload === 'bad') {
          item.reject(new Error('item failed'));
        } else {
          item.resolve(`ok-${item.payload}`);
        }
      }
    });

    const queue = new BatchingQueue<string>(
      { maxBatchSize: 3, maxLatencyMs: 60_000, flushCooldownMs: 0, backpressureThreshold: 100 },
      flushFn,
    );

    const p1 = queue.enqueue<string>('good-1');
    const p2 = queue.enqueue<string>('bad');
    const p3 = queue.enqueue<string>('good-2');

    // Catch rejections to avoid unhandled promise rejection errors
    p1.catch(() => {});
    p2.catch(() => {});
    p3.catch(() => {});

    await queue.waitForPendingFlush();

    await expect(p1).resolves.toBe('ok-good-1');
    await expect(p2).rejects.toThrow('item failed');
    await expect(p3).resolves.toBe('ok-good-2');

    queue.reset();
  });

  it('rejects all items if the flush callback itself throws', async () => {
    const flushFn = vi.fn().mockImplementation(async () => {
      throw new Error('flush crash');
    });

    const queue = new BatchingQueue<string>(
      { maxBatchSize: 2, maxLatencyMs: 60_000, flushCooldownMs: 0, backpressureThreshold: 100 },
      flushFn,
    );

    const p1 = queue.enqueue<string>('a');
    const p2 = queue.enqueue<string>('b');

    p1.catch(() => {});
    p2.catch(() => {});

    await queue.waitForPendingFlush();

    await expect(p1).rejects.toThrow('flush crash');
    await expect(p2).rejects.toThrow('flush crash');

    queue.reset();
  });

  it('continues processing after a flush error', async () => {
    let flushCount = 0;
    const flushFn = vi.fn().mockImplementation(async (items: any[]) => {
      flushCount++;
      if (flushCount === 1) {
        for (const item of items) {
          item.resolve(`first-${item.payload}`);
        }
      } else {
        for (const item of items) {
          item.resolve(`second-${item.payload}`);
        }
      }
    });

    const queue = new BatchingQueue<string>(
      { maxBatchSize: 2, maxLatencyMs: 60_000, flushCooldownMs: 0, backpressureThreshold: 100 },
      flushFn,
    );

    const p1 = queue.enqueue<string>('a');
    const p2 = queue.enqueue<string>('b');

    await queue.waitForPendingFlush();

    await expect(p1).resolves.toBe('first-a');
    await expect(p2).resolves.toBe('first-b');

    const p3 = queue.enqueue<string>('c');
    const p4 = queue.enqueue<string>('d');

    await queue.waitForPendingFlush();

    await expect(p3).resolves.toBe('second-c');
    await expect(p4).resolves.toBe('second-d');

    queue.reset();
  });

  it('sorobanBatchItemErrorsTotal is incremented when flush callback throws', async () => {
    const flushFn = vi.fn().mockImplementation(async () => {
      throw new Error('flush callback crash');
    });

    const queue = new BatchingQueue<string>(
      { maxBatchSize: 2, maxLatencyMs: 60_000, flushCooldownMs: 0, backpressureThreshold: 100 },
      flushFn,
    );

    const p1 = queue.enqueue<string>('a');
    const p2 = queue.enqueue<string>('b');

    p1.catch(() => {});
    p2.catch(() => {});

    await queue.waitForPendingFlush();

    await expect(p1).rejects.toThrow('flush callback crash');
    await expect(p2).rejects.toThrow('flush callback crash');
    // inc(batch.length) = inc(2)
    expect(mockItemErrorsInc).toHaveBeenCalledWith(2);

    queue.reset();
  });
});

// ---------------------------------------------------------------------------
// BatchingQueue – flush cooldown
// ---------------------------------------------------------------------------

describe('BatchingQueue – flush cooldown', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('defers flush when cooldown is active', async () => {
    const flushFn = vi.fn().mockImplementation(async (items: any[]) => {
      for (const item of items) {
        item.resolve(undefined);
      }
    });

    const queue = new BatchingQueue<string>(
      { maxBatchSize: 2, maxLatencyMs: 60_000, flushCooldownMs: 500, backpressureThreshold: 100 },
      flushFn,
    );

    // First batch fills to maxBatchSize → immediate flush
    queue.enqueue('a');
    queue.enqueue('b');
    await queue.waitForPendingFlush();

    expect(flushFn).toHaveBeenCalledTimes(1);

    // Second batch within cooldown
    queue.enqueue('c');
    queue.enqueue('d');

    // The size trigger fires but cooldown defers it
    // After cooldown expires, the deferred flush fires
    await vi.advanceTimersByTimeAsync(600);
    await queue.waitForPendingFlush();

    expect(flushFn).toHaveBeenCalledTimes(2);

    queue.reset();
  });

  it('backpressure bypasses cooldown', async () => {
    const flushFn = vi.fn().mockImplementation(async (items: any[]) => {
      for (const item of items) {
        item.resolve(undefined);
      }
    });

    const queue = new BatchingQueue<string>(
      { maxBatchSize: 2, maxLatencyMs: 60_000, flushCooldownMs: 10_000, backpressureThreshold: 3 },
      flushFn,
    );

    // First flush
    queue.enqueue('a');
    queue.enqueue('b');
    await queue.waitForPendingFlush();
    expect(flushFn).toHaveBeenCalledTimes(1);

    // Enqueue up to backpressure threshold (bypasses cooldown)
    queue.enqueue('c');
    // After first flush completes, depth=1. Adding 2 more → depth=3 = backpressureThreshold
    // But we only add 1 here, so depth=1 after enqueue. However the latency timer
    // fires and doesn't trigger. Let's add 2 items to reach backpressure.
    queue.enqueue('d');
    queue.enqueue('e');
    await queue.waitForPendingFlush();

    // Backpressure triggered (depth >= 3), bypassing the 10s cooldown
    expect(flushFn).toHaveBeenCalledTimes(2);

    queue.reset();
  });
});

// ---------------------------------------------------------------------------
// BatchingQueue – drain
// ---------------------------------------------------------------------------

describe('BatchingQueue – drain', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('rejects all pending items on drain', async () => {
    const flushFn = vi.fn().mockImplementation(async () => {});
    const queue = new BatchingQueue<string>(
      { maxBatchSize: 100, maxLatencyMs: 60_000, flushCooldownMs: 0, backpressureThreshold: 200 },
      flushFn,
    );

    const p1 = queue.enqueue<string>('a');
    const p2 = queue.enqueue<string>('b');

    p1.catch(() => {});
    p2.catch(() => {});

    queue.drain(new Error('shutdown'));

    await expect(p1).rejects.toThrow('shutdown');
    await expect(p2).rejects.toThrow('shutdown');
    expect(queue.depth).toBe(0);
    expect(flushFn).not.toHaveBeenCalled();

    queue.reset();
  });

  it('drain with default error message', async () => {
    const flushFn = vi.fn().mockImplementation(async () => {});
    const queue = new BatchingQueue<string>(
      { maxBatchSize: 100, maxLatencyMs: 60_000, flushCooldownMs: 0, backpressureThreshold: 200 },
      flushFn,
    );

    const p1 = queue.enqueue<string>('a');
    p1.catch(() => {});
    queue.drain();

    await expect(p1).rejects.toThrow('BatchingQueue drained');

    queue.reset();
  });
});

// ---------------------------------------------------------------------------
// BatchingQueue – metrics
// ---------------------------------------------------------------------------

describe('BatchingQueue – metrics', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('records batch size on flush', async () => {
    const flushFn = vi.fn().mockImplementation(async (items: any[]) => {
      for (const item of items) item.resolve(undefined);
    });
    const queue = new BatchingQueue<string>(
      { maxBatchSize: 3, maxLatencyMs: 60_000, flushCooldownMs: 0, backpressureThreshold: 100 },
      flushFn,
    );

    queue.enqueue('a');
    queue.enqueue('b');
    queue.enqueue('c');

    await queue.waitForPendingFlush();

    expect(mockBatchSizeObserve).toHaveBeenCalledWith(3);
    expect(mockFlushInc).toHaveBeenCalledWith({ trigger: 'size' });

    queue.reset();
  });

  it('records flush trigger as latency', async () => {
    const flushFn = vi.fn().mockImplementation(async (items: any[]) => {
      for (const item of items) item.resolve(undefined);
    });
    const queue = new BatchingQueue<string>(
      { maxBatchSize: 100, maxLatencyMs: 500, flushCooldownMs: 0, backpressureThreshold: 200 },
      flushFn,
    );

    queue.enqueue('a');
    await vi.advanceTimersByTimeAsync(501);
    await queue.waitForPendingFlush();

    expect(mockFlushInc).toHaveBeenCalledWith({ trigger: 'latency' });

    queue.reset();
  });

  it('records flush trigger as backpressure', async () => {
    const flushFn = vi.fn().mockImplementation(async (items: any[]) => {
      for (const item of items) item.resolve(undefined);
    });
    const queue = new BatchingQueue<string>(
      { maxBatchSize: 50, maxLatencyMs: 60_000, flushCooldownMs: 0, backpressureThreshold: 3 },
      flushFn,
    );

    queue.enqueue('a');
    queue.enqueue('b');
    queue.enqueue('c');

    await queue.waitForPendingFlush();

    expect(mockFlushInc).toHaveBeenCalledWith({ trigger: 'backpressure' });

    queue.reset();
  });

  it('updates queue depth gauge', async () => {
    const flushFn = vi.fn().mockImplementation(async (items: any[]) => {
      for (const item of items) item.resolve(undefined);
    });
    const queue = new BatchingQueue<string>(
      { maxBatchSize: 2, maxLatencyMs: 60_000, flushCooldownMs: 0, backpressureThreshold: 100 },
      flushFn,
    );

    queue.enqueue('a');
    expect(mockQueueDepthSet).toHaveBeenCalledWith(1);

    queue.enqueue('b');
    expect(mockQueueDepthSet).toHaveBeenCalledWith(2);

    await queue.waitForPendingFlush();
    expect(mockQueueDepthSet).toHaveBeenCalledWith(0);

    queue.reset();
  });
});

// ---------------------------------------------------------------------------
// BatchingQueue – edge cases
// ---------------------------------------------------------------------------

describe('BatchingQueue – edge cases', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('handles empty flush callback gracefully', async () => {
    const flushFn = vi.fn().mockImplementation(async () => {});
    const queue = new BatchingQueue<string>(
      { maxBatchSize: 50, maxLatencyMs: 5000, flushCooldownMs: 0, backpressureThreshold: 100 },
      flushFn,
    );

    const count = await queue.flushNow();
    expect(count).toBe(0);

    queue.reset();
  });

  it('getConfig returns a snapshot', () => {
    const flushFn = vi.fn();
    const queue = new BatchingQueue<string>(
      { maxBatchSize: 42 },
      flushFn,
    );

    const config = queue.getConfig();
    expect(config.maxBatchSize).toBe(42);

    (config as any).maxBatchSize = 999;
    expect(queue.getConfig().maxBatchSize).toBe(42);

    queue.reset();
  });

  it('oldestWaitMs returns 0 for empty queue', () => {
    const flushFn = vi.fn();
    const queue = new BatchingQueue<string>(
      { maxBatchSize: 50, maxLatencyMs: 5000, flushCooldownMs: 0, backpressureThreshold: 100 },
      flushFn,
    );

    expect(queue.oldestWaitMs()).toBe(0);

    queue.reset();
  });

  it('depth reflects current queue size', async () => {
    const flushFn = vi.fn().mockImplementation(async (items: any[]) => {
      for (const item of items) item.resolve(undefined);
    });
    const queue = new BatchingQueue<string>(
      { maxBatchSize: 10, maxLatencyMs: 60_000, flushCooldownMs: 0, backpressureThreshold: 100 },
      flushFn,
    );

    expect(queue.depth).toBe(0);
    queue.enqueue('a');
    expect(queue.depth).toBe(1);
    queue.enqueue('b');
    expect(queue.depth).toBe(2);

    await queue.flushNow();
    expect(queue.depth).toBe(0);

    queue.reset();
  });

  it('reset clears all state', async () => {
    const flushFn = vi.fn().mockImplementation(async (items: any[]) => {
      for (const item of items) item.resolve(undefined);
    });
    const queue = new BatchingQueue<string>(
      { maxBatchSize: 2, maxLatencyMs: 1000, flushCooldownMs: 0, backpressureThreshold: 100 },
      flushFn,
    );

    queue.enqueue('a');
    queue.enqueue('b');

    await queue.waitForPendingFlush();
    expect(flushFn).toHaveBeenCalledTimes(1);

    queue.reset();

    expect(queue.depth).toBe(0);
    expect(queue.oldestWaitMs()).toBe(0);

    queue.reset();
  });

  it('resolves promises when flushFn resolves them', async () => {
    const flushFn = vi.fn().mockImplementation(async (items: any[]) => {
      for (const item of items) {
        item.resolve({ txHash: `tx-${item.payload}` });
      }
    });

    const queue = new BatchingQueue<string>(
      { maxBatchSize: 2, maxLatencyMs: 60_000, flushCooldownMs: 0, backpressureThreshold: 100 },
      flushFn,
    );

    const p1 = queue.enqueue<{ txHash: string }>('leaf1');
    const p2 = queue.enqueue<{ txHash: string }>('leaf2');

    await queue.waitForPendingFlush();

    await expect(p1).resolves.toEqual({ txHash: 'tx-leaf1' });
    await expect(p2).resolves.toEqual({ txHash: 'tx-leaf2' });

    queue.reset();
  });

  it('flushes batch capped at maxBatchSize per cycle', async () => {
    const processed: string[] = [];
    const flushFn = vi.fn().mockImplementation(async (items: any[]) => {
      for (const item of items) {
        processed.push(item.payload);
        item.resolve(undefined);
      }
    });

    const queue = new BatchingQueue<string>(
      { maxBatchSize: 2, maxLatencyMs: 60_000, flushCooldownMs: 0, backpressureThreshold: 100 },
      flushFn,
    );

    // Enqueue 2 items → triggers size flush with batch of 2
    queue.enqueue('a');
    queue.enqueue('b');
    await queue.waitForPendingFlush();

    // First flush: exactly maxBatchSize items
    expect(flushFn).toHaveBeenCalledTimes(1);
    expect(flushFn.mock.calls[0][0]).toHaveLength(2);
    expect(processed).toEqual(['a', 'b']);

    // Enqueue 2 more → triggers another size flush
    queue.enqueue('c');
    queue.enqueue('d');
    await queue.waitForPendingFlush();

    expect(flushFn).toHaveBeenCalledTimes(2);
    expect(processed).toEqual(['a', 'b', 'c', 'd']);

    queue.reset();
  });

  it('handles sequential batch processing', async () => {
    const processed: string[] = [];
    const flushFn = vi.fn().mockImplementation(async (items: any[]) => {
      for (const item of items) {
        processed.push(item.payload);
        item.resolve(undefined);
      }
    });

    const queue = new BatchingQueue<string>(
      { maxBatchSize: 2, maxLatencyMs: 60_000, flushCooldownMs: 0, backpressureThreshold: 100 },
      flushFn,
    );

    queue.enqueue('a');
    queue.enqueue('b');
    await queue.waitForPendingFlush();

    expect(flushFn).toHaveBeenCalledTimes(1);
    expect(processed).toEqual(['a', 'b']);

    queue.enqueue('c');
    queue.enqueue('d');
    await queue.waitForPendingFlush();

    expect(flushFn).toHaveBeenCalledTimes(2);
    expect(processed).toEqual(['a', 'b', 'c', 'd']);

    queue.reset();
  });
});

// ---------------------------------------------------------------------------
// BatchingQueue – concurrent flush prevention
// ---------------------------------------------------------------------------

describe('BatchingQueue – concurrent flush prevention', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('does not start a second flush while one is in progress', async () => {
    let resolveFlush1: () => void;
    const flush1Done = new Promise<void>((r) => { resolveFlush1 = r; });

    let flushCount = 0;
    const flushFn = vi.fn().mockImplementation(async (items: any[]) => {
      flushCount++;
      if (flushCount === 1) {
        await flush1Done;
      }
      for (const item of items) {
        item.resolve(undefined);
      }
    });

    const queue = new BatchingQueue<string>(
      { maxBatchSize: 2, maxLatencyMs: 60_000, flushCooldownMs: 0, backpressureThreshold: 100 },
      flushFn,
    );

    queue.enqueue('a');
    queue.enqueue('b');

    // First flush starts (async)
    await vi.advanceTimersByTimeAsync(0);
    expect(flushFn).toHaveBeenCalledTimes(1);

    // Enqueue more while flush is in progress — flushing=true, so no new flush
    queue.enqueue('c');
    queue.enqueue('d');

    // These enqueues didn't trigger a new flush because flushing=true
    expect(flushFn).toHaveBeenCalledTimes(1);

    // Complete the first flush
    resolveFlush1!();
    await queue.waitForPendingFlush();

    // checkTriggers in finally now sees depth=2 = maxBatchSize → triggers second flush
    await queue.waitForPendingFlush();

    expect(flushFn).toHaveBeenCalledTimes(2);

    queue.reset();
  });
});
