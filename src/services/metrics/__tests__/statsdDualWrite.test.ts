import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { Registry, Counter, Gauge, Histogram, Summary } from 'prom-client';
import {
  startStatsdDualWrite,
  type StatsdDualWriteHandle,
} from '../statsdDualWrite.js';

// Mock the observability metrics from src/metrics.ts
vi.mock('../../../metrics.js', () => ({
  statsdDualWriteRunsTotal: {
    inc: vi.fn(),
  },
  statsdDualWriteErrorsTotal: {
    inc: vi.fn(),
  },
  statsdDualWriteDurationMs: {
    observe: vi.fn(),
  },
  statsdDualWriteMetricsCount: {
    set: vi.fn(),
  },
}));

vi.mock('../../../utils/logger.js', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

import {
  statsdDualWriteRunsTotal,
  statsdDualWriteErrorsTotal,
  statsdDualWriteDurationMs,
  statsdDualWriteMetricsCount,
} from '../../../metrics.js';

/** Create a mock StatsD client for testing */
function createMockStatsdClient() {
  return {
    gauge: vi.fn(),
    increment: vi.fn(),
    timing: vi.fn(),
    histogram: vi.fn(),
    close: vi.fn().mockResolvedValue(undefined),
  };
}

describe('startStatsdDualWrite', () => {
  let registry: Registry;
  let handle: StatsdDualWriteHandle | null;

  beforeEach(() => {
    vi.useFakeTimers();
    registry = new Registry();
    handle = null;
    vi.clearAllMocks();
  });

  afterEach(async () => {
    vi.useRealTimers();
    if (handle) {
      await handle.stop();
    }
    registry.clear();
  });

  /** Advance time and run pending timers, then advance again to catch the next cycle if needed */
  async function runCycles(count: number, intervalMs: number): Promise<void> {
    for (let i = 0; i < count; i++) {
      vi.advanceTimersByTime(intervalMs);
      // flush promises so async logging can resolve
      await vi.runAllTimersAsync();
    }
  }

  it('does not start pushing immediately; waits for first interval', () => {
    const client = createMockStatsdClient();
    handle = startStatsdDualWrite({
      statsdClient: client as any,
      registry,
      intervalMs: 10_000,
    });

    // No calls before the first interval elapses
    expect(client.gauge).not.toHaveBeenCalled();
    expect(client.increment).not.toHaveBeenCalled();
  });

  it('pushes gauge metrics to StatsD', async () => {
    const g = new Gauge({
      name: 'test_gauge',
      help: 'test',
      registers: [registry],
    });
    g.set(42);

    const client = createMockStatsdClient();
    handle = startStatsdDualWrite({
      statsdClient: client as any,
      registry,
      intervalMs: 10_000,
    });

    await runCycles(1, 10_000);

    expect(client.gauge).toHaveBeenCalledWith('test_gauge', 42, {});
  });

  it('pushes gauge metrics with labels', async () => {
    const g = new Gauge({
      name: 'test_gauge_labelled',
      help: 'test',
      labelNames: ['env'] as const,
      registers: [registry],
    });
    g.set({ env: 'production' }, 99);

    const client = createMockStatsdClient();
    handle = startStatsdDualWrite({
      statsdClient: client as any,
      registry,
      intervalMs: 5_000,
    });

    await runCycles(1, 5_000);

    expect(client.gauge).toHaveBeenCalledWith('test_gauge_labelled', 99, {
      env: 'production',
    });
  });

  it('pushes counter deltas to StatsD', async () => {
    const c = new Counter({
      name: 'test_counter',
      help: 'test',
      registers: [registry],
    });

    const client = createMockStatsdClient();
    handle = startStatsdDualWrite({
      statsdClient: client as any,
      registry,
      intervalMs: 10_000,
    });

    // No increments before counter is used
    await runCycles(1, 10_000);
    expect(client.increment).not.toHaveBeenCalled();

    // Increment counter by 5
    c.inc(5);

    await runCycles(1, 10_000);
    expect(client.increment).toHaveBeenCalledWith('test_counter', 5, {});

    vi.clearAllMocks();
    c.inc(3);

    // Next cycle should only emit the delta (3)
    await runCycles(1, 10_000);
    expect(client.increment).toHaveBeenCalledWith('test_counter', 3, {});
  });

  it('handles counter resets (restart scenario)', async () => {
    const c = new Counter({
      name: 'test_restart_counter',
      help: 'test',
      registers: [registry],
    });
    c.inc(100);

    const client = createMockStatsdClient();
    handle = startStatsdDualWrite({
      statsdClient: client as any,
      registry,
      intervalMs: 10_000,
    });

    // First cycle: emit 100 delta
    await runCycles(1, 10_000);
    expect(client.increment).toHaveBeenCalledWith('test_restart_counter', 100, {});

    // Simulate restart: unregister and re-register (counter goes back to 0)
    vi.clearAllMocks();
    registry.removeSingleMetric('test_restart_counter');
    const c2 = new Counter({
      name: 'test_restart_counter',
      help: 'test',
      registers: [registry],
    });
    c2.inc(1);

    await runCycles(1, 10_000);
    // Since the counter value went from 100 → gone → 1,
    // previousCounters still has 100, but the registry now reports 1.
    // Delta = 1 - 100 = -99, which is negative, so nothing is emitted.
    // This is correct behaviour: StatsD doesn't handle negative increments well.
    expect(client.increment).not.toHaveBeenCalled();
  });

  it('pushes histogram metrics with buckets', async () => {
    const h = new Histogram({
      name: 'test_histogram',
      help: 'test',
      buckets: [0.1, 0.5, 1],
      registers: [registry],
    });
    h.observe(0.3); // falls in [0.5] bucket
    h.observe(0.8); // falls in [1] bucket

    const client = createMockStatsdClient();
    handle = startStatsdDualWrite({
      statsdClient: client as any,
      registry,
      intervalMs: 10_000,
    });

    await runCycles(1, 10_000);

    // Should emit bucket counts
    expect(client.histogram).toHaveBeenCalledWith(
      'test_histogram_bucket',
      expect.any(Number),
      expect.objectContaining({ le: expect.any(String) }),
    );
    // Should emit timing for the sum delta (0.3 + 0.8 = 1.1 seconds → 1100 ms)
    expect(client.timing).toHaveBeenCalledWith('test_histogram', 1100, {});
  });

  it('pushes summary metrics', async () => {
    const s = new Summary({
      name: 'test_summary',
      help: 'test',
      percentiles: [0.5, 0.9],
      registers: [registry],
    });
    s.observe(10);
    s.observe(20);

    const client = createMockStatsdClient();
    handle = startStatsdDualWrite({
      statsdClient: client as any,
      registry,
      intervalMs: 10_000,
    });

    await runCycles(1, 10_000);

    // Should emit quantiles and count
    expect(client.histogram).toHaveBeenCalledWith(
      'test_summary_count',
      2,
      {},
    );
  });

  it('sanitizes metric names with colons', async () => {
    const g = new Gauge({
      name: 'my_service:metric_name',
      help: 'test',
      registers: [registry],
    });
    g.set(1);

    const client = createMockStatsdClient();
    handle = startStatsdDualWrite({
      statsdClient: client as any,
      registry,
      intervalMs: 10_000,
    });

    await runCycles(1, 10_000);

    expect(client.gauge).toHaveBeenCalledWith(
      expect.stringContaining('my_service_metric_name'),
      1,
      {},
    );
  });

  it('sanitizes label values in tags', async () => {
    const g = new Gauge({
      name: 'test_sanitize',
      help: 'test',
      labelNames: ['path'] as const,
      registers: [registry],
    });
    g.set({ path: '/api/v1/health' }, 1);

    const client = createMockStatsdClient();
    handle = startStatsdDualWrite({
      statsdClient: client as any,
      registry,
      intervalMs: 10_000,
    });

    await runCycles(1, 10_000);

    expect(client.gauge).toHaveBeenCalledWith(
      'test_sanitize',
      1,
      { path: '_api_v1_health' },
    );
  });

  it('emits run outcome=ok after a successful cycle', async () => {
    const client = createMockStatsdClient();
    handle = startStatsdDualWrite({
      statsdClient: client as any,
      registry,
      intervalMs: 10_000,
    });

    await runCycles(1, 10_000);

    expect(statsdDualWriteRunsTotal.inc).toHaveBeenCalledWith({ outcome: 'ok' });
  });

  it('emits run outcome=error when getMetricsAsJSON throws', async () => {
    const brokenRegistry = {
      getMetricsAsJSON: () => {
        throw new Error('registry broken');
      },
    };

    const client = createMockStatsdClient();
    handle = startStatsdDualWrite({
      statsdClient: client as any,
      registry: brokenRegistry as any,
      intervalMs: 10_000,
    });

    await runCycles(1, 10_000);

    expect(statsdDualWriteRunsTotal.inc).toHaveBeenCalledWith({ outcome: 'error' });
    expect(statsdDualWriteErrorsTotal.inc).toHaveBeenCalledWith({
      reason: 'push_failed',
    });
  });

  it('sets metricsCount and observes duration', async () => {
    const client = createMockStatsdClient();
    handle = startStatsdDualWrite({
      statsdClient: client as any,
      registry,
      intervalMs: 10_000,
    });

    await runCycles(1, 10_000);

    expect(statsdDualWriteMetricsCount.set).toHaveBeenCalledWith(0);
    expect(statsdDualWriteDurationMs.observe).toHaveBeenCalledWith(
      expect.any(Number),
    );
  });

  it('stop() clears the timer and closes the client', async () => {
    const client = createMockStatsdClient();
    handle = startStatsdDualWrite({
      statsdClient: client as any,
      registry,
      intervalMs: 10_000,
    });

    // Run one cycle so we can verify the timer is running
    await runCycles(1, 10_000);
    expect(client.gauge).not.toHaveBeenCalled(); // no metrics in registry

    await handle.stop();

    // Run another cycle — should not fire because timer was cleared
    await runCycles(1, 10_000);

    expect(client.close).toHaveBeenCalled();
  });

  it('handles endpoint down by continuing to push on next cycle without crashing', async () => {
    const g = new Gauge({
      name: 'test_resilience',
      help: 'test',
      registers: [registry],
    });
    g.set(10);

    const client = createMockStatsdClient();
    (client.gauge as ReturnType<typeof vi.fn>).mockImplementationOnce(() => {
      throw new Error('ECONNREFUSED');
    });

    handle = startStatsdDualWrite({
      statsdClient: client as any,
      registry,
      intervalMs: 10_000,
    });

    // First cycle: gauge throws but the try/catch in StatsDClient swallows it
    await runCycles(1, 10_000);
    expect(client.gauge).toHaveBeenCalled();

    // Second cycle: client recovers, gauge works again
    vi.clearAllMocks();
    g.set(20);
    await runCycles(1, 10_000);
    expect(client.gauge).toHaveBeenCalledWith('test_resilience', 20, {});
  });

  it('recovers and emits positive delta after a counter reset cycle', async () => {
    const c = new Counter({
      name: 'test_recovery_counter',
      help: 'test',
      registers: [registry],
    });
    c.inc(100);

    const client = createMockStatsdClient();
    handle = startStatsdDualWrite({
      statsdClient: client as any,
      registry,
      intervalMs: 10_000,
    });

    // First cycle: emit 100
    await runCycles(1, 10_000);
    expect(client.increment).toHaveBeenCalledWith('test_recovery_counter', 100, {});

    // Simulate counter reset: unregister and re-register at 0
    vi.clearAllMocks();
    registry.removeSingleMetric('test_recovery_counter');
    const c2 = new Counter({
      name: 'test_recovery_counter',
      help: 'test',
      registers: [registry],
    });
    c2.inc(1);

    // Second cycle: old prev=100, new value=1, delta=-99 → skipped
    await runCycles(1, 10_000);
    // increment should not have been called for test_recovery_counter
    const counterCalls = (client.increment as ReturnType<typeof vi.fn>).mock.calls.filter(
      (call: [string]) => call[0] === 'test_recovery_counter',
    );
    expect(counterCalls).toHaveLength(0);

    // Third cycle: prev=1 (updated after second cycle), inc(3) → value=4, delta=3
    vi.clearAllMocks();
    c2.inc(3);
    await runCycles(1, 10_000);
    expect(client.increment).toHaveBeenCalledWith('test_recovery_counter', 3, {});
  });

  it('does not emit counter delta when value has not changed', async () => {
    const c = new Counter({
      name: 'test_static',
      help: 'test',
      registers: [registry],
    });

    const client = createMockStatsdClient();
    handle = startStatsdDualWrite({
      statsdClient: client as any,
      registry,
      intervalMs: 10_000,
    });

    // First cycle: counter is 0, no delta to emit
    await runCycles(1, 10_000);
    expect(client.increment).not.toHaveBeenCalled();

    // Second cycle: still 0, still no delta
    await runCycles(1, 10_000);
    expect(client.increment).not.toHaveBeenCalled();
  });

  it('handles empty registry gracefully', async () => {
    const client = createMockStatsdClient();
    handle = startStatsdDualWrite({
      statsdClient: client as any,
      registry,
      intervalMs: 10_000,
    });

    await runCycles(1, 10_000);

    // No metrics to push, but cycle succeeded
    expect(statsdDualWriteRunsTotal.inc).toHaveBeenCalledWith({ outcome: 'ok' });
    expect(statsdDualWriteMetricsCount.set).toHaveBeenCalledWith(0);
  });
});
