import { beforeEach, describe, expect, it, vi } from 'vitest';
import { logger } from '../../../src/utils/logger.js';
import { runInstrumentedJob, type JobOutcome } from '../../../src/jobs/jobRunner.js';

/**
 * `jobRunner` labels each metric with the job name and then calls an
 * observe/inc/set on the returned child. Give every metric its own handle so
 * assertions can tell the four metrics apart.
 */
const metrics = vi.hoisted(() => {
  const make = () => {
    const handle = { observe: vi.fn(), inc: vi.fn(), set: vi.fn() };
    const metric = { labels: vi.fn(() => handle) };
    return { metric, handle };
  };
  return {
    duration: make(),
    runs: make(),
    items: make(),
    lastRun: make(),
  };
});

const pushgateway = vi.hoisted(() => ({
  pushJobMetrics: vi.fn(async () => {}),
  deleteJobGrouping: vi.fn(async () => {}),
}));

vi.mock('../../../src/utils/logger', () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));

vi.mock('../../../src/metrics', () => ({
  jobDurationSeconds: metrics.duration.metric,
  jobRunsTotal: metrics.runs.metric,
  jobItemsProcessedTotal: metrics.items.metric,
  jobLastRunTimestamp: metrics.lastRun.metric,
}));

vi.mock('../../../src/jobs/pushgatewayClient', () => ({
  getPushgatewayClient: () => pushgateway,
}));

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

beforeEach(() => {
  vi.clearAllMocks();
});

describe('runInstrumentedJob — outcome contract', () => {
  it('returns the outcome reported by the job unchanged', async () => {
    const outcome: JobOutcome = { itemsProcessed: 7, success: true };

    const result = await runInstrumentedJob('attestation_drainer', async () => outcome);

    expect(result).toEqual({ itemsProcessed: 7, success: true });
  });

  it('preserves a zero-item successful run (nothing was due)', async () => {
    const result = await runInstrumentedJob('audit_anchor', async () => ({
      itemsProcessed: 0,
      success: true,
    }));

    expect(result).toEqual({ itemsProcessed: 0, success: true });
  });

  it('preserves a failure the job reported itself, including its item count', async () => {
    const result = await runInstrumentedJob('purge_cdn', async () => ({
      itemsProcessed: 3,
      success: false,
    }));

    expect(result).toEqual({ itemsProcessed: 3, success: false });
  });

  it('calls the job exactly once per invocation', async () => {
    const fn = vi.fn(async () => ({ itemsProcessed: 1, success: true }));

    await runInstrumentedJob('once_job', fn);

    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('does not mutate the outcome object returned by the job', async () => {
    const outcome: JobOutcome = { itemsProcessed: 2, success: true };

    await runInstrumentedJob('immutable_job', async () => outcome);

    expect(outcome).toEqual({ itemsProcessed: 2, success: true });
  });
});

describe('runInstrumentedJob — thrown errors are contained', () => {
  it('converts a thrown Error into a failed, zero-item outcome instead of rejecting', async () => {
    const boom = new Error('database unavailable');

    await expect(
      runInstrumentedJob('exploding_job', async () => {
        throw boom;
      }),
    ).resolves.toEqual({ itemsProcessed: 0, success: false });
  });

  it('logs the unhandled error with the job name and the original error', async () => {
    const boom = new Error('connection reset');

    await runInstrumentedJob('logged_job', async () => {
      throw boom;
    });

    expect(logger.error).toHaveBeenCalledTimes(1);
    const [message, logged] = vi.mocked(logger.error).mock.calls[0];
    expect(String(message)).toContain('logged_job');
    expect(logged).toBe(boom);
  });

  it('tolerates a non-Error throwable without rejecting', async () => {
    await expect(
      runInstrumentedJob('string_thrower', async () => {
        // eslint-disable-next-line no-throw-literal
        throw 'not an error object';
      }),
    ).resolves.toEqual({ itemsProcessed: 0, success: false });

    expect(logger.error).toHaveBeenCalledTimes(1);
  });

  it('does not log an error when the job reports success', async () => {
    await runInstrumentedJob('quiet_job', async () => ({ itemsProcessed: 1, success: true }));

    expect(logger.error).not.toHaveBeenCalled();
  });
});

describe('runInstrumentedJob — metric recording', () => {
  it('observes a non-negative duration for the job label', async () => {
    await runInstrumentedJob('timed_job', async () => ({ itemsProcessed: 0, success: true }));

    expect(metrics.duration.metric.labels).toHaveBeenCalledWith('timed_job');
    expect(metrics.duration.handle.observe).toHaveBeenCalledTimes(1);
    const observed = metrics.duration.handle.observe.mock.calls[0][0];
    expect(typeof observed).toBe('number');
    expect(observed).toBeGreaterThanOrEqual(0);
  });

  it('counts a successful run under outcome="success"', async () => {
    await runInstrumentedJob('ok_job', async () => ({ itemsProcessed: 0, success: true }));

    expect(metrics.runs.metric.labels).toHaveBeenCalledWith('ok_job', 'success');
    expect(metrics.runs.handle.inc).toHaveBeenCalledTimes(1);
  });

  it('counts a failed run under outcome="failure"', async () => {
    await runInstrumentedJob('bad_job', async () => {
      throw new Error('boom');
    });

    expect(metrics.runs.metric.labels).toHaveBeenCalledWith('bad_job', 'failure');
    expect(metrics.runs.handle.inc).toHaveBeenCalledTimes(1);
  });

  it('increments the item counter by the number the job reported', async () => {
    await runInstrumentedJob('items_job', async () => ({ itemsProcessed: 42, success: true }));

    expect(metrics.items.metric.labels).toHaveBeenCalledWith('items_job');
    expect(metrics.items.handle.inc).toHaveBeenCalledWith(42);
  });

  it('still increments the item counter by 0 for a zero-item run', async () => {
    await runInstrumentedJob('empty_job', async () => ({ itemsProcessed: 0, success: true }));

    expect(metrics.items.handle.inc).toHaveBeenCalledWith(0);
  });

  it('increments the item counter by 0 when the job throws', async () => {
    await runInstrumentedJob('throwing_items_job', async () => {
      throw new Error('boom');
    });

    expect(metrics.items.handle.inc).toHaveBeenCalledWith(0);
  });

  it('sets the last-run timestamp in unix seconds', async () => {
    const before = Date.now() / 1000;

    await runInstrumentedJob('stamped_job', async () => ({ itemsProcessed: 0, success: true }));

    const after = Date.now() / 1000;
    expect(metrics.lastRun.metric.labels).toHaveBeenCalledWith('stamped_job');
    const stamp = metrics.lastRun.handle.set.mock.calls[0][0];
    expect(stamp).toBeGreaterThanOrEqual(before);
    expect(stamp).toBeLessThanOrEqual(after);
  });

  it('labels every metric with the exact job name it was given', async () => {
    await runInstrumentedJob('weird/job name:1', async () => ({ itemsProcessed: 1, success: true }));

    expect(metrics.duration.metric.labels).toHaveBeenCalledWith('weird/job name:1');
    expect(metrics.runs.metric.labels).toHaveBeenCalledWith('weird/job name:1', 'success');
    expect(metrics.items.metric.labels).toHaveBeenCalledWith('weird/job name:1');
    expect(metrics.lastRun.metric.labels).toHaveBeenCalledWith('weird/job name:1');
  });
});

describe('runInstrumentedJob — Pushgateway lifecycle', () => {
  it('pushes a per-run grouping and deletes it once the run succeeded', async () => {
    await runInstrumentedJob('push_ok_job', async () => ({ itemsProcessed: 1, success: true }));

    expect(pushgateway.pushJobMetrics).toHaveBeenCalledTimes(1);
    expect(pushgateway.deleteJobGrouping).toHaveBeenCalledTimes(1);

    const [jobName, runId] = pushgateway.pushJobMetrics.mock.calls[0];
    expect(jobName).toBe('push_ok_job');
    expect(runId).toMatch(UUID_V4);
    expect(pushgateway.deleteJobGrouping.mock.calls[0][0]).toBe('push_ok_job');
    // push and delete must refer to the same grouping.
    expect(pushgateway.deleteJobGrouping.mock.calls[0][1]).toBe(runId);
  });

  it('leaves a failed run’s grouping in place for operator visibility', async () => {
    await runInstrumentedJob('push_fail_job', async () => ({ itemsProcessed: 0, success: false }));

    expect(pushgateway.pushJobMetrics).toHaveBeenCalledTimes(1);
    expect(pushgateway.deleteJobGrouping).not.toHaveBeenCalled();
  });

  it('leaves the grouping in place when the job throws', async () => {
    await runInstrumentedJob('push_throw_job', async () => {
      throw new Error('boom');
    });

    expect(pushgateway.pushJobMetrics).toHaveBeenCalledTimes(1);
    expect(pushgateway.deleteJobGrouping).not.toHaveBeenCalled();
  });

  it('uses a fresh run id for every invocation of the same job', async () => {
    await runInstrumentedJob('same_job', async () => ({ itemsProcessed: 0, success: true }));
    await runInstrumentedJob('same_job', async () => ({ itemsProcessed: 0, success: true }));

    const first = pushgateway.pushJobMetrics.mock.calls[0][1];
    const second = pushgateway.pushJobMetrics.mock.calls[1][1];
    expect(first).not.toBe(second);
    expect(first).toMatch(UUID_V4);
    expect(second).toMatch(UUID_V4);
  });

  it('awaits the push before resolving, so metrics are flushed before the caller continues', async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    pushgateway.pushJobMetrics.mockImplementationOnce(async () => {
      await gate;
    });

    let settled = false;
    const run = runInstrumentedJob('gated_job', async () => ({
      itemsProcessed: 0,
      success: true,
    })).then(() => {
      settled = true;
    });

    await Promise.resolve();
    await Promise.resolve();
    expect(settled).toBe(false);

    release();
    await run;
    expect(settled).toBe(true);
  });
});
