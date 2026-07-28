import { beforeEach, describe, expect, it, vi } from 'vitest';
import { runInstrumentedJob } from '../../../src/jobs/jobRunner.js';
import * as pushgatewayClientModule from '../../../src/jobs/pushgatewayClient.js';
import {
  jobDurationSeconds,
  jobItemsProcessedTotal,
  jobRunsTotal,
} from '../../../src/metrics.js';

vi.mock('../../../src/utils/logger', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

function fakePushgatewayClient() {
  return {
    pushJobMetrics: vi.fn(async () => {}),
    deleteJobGrouping: vi.fn(async () => {}),
  };
}

describe('runInstrumentedJob', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    jobDurationSeconds.reset();
    jobRunsTotal.reset();
    jobItemsProcessedTotal.reset();
  });

  it('pushes metrics and deletes the grouping on success', async () => {
    const client = fakePushgatewayClient();
    vi.spyOn(pushgatewayClientModule, 'getPushgatewayClient').mockReturnValue(client);

    const outcome = await runInstrumentedJob('test_job', async () => ({
      itemsProcessed: 3,
      success: true,
    }));

    expect(outcome).toEqual({ itemsProcessed: 3, success: true });
    expect(client.pushJobMetrics).toHaveBeenCalledTimes(1);
    expect(client.pushJobMetrics).toHaveBeenCalledWith('test_job', expect.any(String));
    expect(client.deleteJobGrouping).toHaveBeenCalledTimes(1);
    expect(client.deleteJobGrouping).toHaveBeenCalledWith('test_job', expect.any(String));

    // The same run id is used for both calls.
    const pushRunId = client.pushJobMetrics.mock.calls[0][1];
    const deleteRunId = client.deleteJobGrouping.mock.calls[0][1];
    expect(pushRunId).toBe(deleteRunId);
  });

  it('pushes metrics but does not delete the grouping when the job fails', async () => {
    const client = fakePushgatewayClient();
    vi.spyOn(pushgatewayClientModule, 'getPushgatewayClient').mockReturnValue(client);

    const outcome = await runInstrumentedJob('test_job', async () => ({
      itemsProcessed: 0,
      success: false,
    }));

    expect(outcome).toEqual({ itemsProcessed: 0, success: false });
    expect(client.pushJobMetrics).toHaveBeenCalledTimes(1);
    expect(client.deleteJobGrouping).not.toHaveBeenCalled();
  });

  it('treats an unhandled throw from the job function as a failed run', async () => {
    const client = fakePushgatewayClient();
    vi.spyOn(pushgatewayClientModule, 'getPushgatewayClient').mockReturnValue(client);

    const outcome = await runInstrumentedJob('test_job', async () => {
      throw new Error('boom');
    });

    expect(outcome).toEqual({ itemsProcessed: 0, success: false });
    expect(client.deleteJobGrouping).not.toHaveBeenCalled();
  });

  it('records duration, outcome, and item-count metrics', async () => {
    const client = fakePushgatewayClient();
    vi.spyOn(pushgatewayClientModule, 'getPushgatewayClient').mockReturnValue(client);

    await runInstrumentedJob('metric_job', async () => ({ itemsProcessed: 5, success: true }));

    const runsMetric = await jobRunsTotal.get();
    const successSample = runsMetric.values.find(
      (v) => v.labels.job === 'metric_job' && v.labels.outcome === 'success',
    );
    expect(successSample?.value).toBe(1);

    const itemsMetric = await jobItemsProcessedTotal.get();
    const itemsSample = itemsMetric.values.find((v) => v.labels.job === 'metric_job');
    expect(itemsSample?.value).toBe(5);

    const durationMetric = await jobDurationSeconds.get();
    const durationSample = durationMetric.values.find(
      (v) => v.labels.job === 'metric_job' && v.metricName?.endsWith('_count'),
    );
    expect(durationSample?.value).toBe(1);
  });
});
