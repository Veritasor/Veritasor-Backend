import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  HttpPushgatewayClient,
  getPushgatewayClient,
  resetPushgatewayClientForTests,
  type PushgatewayLike,
} from '../../../src/jobs/pushgatewayClient.js';
import { logger } from '../../../src/utils/logger.js';

vi.mock('../../../src/utils/logger', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

function fakeGateway(overrides: Partial<PushgatewayLike> = {}): PushgatewayLike {
  return {
    push: vi.fn(async () => ({})),
    delete: vi.fn(async () => ({})),
    ...overrides,
  };
}

describe('HttpPushgatewayClient', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('pushes metrics grouped by job name and run id', async () => {
    const gateway = fakeGateway();
    const client = new HttpPushgatewayClient(gateway);

    await client.pushJobMetrics('attestation_reminder', 'run-1');

    expect(gateway.push).toHaveBeenCalledWith({
      jobName: 'attestation_reminder',
      groupings: { run_id: 'run-1' },
    });
  });

  it('deletes a grouping by job name and run id', async () => {
    const gateway = fakeGateway();
    const client = new HttpPushgatewayClient(gateway);

    await client.deleteJobGrouping('attestation_reminder', 'run-1');

    expect(gateway.delete).toHaveBeenCalledWith({
      jobName: 'attestation_reminder',
      groupings: { run_id: 'run-1' },
    });
  });

  it('retries push when the Pushgateway is unreachable, then succeeds', async () => {
    const push = vi
      .fn()
      .mockRejectedValueOnce(new Error('ECONNREFUSED'))
      .mockRejectedValueOnce(new Error('ECONNREFUSED'))
      .mockResolvedValueOnce({});
    const client = new HttpPushgatewayClient(fakeGateway({ push }));

    await client.pushJobMetrics('job', 'run-1');

    expect(push).toHaveBeenCalledTimes(3);
    expect(logger.warn).toHaveBeenCalledTimes(2);
  });

  it('gives up after the max retry attempts and logs, without throwing', async () => {
    const push = vi.fn().mockRejectedValue(new Error('ECONNREFUSED'));
    const client = new HttpPushgatewayClient(fakeGateway({ push }));

    await expect(client.pushJobMetrics('job', 'run-1')).resolves.toBeUndefined();

    expect(push).toHaveBeenCalledTimes(3);
    expect(logger.error).toHaveBeenCalledTimes(1);
  });

  it('never throws out of deleteJobGrouping when the Pushgateway is unreachable', async () => {
    const del = vi.fn().mockRejectedValue(new Error('ECONNREFUSED'));
    const client = new HttpPushgatewayClient(fakeGateway({ delete: del }));

    await expect(client.deleteJobGrouping('job', 'run-1')).resolves.toBeUndefined();
    expect(del).toHaveBeenCalledTimes(3);
  });
});

describe('getPushgatewayClient', () => {
  const ORIGINAL_URL = process.env.PUSHGATEWAY_URL;

  beforeEach(() => {
    resetPushgatewayClientForTests();
  });

  afterEach(() => {
    if (ORIGINAL_URL === undefined) {
      delete process.env.PUSHGATEWAY_URL;
    } else {
      process.env.PUSHGATEWAY_URL = ORIGINAL_URL;
    }
    resetPushgatewayClientForTests();
  });

  it('returns a no-op client when PUSHGATEWAY_URL is unset', async () => {
    delete process.env.PUSHGATEWAY_URL;
    const client = getPushgatewayClient();
    // Should resolve cleanly without attempting any network call.
    await expect(client.pushJobMetrics('job', 'run-1')).resolves.toBeUndefined();
    await expect(client.deleteJobGrouping('job', 'run-1')).resolves.toBeUndefined();
  });

  it('caches the client across calls', () => {
    delete process.env.PUSHGATEWAY_URL;
    const first = getPushgatewayClient();
    const second = getPushgatewayClient();
    expect(first).toBe(second);
  });

  it('builds an HttpPushgatewayClient when PUSHGATEWAY_URL is set', () => {
    process.env.PUSHGATEWAY_URL = 'http://localhost:9091';
    const client = getPushgatewayClient();
    expect(client).toBeInstanceOf(HttpPushgatewayClient);
  });
});
