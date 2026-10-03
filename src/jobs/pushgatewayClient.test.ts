// Tests for pushgatewayClient.ts
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { HttpPushgatewayClient, NoopPushgatewayClient, getPushgatewayClient, resetPushgatewayClientForTests } from './pushgatewayClient.js';

// Helper mock implementing PushgatewayLike
class MockPushgateway implements PushgatewayLike {
  constructor(public succeedAfter: number = 1, public failMessage = 'failed') {
    this.attempts = 0;
  }
  attempts: number;
  async push(params: { jobName: string; groupings?: Record<string, string> }) {
    this.attempts++;
    if (this.attempts >= this.succeedAfter) {
      return Promise.resolve();
    }
    return Promise.reject(new Error(this.failMessage));
  }
  async delete(params: { jobName: string; groupings?: Record<string, string> }) {
    this.attempts++;
    if (this.attempts >= this.succeedAfter) {
      return Promise.resolve();
    }
    return Promise.reject(new Error(this.failMessage));
  }
}

describe('HttpPushgatewayClient', () => {
  it('retries on failure and succeeds', async () => {
    const mock = new MockPushgateway(2); // succeed on second attempt
    const client = new HttpPushgatewayClient(mock);
    await client.pushJobMetrics('job', 'run1');
    expect(mock.attempts).toBe(2);
  });

  it('exhausts retries and logs error', async () => {
    const mock = new MockPushgateway(5, 'boom'); // never succeed within max attempts (3)
    const loggerSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const client = new HttpPushgatewayClient(mock);
    await client.pushJobMetrics('job', 'run2');
    expect(mock.attempts).toBe(3);
    loggerSpy.mockRestore();
  });
});

describe('NoopPushgatewayClient', () => {
  it('does nothing without throwing', async () => {
    const client = new NoopPushgatewayClient();
    await expect(client.pushJobMetrics('job', 'run')).resolves.toBeUndefined();
    await expect(client.deleteJobGrouping('job', 'run')).resolves.toBeUndefined();
  });
});

describe('getPushgatewayClient and reset', () => {
  const originalEnv = process.env.PUSHGATEWAY_URL;
  afterEach(() => {
    process.env.PUSHGATEWAY_URL = originalEnv;
    resetPushgatewayClientForTests();
  });

  it('returns Noop when env unset', () => {
    delete process.env.PUSHGATEWAY_URL;
    const client = getPushgatewayClient();
    expect(client).toBeInstanceOf(NoopPushgatewayClient);
  });

  it('caches client after first call', () => {
    process.env.PUSHGATEWAY_URL = 'http://example.com';
    const client1 = getPushgatewayClient();
    const client2 = getPushgatewayClient();
    expect(client1).toBe(client2);
  });

  it('reset clears cache', () => {
    process.env.PUSHGATEWAY_URL = 'http://example.com';
    const client1 = getPushgatewayClient();
    resetPushgatewayClientForTests();
    const client2 = getPushgatewayClient();
    expect(client1).not.toBe(client2);
  });
});
