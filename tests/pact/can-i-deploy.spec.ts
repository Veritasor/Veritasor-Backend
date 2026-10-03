import { describe, expect, it, vi } from 'vitest';
import { canIDeploy } from '../../src/utils/pactCanIDeploy.js';

describe('canIDeploy', () => {
  it('retries can-i-deploy when the broker returns a transient error', async () => {
    const runner = vi.fn()
      .mockRejectedValueOnce(new Error('ECONNRESET'))
      .mockResolvedValueOnce({ stdout: '', stderr: '' });

    await expect(
      canIDeploy({
        consumerName: 'Veritasor-Frontend',
        providerName: 'Veritasor-Backend',
        consumerVersion: '1.2.3',
        brokerBaseUrl: 'https://broker.example.test',
        retries: 2,
        retryDelayMs: 0,
        runner,
      }),
    ).resolves.toBeUndefined();

    expect(runner).toHaveBeenCalledTimes(2);
    expect(runner).toHaveBeenNthCalledWith(
      1,
      'npx',
      [
        '-y',
        'pact-broker',
        'can-i-deploy',
        '--pacticipant',
        'Veritasor-Frontend',
        '--version',
        '1.2.3',
        '--to',
        'Veritasor-Backend',
        '--broker-base-url',
        'https://broker.example.test',
      ],
      expect.objectContaining({ env: expect.any(Object) }),
    );
  });
});
