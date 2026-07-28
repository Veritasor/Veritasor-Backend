import { describe, expect, it, vi } from 'vitest';
import { publishPactContract } from '../../src/utils/pactBroker.js';

describe('publishPactContract', () => {
  it('retries publishing when the broker is temporarily unreachable', async () => {
    const runner = vi.fn()
      .mockRejectedValueOnce(new Error('ECONNREFUSED'))
      .mockResolvedValueOnce({ stdout: '', stderr: '' });

    await expect(
      publishPactContract({
        pactFilePath: 'tests/pacts/frontend-backend.json',
        brokerBaseUrl: 'https://broker.example.test',
        consumerVersion: '1.2.3',
        consumerName: 'Veritasor-Frontend',
        providerName: 'Veritasor-Backend',
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
        'publish',
        'tests/pacts/frontend-backend.json',
        '--consumer-app-name',
        'Veritasor-Frontend',
        '--provider-app-name',
        'Veritasor-Backend',
        '--broker-base-url',
        'https://broker.example.test',
        '--consumer-app-version',
        '1.2.3',
      ],
      expect.objectContaining({ env: expect.any(Object) }),
    );
  });
});
