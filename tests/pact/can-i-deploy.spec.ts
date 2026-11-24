import { afterEach, describe, expect, it, vi } from 'vitest';
import { canIDeploy } from '../../src/utils/pactCanIDeploy.js';

afterEach(() => {
  vi.unstubAllEnvs();
});

describe('canIDeploy', () => {
  const options = {
    consumerName: 'Veritasor-Frontend',
    providerName: 'Veritasor-Backend',
    consumerVersion: '1.2.3',
    brokerBaseUrl: 'https://broker.example.test',
  };

  it('resolves when the Pact Broker reports that the version is deployable', async () => {
    const runner = vi.fn().mockResolvedValue({ stdout: '', stderr: '' });

    await expect(canIDeploy({ ...options, runner })).resolves.toBeUndefined();

    expect(runner).toHaveBeenCalledOnce();
    expect(runner).toHaveBeenCalledWith(
      'npx',
      [
        '-y',
        'pact-broker',
        'can-i-deploy',
        '--pacticipant',
        options.consumerName,
        '--version',
        options.consumerVersion,
        '--to',
        options.providerName,
        '--broker-base-url',
        options.brokerBaseUrl,
      ],
      expect.objectContaining({
        env: expect.objectContaining({
          PACT_BROKER_URL: options.brokerBaseUrl,
        }),
      }),
    );
  });

  it('rejects with the Pact CLI error when the version is not deployable', async () => {
    const notDeployable = Object.assign(
      new Error('The pacticipant version is not deployable'),
      { code: 1 },
    );
    const runner = vi.fn().mockRejectedValue(notDeployable);

    await expect(
      canIDeploy({ ...options, retries: 1, runner }),
    ).rejects.toBe(notDeployable);

    expect(runner).toHaveBeenCalledOnce();
  });

  it('retries runner failures and rejects with the final error', async () => {
    const firstFailure = Object.assign(new Error('ECONNRESET'), { code: 'ECONNRESET' });
    const finalFailure = Object.assign(new Error('spawn npx ENOENT'), { code: 'ENOENT' });
    const runner = vi.fn()
      .mockRejectedValueOnce(firstFailure)
      .mockRejectedValueOnce(finalFailure);

    await expect(
      canIDeploy({
        ...options,
        retries: 2,
        retryDelayMs: 0,
        runner,
      }),
    ).rejects.toBe(finalFailure);

    expect(runner).toHaveBeenCalledTimes(2);
  });

  it('rejects when the Pact Broker URL is missing without invoking the runner', async () => {
    vi.stubEnv('PACT_BROKER_URL', '');
    vi.stubEnv('PACT_BROKER_BASE_URL', '');
    const runner = vi.fn();

    await expect(
      canIDeploy({
        consumerName: options.consumerName,
        providerName: options.providerName,
        consumerVersion: options.consumerVersion,
        retries: 1,
        runner,
      }),
    ).rejects.toThrow('PACT_BROKER_URL is required to run can-i-deploy');

    expect(runner).not.toHaveBeenCalled();
  });
});
