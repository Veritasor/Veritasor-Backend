import { describe, expect, it, vi } from 'vitest';
import { publishPactContract } from '../../src/utils/pactBroker.js';

describe('publishPactContract', () => {
  it('retries publishing when the broker is temporarily unreachable', async () => {
    const runner = vi.fn()
      .mockRejectedValueOnce(new Error('ECONNREFUSED'))
      .mockResolvedValueOnce({ stdout: '', stderr: '' });

    await expect(
      publishPactContract({
        pactFilePath: 'tests/pacts/Veritasor-Frontend-Veritasor-Backend.json',
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
        'tests/pacts/Veritasor-Frontend-Veritasor-Backend.json',
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

  it('retries multiple times before succeeding', async () => {
    const runner = vi.fn()
      .mockRejectedValueOnce(new Error('ECONNREFUSED'))
      .mockRejectedValueOnce(new Error('ETIMEDOUT'))
      .mockRejectedValueOnce(new Error('ECONNRESET'))
      .mockResolvedValueOnce({ stdout: '', stderr: '' });

    await expect(
      publishPactContract({
        pactFilePath: 'tests/pacts/Veritasor-Frontend-Veritasor-Backend.json',
        brokerBaseUrl: 'https://broker.example.test',
        consumerVersion: '1.2.3',
        consumerName: 'Veritasor-Frontend',
        providerName: 'Veritasor-Backend',
        retries: 4,
        retryDelayMs: 0,
        runner,
      }),
    ).resolves.toBeUndefined();

    expect(runner).toHaveBeenCalledTimes(4);
  });

  it('throws the last error after exhausting retries', async () => {
    const lastError = new Error('ETIMEDOUT');
    const runner = vi.fn()
      .mockRejectedValueOnce(new Error('ECONNREFUSED'))
      .mockRejectedValueOnce(new Error('ECONNRESET'))
      .mockRejectedValue(lastError);

    await expect(
      publishPactContract({
        pactFilePath: 'tests/pacts/Veritasor-Frontend-Veritasor-Backend.json',
        brokerBaseUrl: 'https://broker.example.test',
        consumerVersion: '1.2.3',
        consumerName: 'Veritasor-Frontend',
        providerName: 'Veritasor-Backend',
        retries: 3,
        retryDelayMs: 0,
        runner,
      }),
    ).rejects.toThrow('ETIMEDOUT');

    expect(runner).toHaveBeenCalledTimes(3);
  });

  it('includes --tag flag when tag is provided', async () => {
    const runner = vi.fn().mockResolvedValueOnce({ stdout: '', stderr: '' });

    await expect(
      publishPactContract({
        pactFilePath: 'tests/pacts/Veritasor-Frontend-Veritasor-Backend.json',
        brokerBaseUrl: 'https://broker.example.test',
        consumerVersion: '1.2.3',
        consumerName: 'Veritasor-Frontend',
        providerName: 'Veritasor-Backend',
        tag: 'main',
        retryDelayMs: 0,
        runner,
      }),
    ).resolves.toBeUndefined();

    const args = runner.mock.calls[0][1];
    expect(args).toContain('--tag');
    expect(args).toContain('main');
  });

  it('does not include --tag flag when tag is not provided', async () => {
    const runner = vi.fn().mockResolvedValueOnce({ stdout: '', stderr: '' });

    await expect(
      publishPactContract({
        pactFilePath: 'tests/pacts/Veritasor-Frontend-Veritasor-Backend.json',
        brokerBaseUrl: 'https://broker.example.test',
        consumerVersion: '1.2.3',
        consumerName: 'Veritasor-Frontend',
        providerName: 'Veritasor-Backend',
        retryDelayMs: 0,
        runner,
      }),
    ).resolves.toBeUndefined();

    const args = runner.mock.calls[0][1];
    expect(args).not.toContain('--tag');
  });

  it('sets PACT_BROKER_URL in runner environment', async () => {
    const runner = vi.fn().mockResolvedValueOnce({ stdout: '', stderr: '' });

    await expect(
      publishPactContract({
        pactFilePath: 'tests/pacts/Veritasor-Frontend-Veritasor-Backend.json',
        brokerBaseUrl: 'https://broker.example.test',
        consumerVersion: '1.2.3',
        consumerName: 'Veritasor-Frontend',
        providerName: 'Veritasor-Backend',
        retryDelayMs: 0,
        runner,
      }),
    ).resolves.toBeUndefined();

    const env = runner.mock.calls[0][2].env;
    expect(env).toHaveProperty('PACT_BROKER_URL', 'https://broker.example.test');
  });

  it('throws error when broker URL is missing', async () => {
    delete process.env.PACT_BROKER_URL;
    delete process.env.PACT_BROKER_BASE_URL;

    await expect(
      publishPactContract({
        pactFilePath: 'tests/pacts/Veritasor-Frontend-Veritasor-Backend.json',
        consumerVersion: '1.2.3',
        consumerName: 'Veritasor-Frontend',
        providerName: 'Veritasor-Backend',
        retryDelayMs: 0,
      }),
    ).rejects.toThrow(/PACT_BROKER_URL/);
  });
});
