import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { ExecFileOptions } from 'node:child_process';
import { createSecretLoader } from './secret-loader.js';

const execFileAsync = promisify(execFile);

export interface PublishPactContractOptions {
  pactFilePath: string;
  consumerName: string;
  providerName: string;
  consumerVersion: string;
  brokerBaseUrl?: string;
  tag?: string;
  retries?: number;
  retryDelayMs?: number;
  runner?: CommandRunner;
}

export type CommandRunner = (
  command: string,
  args: string[],
  options: ExecFileOptions,
) => Promise<{ stdout: string; stderr: string }>;

export async function publishPactContract(options: PublishPactContractOptions): Promise<void> {
  const brokerBaseUrl = options.brokerBaseUrl ?? (await resolveBrokerBaseUrl());
  const retries = options.retries ?? 3;
  const retryDelayMs = options.retryDelayMs ?? 3000;
  const runner = options.runner ?? defaultRunner;
  const args = buildPublishArgs(options, brokerBaseUrl);

  let lastError: unknown;
  for (let attempt = 1; attempt <= retries; attempt += 1) {
    try {
      await runner('npx', args, {
        env: {
          ...process.env,
          PACT_BROKER_URL: brokerBaseUrl,
        },
      });
      return;
    } catch (error) {
      lastError = error;
      if (attempt >= retries) {
        throw error;
      }
      if (retryDelayMs > 0) {
        await delay(retryDelayMs);
      }
    }
  }

  throw lastError instanceof Error ? lastError : new Error(String(lastError));
}

function buildPublishArgs(options: PublishPactContractOptions, brokerBaseUrl: string): string[] {
  const args = [
    '-y',
    'pact-broker',
    'publish',
    options.pactFilePath,
    '--consumer-app-name',
    options.consumerName,
    '--provider-app-name',
    options.providerName,
    '--broker-base-url',
    brokerBaseUrl,
    '--consumer-app-version',
    options.consumerVersion,
  ];

  if (options.tag) {
    args.push('--tag', options.tag);
  }

  return args;
}

async function resolveBrokerBaseUrl(): Promise<string> {
  const loader = createSecretLoader();
  await loader.reload();

  const brokerBaseUrl = process.env.PACT_BROKER_URL ?? process.env.PACT_BROKER_BASE_URL;
  if (brokerBaseUrl && brokerBaseUrl.trim()) {
    return brokerBaseUrl.trim();
  }

  const loadedUrl = await loader.get('PACT_BROKER_URL');
  if (loadedUrl && loadedUrl.trim()) {
    return loadedUrl.trim();
  }

  throw new Error('PACT_BROKER_URL is required to publish Pact contracts');
}

async function defaultRunner(command: string, args: string[], options: ExecFileOptions): Promise<{ stdout: string; stderr: string }> {
  return execFileAsync(command, args, options);
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}
