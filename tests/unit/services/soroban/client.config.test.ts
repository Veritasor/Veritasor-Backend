/**
 * Focused regression coverage for SorobanClientConfig failure handling.
 *
 * The config surface (`getSorobanConfig`) and the retry-policy parser
 * (`getSorobanRetryPolicy`) are the only public entry points to the
 * environment parsing helpers in `src/services/soroban/client.ts`. These
 * tests pin the exact failure contract so a silent change to a thrown
 * message or bound cannot regress unnoticed.
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { Networks } from '@stellar/stellar-sdk';
import {
  getSorobanConfig,
  getSorobanRetryPolicy,
} from '../../../../src/services/soroban/client.js';

const VALID_CONTRACT_ID =
  'CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM';

const SOROBAN_ENV_KEYS = [
  'SOROBAN_RPC_URL',
  'SOROBAN_CONTRACT_ID',
  'SOROBAN_NETWORK_PASSPHRASE',
  'SOROBAN_RPC_TIMEOUT_MS',
  'SOROBAN_RPC_MAX_RETRIES',
  'SOROBAN_BACKOFF_BASE_MS',
  'SOROBAN_RPC_RETRY_BASE_DELAY_MS',
  'SOROBAN_BACKOFF_MAX_MS',
  'SOROBAN_RPC_RETRY_MAX_DELAY_MS',
  'SOROBAN_RPC_RETRY_JITTER_RATIO',
  'SOROBAN_RPC_CIRCUIT_BREAKER_THRESHOLD',
  'SOROBAN_RPC_CIRCUIT_BREAKER_RESET_MS',
] as const;

const savedEnv: Record<string, string | undefined> = {};

beforeEach(() => {
  for (const key of SOROBAN_ENV_KEYS) {
    savedEnv[key] = process.env[key];
    delete process.env[key];
  }
});

afterEach(() => {
  for (const key of SOROBAN_ENV_KEYS) {
    const original = savedEnv[key];
    if (original === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = original;
    }
  }
});

describe('getSorobanConfig — required configuration failures', () => {
  it('throws a deterministic error when SOROBAN_CONTRACT_ID is unset', () => {
    expect(() => getSorobanConfig()).toThrow(
      'Missing required environment variable: SOROBAN_CONTRACT_ID',
    );
  });

  it('treats an empty SOROBAN_CONTRACT_ID as missing', () => {
    process.env.SOROBAN_CONTRACT_ID = '';

    expect(() => getSorobanConfig()).toThrow(
      'Missing required environment variable: SOROBAN_CONTRACT_ID',
    );
  });

  it('rejects a malformed contract id after the presence check', () => {
    process.env.SOROBAN_CONTRACT_ID = 'not-a-contract';

    expect(() => getSorobanConfig()).toThrow(
      'Invalid SOROBAN_CONTRACT_ID. Expected a valid Stellar contract address (C...).',
    );
  });

  it('rejects a Stellar account id (G...) used where a contract id is required', () => {
    process.env.SOROBAN_CONTRACT_ID = `G${'A'.repeat(55)}`;

    expect(() => getSorobanConfig()).toThrow(/Invalid SOROBAN_CONTRACT_ID/);
  });

  it('does not throw once a valid contract id is present', () => {
    process.env.SOROBAN_CONTRACT_ID = VALID_CONTRACT_ID;

    expect(() => getSorobanConfig()).not.toThrow();
  });
});

describe('getSorobanConfig — defaults and overrides', () => {
  beforeEach(() => {
    process.env.SOROBAN_CONTRACT_ID = VALID_CONTRACT_ID;
  });

  it('falls back to the public testnet defaults', () => {
    const config = getSorobanConfig();

    expect(config).toEqual({
      rpcUrl: 'https://soroban-testnet.stellar.org',
      contractId: VALID_CONTRACT_ID,
      networkPassphrase: Networks.TESTNET,
    });
  });

  it('honours explicit rpc url and network passphrase overrides', () => {
    process.env.SOROBAN_RPC_URL = 'https://rpc.example.test';
    process.env.SOROBAN_NETWORK_PASSPHRASE = Networks.PUBLIC;

    const config = getSorobanConfig();

    expect(config.rpcUrl).toBe('https://rpc.example.test');
    expect(config.networkPassphrase).toBe(Networks.PUBLIC);
  });

  it('treats an empty rpc url as an explicit (if unsafe) value rather than a default', () => {
    process.env.SOROBAN_RPC_URL = '';

    expect(getSorobanConfig().rpcUrl).toBe('');
  });
});

describe('getSorobanRetryPolicy — defaults and environment parsing', () => {
  it('returns the documented default policy when no env is set', () => {
    expect(getSorobanRetryPolicy()).toEqual({
      timeoutMs: 5_000,
      maxRetries: 2,
      retryBaseDelayMs: 200,
      retryMaxDelayMs: 1_500,
      retryJitterRatio: 0.2,
      circuitBreakerThreshold: 5,
      circuitBreakerResetMs: 30_000,
    });
  });

  it('reads every override from the environment', () => {
    process.env.SOROBAN_RPC_TIMEOUT_MS = '1234';
    process.env.SOROBAN_RPC_MAX_RETRIES = '3';
    process.env.SOROBAN_BACKOFF_BASE_MS = '50';
    process.env.SOROBAN_BACKOFF_MAX_MS = '5000';
    process.env.SOROBAN_RPC_RETRY_JITTER_RATIO = '0.5';
    process.env.SOROBAN_RPC_CIRCUIT_BREAKER_THRESHOLD = '2';
    process.env.SOROBAN_RPC_CIRCUIT_BREAKER_RESET_MS = '2000';

    expect(getSorobanRetryPolicy()).toEqual({
      timeoutMs: 1234,
      maxRetries: 3,
      retryBaseDelayMs: 50,
      retryMaxDelayMs: 5000,
      retryJitterRatio: 0.5,
      circuitBreakerThreshold: 2,
      circuitBreakerResetMs: 2000,
    });
  });

  it('allows per-call overrides to win over the environment', () => {
    process.env.SOROBAN_RPC_MAX_RETRIES = '3';

    expect(getSorobanRetryPolicy({ maxRetries: 1 }).maxRetries).toBe(1);
  });

  it('falls back to the legacy RPC_RETRY_* names when the BACKOFF_* names are unset', () => {
    process.env.SOROBAN_RPC_RETRY_BASE_DELAY_MS = '300';
    process.env.SOROBAN_RPC_RETRY_MAX_DELAY_MS = '900';

    const policy = getSorobanRetryPolicy();

    expect(policy.retryBaseDelayMs).toBe(300);
    expect(policy.retryMaxDelayMs).toBe(900);
  });

  it('prefers the BACKOFF_* names over the legacy RPC_RETRY_* names', () => {
    process.env.SOROBAN_BACKOFF_BASE_MS = '100';
    process.env.SOROBAN_RPC_RETRY_BASE_DELAY_MS = '300';
    process.env.SOROBAN_BACKOFF_MAX_MS = '400';
    process.env.SOROBAN_RPC_RETRY_MAX_DELAY_MS = '900';

    const policy = getSorobanRetryPolicy();

    expect(policy.retryBaseDelayMs).toBe(100);
    expect(policy.retryMaxDelayMs).toBe(400);
  });
});

describe('getSorobanRetryPolicy — invalid input failures', () => {
  it('rejects a non-integer timeout', () => {
    process.env.SOROBAN_RPC_TIMEOUT_MS = 'abc';

    expect(() => getSorobanRetryPolicy()).toThrow(
      'Invalid SOROBAN_RPC_TIMEOUT_MS. Expected an integer between 100 and 60000.',
    );
  });

  it('rejects a fractional integer field', () => {
    process.env.SOROBAN_RPC_MAX_RETRIES = '1.5';

    expect(() => getSorobanRetryPolicy()).toThrow(/Invalid SOROBAN_RPC_MAX_RETRIES/);
  });

  it('rejects a timeout below the lower bound', () => {
    process.env.SOROBAN_RPC_TIMEOUT_MS = '99';

    expect(() => getSorobanRetryPolicy()).toThrow(
      'Invalid SOROBAN_RPC_TIMEOUT_MS. Expected an integer between 100 and 60000.',
    );
  });

  it('rejects a timeout above the upper bound', () => {
    process.env.SOROBAN_RPC_TIMEOUT_MS = '60001';

    expect(() => getSorobanRetryPolicy()).toThrow(
      'Invalid SOROBAN_RPC_TIMEOUT_MS. Expected an integer between 100 and 60000.',
    );
  });

  it('accepts the exact timeout bounds', () => {
    process.env.SOROBAN_RPC_TIMEOUT_MS = '100';
    expect(getSorobanRetryPolicy().timeoutMs).toBe(100);

    process.env.SOROBAN_RPC_TIMEOUT_MS = '60000';
    expect(getSorobanRetryPolicy().timeoutMs).toBe(60_000);
  });

  it('rejects maxRetries above the hard cap of 5', () => {
    process.env.SOROBAN_RPC_MAX_RETRIES = '6';

    expect(() => getSorobanRetryPolicy()).toThrow(
      'Invalid SOROBAN_RPC_MAX_RETRIES. Expected an integer between 0 and 5.',
    );
  });

  it('accepts maxRetries of 0 (retries disabled)', () => {
    process.env.SOROBAN_RPC_MAX_RETRIES = '0';

    expect(getSorobanRetryPolicy().maxRetries).toBe(0);
  });

  it('rejects a jitter ratio above 1', () => {
    process.env.SOROBAN_RPC_RETRY_JITTER_RATIO = '2';

    expect(() => getSorobanRetryPolicy()).toThrow(
      'Invalid SOROBAN_RPC_RETRY_JITTER_RATIO. Expected a number between 0 and 1.',
    );
  });

  it('rejects a negative jitter ratio', () => {
    process.env.SOROBAN_RPC_RETRY_JITTER_RATIO = '-0.1';

    expect(() => getSorobanRetryPolicy()).toThrow(/Invalid SOROBAN_RPC_RETRY_JITTER_RATIO/);
  });

  it('rejects a non-numeric jitter ratio', () => {
    process.env.SOROBAN_RPC_RETRY_JITTER_RATIO = 'NaN';

    expect(() => getSorobanRetryPolicy()).toThrow(/Invalid SOROBAN_RPC_RETRY_JITTER_RATIO/);
  });

  it('accepts the jitter ratio bounds', () => {
    process.env.SOROBAN_RPC_RETRY_JITTER_RATIO = '0';
    expect(getSorobanRetryPolicy().retryJitterRatio).toBe(0);

    process.env.SOROBAN_RPC_RETRY_JITTER_RATIO = '1';
    expect(getSorobanRetryPolicy().retryJitterRatio).toBe(1);
  });

  it('rejects a circuit-breaker threshold outside its bounds', () => {
    process.env.SOROBAN_RPC_CIRCUIT_BREAKER_THRESHOLD = '0';

    expect(() => getSorobanRetryPolicy()).toThrow(
      'Invalid SOROBAN_RPC_CIRCUIT_BREAKER_THRESHOLD. Expected an integer between 1 and 20.',
    );
  });

  it('rejects a circuit-breaker reset below its bounds', () => {
    process.env.SOROBAN_RPC_CIRCUIT_BREAKER_RESET_MS = '999';

    expect(() => getSorobanRetryPolicy()).toThrow(
      'Invalid SOROBAN_RPC_CIRCUIT_BREAKER_RESET_MS. Expected an integer between 1000 and 300000.',
    );
  });

  it('rejects backoff base greater than backoff max passed as overrides', () => {
    expect(() =>
      getSorobanRetryPolicy({ retryBaseDelayMs: 5000, retryMaxDelayMs: 1000 }),
    ).toThrow(
      'Invalid Soroban retry policy. retryBaseDelayMs must be less than or equal to retryMaxDelayMs.',
    );
  });

  it('rejects backoff base greater than backoff max supplied via the environment', () => {
    process.env.SOROBAN_BACKOFF_BASE_MS = '400';
    process.env.SOROBAN_BACKOFF_MAX_MS = '300';

    expect(() => getSorobanRetryPolicy()).toThrow(
      /retryBaseDelayMs must be less than or equal to retryMaxDelayMs/,
    );
  });
});
