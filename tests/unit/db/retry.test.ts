/**
 * Unit tests for src/db/retry.ts
 *
 * `withPgBouncerRetry` is the safety net around PgBouncer pool churn, so this
 * suite pins every observable behaviour of the module:
 *
 *   - the three exported tunables (defaults + `Math.max` clamping, including
 *     re-evaluation against overridden env vars),
 *   - the transient-error classifier for each PG / Node code and the
 *     "Connection terminated" message path,
 *   - the full-jitter backoff window `min(MAX_DELAY, BASE * 2^attempt)` and its
 *     rounding / bounds under an injected `randomFn`,
 *   - the retry loop's state transitions (success, exhaustion, non-retryable
 *     short-circuit) with the structured logger output it emits.
 *
 * `sleepFn` and `randomFn` are always injected, so the suite never touches real
 * timers and stays deterministic.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// The production logger is only used for observability; mock it so retries can
// be asserted on without writing to the console (mirrors other tests/unit
// suites such as tests/unit/pgbouncerScraper.test.ts).
const mocks = vi.hoisted(() => ({
  logger: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));

vi.mock('../../../src/utils/logger.js', () => ({ logger: mocks.logger }));

import {
  isTransientConnectionError,
  pgBouncerBackoffMs,
  withPgBouncerRetry,
  PGBOUNCER_MAX_RETRIES,
  PGBOUNCER_BASE_DELAY_MS,
  PGBOUNCER_MAX_DELAY_MS,
} from '../../../src/db/retry.js';

const TUNABLE_ENV = [
  'PGBOUNCER_MAX_RETRIES',
  'PGBOUNCER_BASE_DELAY_MS',
  'PGBOUNCER_MAX_DELAY_MS',
] as const;

type TunableEnv = Partial<Record<(typeof TUNABLE_ENV)[number], string>>;

function clearTunableEnv(): void {
  for (const key of TUNABLE_ENV) delete process.env[key];
}

/**
 * Re-evaluates src/db/retry.ts with a fresh module registry so the module-level
 * `Math.max(...)` clamps are re-run against the supplied environment.
 */
async function loadRetryWithEnv(
  env: TunableEnv = {},
): Promise<typeof import('../../../src/db/retry.js')> {
  vi.resetModules();
  clearTunableEnv();
  for (const [key, value] of Object.entries(env)) {
    process.env[key] = value as string;
  }
  return import('../../../src/db/retry.js');
}

function makeError(code: string, message = 'db error'): NodeJS.ErrnoException {
  return Object.assign(new Error(message), { code });
}

/** Sleep stub: resolves immediately and records every requested delay. */
function makeSleep() {
  const calls: number[] = [];
  const fn = (ms: number): Promise<void> => {
    calls.push(ms);
    return Promise.resolve();
  };
  return { fn, calls };
}

const fixedRandom = (value: number) => () => value;

function loggedPayload(callIndex = 0): Record<string, unknown> {
  const line = mocks.logger.warn.mock.calls[callIndex]?.[0];
  return JSON.parse(line as string) as Record<string, unknown>;
}

beforeEach(() => {
  clearTunableEnv();
  mocks.logger.warn.mockClear();
  mocks.logger.info.mockClear();
  mocks.logger.debug.mockClear();
  mocks.logger.error.mockClear();
});

afterEach(() => {
  clearTunableEnv();
  vi.resetModules();
});

// ─── Exported tunables ────────────────────────────────────────────────────────

describe('PGBOUNCER_* tunables', () => {
  it('defaults to 3 retries, 50ms base and a 2000ms cap', () => {
    expect(PGBOUNCER_MAX_RETRIES).toBe(3);
    expect(PGBOUNCER_BASE_DELAY_MS).toBe(50);
    expect(PGBOUNCER_MAX_DELAY_MS).toBe(2_000);
  });

  it('reads numeric overrides from the environment', async () => {
    const mod = await loadRetryWithEnv({
      PGBOUNCER_MAX_RETRIES: '7',
      PGBOUNCER_BASE_DELAY_MS: '125',
      PGBOUNCER_MAX_DELAY_MS: '9000',
    });
    expect(mod.PGBOUNCER_MAX_RETRIES).toBe(7);
    expect(mod.PGBOUNCER_BASE_DELAY_MS).toBe(125);
    expect(mod.PGBOUNCER_MAX_DELAY_MS).toBe(9_000);
  });

  it('clamps a negative retry budget to 0 (never a negative loop bound)', async () => {
    const mod = await loadRetryWithEnv({ PGBOUNCER_MAX_RETRIES: '-5' });
    expect(mod.PGBOUNCER_MAX_RETRIES).toBe(0);
  });

  it('clamps both delays to a 1ms floor', async () => {
    const mod = await loadRetryWithEnv({
      PGBOUNCER_BASE_DELAY_MS: '0',
      PGBOUNCER_MAX_DELAY_MS: '-100',
    });
    expect(mod.PGBOUNCER_BASE_DELAY_MS).toBe(1);
    expect(mod.PGBOUNCER_MAX_DELAY_MS).toBe(1);
  });

  it('treats an empty retry override as 0 (empty string is not nullish)', async () => {
    const mod = await loadRetryWithEnv({ PGBOUNCER_MAX_RETRIES: '' });
    expect(mod.PGBOUNCER_MAX_RETRIES).toBe(0);
  });

  it('documents the current behaviour for non-numeric configuration', async () => {
    const mod = await loadRetryWithEnv({
      PGBOUNCER_MAX_RETRIES: 'not-a-number',
      PGBOUNCER_BASE_DELAY_MS: 'nope',
      PGBOUNCER_MAX_DELAY_MS: 'x',
    });
    // `Math.max(floor, NaN)` propagates NaN rather than falling back to the
    // default — pinned here so a future fix to throw or fall back is visible.
    expect(Number.isNaN(mod.PGBOUNCER_MAX_RETRIES)).toBe(true);
    expect(Number.isNaN(mod.PGBOUNCER_BASE_DELAY_MS)).toBe(true);
    expect(Number.isNaN(mod.PGBOUNCER_MAX_DELAY_MS)).toBe(true);
  });
});

// ─── isTransientConnectionError ──────────────────────────────────────────────

describe('isTransientConnectionError', () => {
  it.each([
    '08000', // connection_exception
    '08003', // connection_does_not_exist
    '08006', // connection_failure
    '08001', // sqlclient_unable_to_establish_sqlconnection
    '08004', // sqlserver_rejected_establishment_of_sqlconnection
    '57P01', // admin_shutdown (PgBouncer forced-close)
    '57P02', // crash_shutdown
    '57P03', // cannot_connect_now
  ])('classifies PostgreSQL transient code %s as retryable', (code) => {
    expect(isTransientConnectionError(makeError(code))).toBe(true);
  });

  it.each([
    'ECONNRESET',
    'ECONNREFUSED',
    'ECONNABORTED',
    'EPIPE',
    'ETIMEDOUT',
    'EHOSTUNREACH',
    'ENETUNREACH',
  ])('classifies Node socket code %s as retryable', (code) => {
    expect(isTransientConnectionError(makeError(code))).toBe(true);
  });

  it('retries the "Connection terminated" message path case-insensitively', () => {
    expect(
      isTransientConnectionError(new Error('Connection terminated unexpectedly')),
    ).toBe(true);
    expect(
      isTransientConnectionError(new Error('connection TERMINATED by pgbouncer')),
    ).toBe(true);
  });

  it('treats a transient message as retryable even for an unrelated error code', () => {
    expect(
      isTransientConnectionError(
        makeError('23505', 'connection terminated while flushing the socket'),
      ),
    ).toBe(true);
  });

  it('rejects query-level errors, plain errors and non-Error values', () => {
    expect(isTransientConnectionError(makeError('23505', 'unique_violation'))).toBe(false);
    expect(isTransientConnectionError(makeError('28P01', 'password authentication failed'))).toBe(false);
    expect(isTransientConnectionError(new Error('syntax error at or near "SELCT"'))).toBe(false);
    expect(isTransientConnectionError(null)).toBe(false);
    expect(isTransientConnectionError(undefined)).toBe(false);
    expect(isTransientConnectionError('ECONNRESET')).toBe(false);
    expect(isTransientConnectionError(42)).toBe(false);
    expect(isTransientConnectionError({ code: '08006' })).toBe(false);
  });
});

// ─── pgBouncerBackoffMs ───────────────────────────────────────────────────────

describe('pgBouncerBackoffMs', () => {
  it('returns the lower jitter bound for any attempt when random = 0', () => {
    for (const attempt of [0, 1, 2, 5, 50]) {
      expect(pgBouncerBackoffMs(attempt, fixedRandom(0))).toBe(0);
    }
  });

  it('returns the full window for the upper jitter bound (random = 1)', () => {
    for (const attempt of [0, 1, 2, 3, 4]) {
      const window = Math.min(
        PGBOUNCER_MAX_DELAY_MS,
        PGBOUNCER_BASE_DELAY_MS * 2 ** attempt,
      );
      expect(pgBouncerBackoffMs(attempt, fixedRandom(1))).toBe(Math.round(window));
    }
  });

  it('computes min(MAX_DELAY, BASE * 2^attempt) and caps beyond the window', () => {
    // Default BASE=50 → 100, 200, 400; attempt 6 would be 3200 → capped at 2000.
    expect(pgBouncerBackoffMs(1, fixedRandom(1))).toBe(100);
    expect(pgBouncerBackoffMs(2, fixedRandom(1))).toBe(200);
    expect(pgBouncerBackoffMs(3, fixedRandom(1))).toBe(400);
    expect(pgBouncerBackoffMs(6, fixedRandom(1))).toBe(PGBOUNCER_MAX_DELAY_MS);
    expect(pgBouncerBackoffMs(20, fixedRandom(1))).toBe(PGBOUNCER_MAX_DELAY_MS);
  });

  it('rounds the jittered delay to the nearest millisecond', () => {
    // attempt 1 → 100ms window
    expect(pgBouncerBackoffMs(1, fixedRandom(0.333))).toBe(33); // 33.3
    expect(pgBouncerBackoffMs(1, fixedRandom(0.336))).toBe(34); // 33.6
    expect(pgBouncerBackoffMs(1, fixedRandom(0.5))).toBe(50);
  });

  it('stays within [0, MAX_DELAY] across a wide attempt range', () => {
    for (let attempt = 0; attempt <= 40; attempt++) {
      const delay = pgBouncerBackoffMs(attempt, fixedRandom(1));
      expect(delay).toBeGreaterThanOrEqual(0);
      expect(delay).toBeLessThanOrEqual(PGBOUNCER_MAX_DELAY_MS);
    }
  });
});

// ─── withPgBouncerRetry ───────────────────────────────────────────────────────

describe('withPgBouncerRetry', () => {
  it('returns immediately on success without sleeping or logging', async () => {
    const fn = vi.fn().mockResolvedValue('ok');
    const { fn: sleep, calls } = makeSleep();

    await expect(withPgBouncerRetry(fn, 'test', sleep)).resolves.toBe('ok');

    expect(fn).toHaveBeenCalledTimes(1);
    expect(calls).toHaveLength(0);
    expect(mocks.logger.warn).not.toHaveBeenCalled();
  });

  it('recovers after one transient failure, sleeping the attempt-1 delay', async () => {
    const transient = makeError('ECONNRESET');
    const fn = vi.fn().mockRejectedValueOnce(transient).mockResolvedValue('recovered');
    const { fn: sleep, calls } = makeSleep();

    await expect(
      withPgBouncerRetry(fn, 'test', sleep, fixedRandom(0.5)),
    ).resolves.toBe('recovered');

    expect(fn).toHaveBeenCalledTimes(2);
    expect(calls).toEqual([pgBouncerBackoffMs(1, fixedRandom(0.5))]);
    expect(mocks.logger.warn).toHaveBeenCalledTimes(1);
  });

  it('retries exactly PGBOUNCER_MAX_RETRIES additional times, then rethrows the original error', async () => {
    const transient = makeError('08006', 'server closed the connection');
    const fn = vi.fn().mockRejectedValue(transient);
    const { fn: sleep, calls } = makeSleep();

    await expect(
      withPgBouncerRetry(fn, 'test', sleep, fixedRandom(0)),
    ).rejects.toBe(transient);

    expect(fn).toHaveBeenCalledTimes(1 + PGBOUNCER_MAX_RETRIES);
    expect(calls).toHaveLength(PGBOUNCER_MAX_RETRIES);
    expect(mocks.logger.warn).toHaveBeenCalledTimes(PGBOUNCER_MAX_RETRIES);
  });

  it('passes attempt+1 and the computed delay to sleepFn and logs the same values', async () => {
    const transient = makeError('57P01');
    const fn = vi.fn();
    for (let i = 0; i < PGBOUNCER_MAX_RETRIES; i++) fn.mockRejectedValueOnce(transient);
    fn.mockResolvedValueOnce('done');
    const { fn: sleep, calls } = makeSleep();

    await expect(
      withPgBouncerRetry(fn, 'transfer:insert', sleep, fixedRandom(1)),
    ).resolves.toBe('done');

    expect(calls).toEqual([
      pgBouncerBackoffMs(1, fixedRandom(1)),
      pgBouncerBackoffMs(2, fixedRandom(1)),
      pgBouncerBackoffMs(3, fixedRandom(1)),
    ]);
    expect(mocks.logger.warn).toHaveBeenCalledTimes(PGBOUNCER_MAX_RETRIES);

    const attempts = mocks.logger.warn.mock.calls.map((call) => loggedFromCall(call));
    expect(attempts.map((p) => p.attempt)).toEqual([1, 2, 3]);
    expect(attempts.map((p) => p.delayMs)).toEqual(calls);
    expect(attempts.every((p) => p.maxRetries === PGBOUNCER_MAX_RETRIES)).toBe(true);
  });

  it('emits one structured observability record per retry', async () => {
    const transient = makeError('ETIMEDOUT', 'connect ETIMEDOUT 10.0.0.1:6432');
    const fn = vi.fn().mockRejectedValueOnce(transient).mockResolvedValue('ok');
    const { fn: sleep } = makeSleep();

    await withPgBouncerRetry(fn, 'transfer:insert', sleep, fixedRandom(0.25));

    expect(mocks.logger.warn).toHaveBeenCalledTimes(1);
    expect(loggedPayload()).toEqual({
      event: 'pgbouncer_reconnect_retry',
      label: 'transfer:insert',
      attempt: 1,
      maxRetries: PGBOUNCER_MAX_RETRIES,
      delayMs: pgBouncerBackoffMs(1, fixedRandom(0.25)),
      errorCode: 'ETIMEDOUT',
      errorMessage: 'connect ETIMEDOUT 10.0.0.1:6432',
    });
  });

  it('logs a null errorCode for message-only transient failures', async () => {
    const fn = vi
      .fn()
      .mockRejectedValueOnce(new Error('Connection terminated unexpectedly'))
      .mockResolvedValue('ok');
    const { fn: sleep } = makeSleep();

    await withPgBouncerRetry(fn, 'query', sleep, fixedRandom(0));

    expect(loggedPayload()).toMatchObject({
      errorCode: null,
      errorMessage: 'Connection terminated unexpectedly',
    });
  });

  const NON_TRANSIENT: Array<[string, unknown]> = [
    ['constraint violation', makeError('23505', 'duplicate key value violates unique constraint')],
    ['auth failure', makeError('28P01', 'password authentication failed')],
    ['plain error', new Error('syntax error at or near "SELCT"')],
  ];

  it.each(NON_TRANSIENT)('does not retry a %s', async (_name, error) => {
    const fn = vi.fn().mockRejectedValue(error);
    const { fn: sleep, calls } = makeSleep();

    await expect(
      withPgBouncerRetry(fn, 'test', sleep, fixedRandom(1)),
    ).rejects.toBe(error);

    expect(fn).toHaveBeenCalledTimes(1);
    expect(calls).toHaveLength(0);
    expect(mocks.logger.warn).not.toHaveBeenCalled();
  });

  it('does not retry non-Error throwables', async () => {
    const fn = vi.fn().mockRejectedValue('string-thrown');
    const { fn: sleep, calls } = makeSleep();

    await expect(withPgBouncerRetry(fn, 'test', sleep)).rejects.toBe('string-thrown');

    expect(fn).toHaveBeenCalledTimes(1);
    expect(calls).toHaveLength(0);
    expect(mocks.logger.warn).not.toHaveBeenCalled();
  });

  it('can recover on the very last permitted attempt', async () => {
    const transient = makeError('ECONNRESET');
    const fn = vi.fn();
    for (let i = 0; i < PGBOUNCER_MAX_RETRIES; i++) fn.mockRejectedValueOnce(transient);
    fn.mockResolvedValueOnce('last-chance');
    const { fn: sleep } = makeSleep();

    await expect(
      withPgBouncerRetry(fn, 'test', sleep, fixedRandom(0)),
    ).resolves.toBe('last-chance');

    expect(fn).toHaveBeenCalledTimes(1 + PGBOUNCER_MAX_RETRIES);
  });
});

// ─── Retry budget boundaries (env-driven) ─────────────────────────────────────

describe('withPgBouncerRetry retry budget boundaries', () => {
  it('does not retry at all when PGBOUNCER_MAX_RETRIES=0', async () => {
    const mod = await loadRetryWithEnv({ PGBOUNCER_MAX_RETRIES: '0' });
    const transient = makeError('ECONNRESET');
    const fn = vi.fn().mockRejectedValue(transient);
    const { fn: sleep, calls } = makeSleep();

    await expect(
      mod.withPgBouncerRetry(fn, 'test', sleep, fixedRandom(0)),
    ).rejects.toBe(transient);

    expect(fn).toHaveBeenCalledTimes(1);
    expect(calls).toHaveLength(0);
    expect(mocks.logger.warn).not.toHaveBeenCalled();
  });

  it('honours a raised budget and reports it in the log record', async () => {
    const mod = await loadRetryWithEnv({ PGBOUNCER_MAX_RETRIES: '5' });
    const fn = vi.fn().mockRejectedValue(makeError('08000'));
    const { fn: sleep, calls } = makeSleep();

    await expect(mod.withPgBouncerRetry(fn, 'test', sleep, fixedRandom(0))).rejects.toThrow();

    expect(fn).toHaveBeenCalledTimes(6);
    expect(calls).toHaveLength(5);
    expect(mocks.logger.warn).toHaveBeenCalledTimes(5);
    expect(loggedPayload(0).maxRetries).toBe(5);
    expect(loggedPayload(4).attempt).toBe(5);
  });

  it('clamps a negative budget to the no-retry floor', async () => {
    const mod = await loadRetryWithEnv({ PGBOUNCER_MAX_RETRIES: '-3' });
    const fn = vi.fn().mockRejectedValue(makeError('08000'));
    const { fn: sleep } = makeSleep();

    await expect(mod.withPgBouncerRetry(fn, 'test', sleep)).rejects.toThrow();
    expect(fn).toHaveBeenCalledTimes(1);
    expect(mocks.logger.warn).not.toHaveBeenCalled();
  });

  it('applies overridden base/cap values to the backoff window', async () => {
    const mod = await loadRetryWithEnv({
      PGBOUNCER_MAX_RETRIES: '3',
      PGBOUNCER_BASE_DELAY_MS: '10',
      PGBOUNCER_MAX_DELAY_MS: '25',
    });

    expect(mod.pgBouncerBackoffMs(1, fixedRandom(1))).toBe(20); // 10 * 2^1
    expect(mod.pgBouncerBackoffMs(2, fixedRandom(1))).toBe(25); // 40 capped to 25

    const fn = vi.fn().mockRejectedValueOnce(makeError('08000')).mockResolvedValue('ok');
    const { fn: sleep, calls } = makeSleep();
    await expect(
      mod.withPgBouncerRetry(fn, 'test', sleep, fixedRandom(1)),
    ).resolves.toBe('ok');
    expect(calls).toEqual([20]);
  });
});

/** Parses the JSON string handed to logger.warn by an individual call. */
function loggedFromCall(call: unknown[]): Record<string, number> {
  return JSON.parse(call[0] as string) as Record<string, number>;
}
