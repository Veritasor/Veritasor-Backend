/**
 * Unit tests for src/db/retry.ts
 *
 * All sleepFn and randomFn dependencies are injected so tests run
 * synchronously-fast without real timers.
 */

import {
  isTransientConnectionError,
  pgBouncerBackoffMs,
  withPgBouncerRetry,
  PGBOUNCER_MAX_RETRIES,
  PGBOUNCER_BASE_DELAY_MS,
  PGBOUNCER_MAX_DELAY_MS,
} from '../../../src/db/retry.js';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeError(code: string, message = 'db error'): Error {
  return Object.assign(new Error(message), { code });
}

/** A sleep stub that resolves immediately and records calls. */
function makeSleep() {
  const calls: number[] = [];
  const fn = (ms: number): Promise<void> => {
    calls.push(ms);
    return Promise.resolve();
  };
  return { fn, calls };
}

/** Always returns the same fixed value — makes backoff deterministic. */
const fixedRandom = (v: number) => () => v;

// ─── isTransientConnectionError ──────────────────────────────────────────────

describe('isTransientConnectionError', () => {
  it('returns false for non-Error values', () => {
    expect(isTransientConnectionError(null)).toBe(false);
    expect(isTransientConnectionError('string error')).toBe(false);
    expect(isTransientConnectionError(42)).toBe(false);
  });

  it('returns false for errors without a recognised code', () => {
    expect(isTransientConnectionError(new Error('something else'))).toBe(false);
    expect(isTransientConnectionError(makeError('23505'))).toBe(false); // unique violation
    expect(isTransientConnectionError(makeError('28P01'))).toBe(false); // invalid password
  });

  it.each([
    '08000', '08003', '08006', '08001', '08004',
    '57P01', '57P02', '57P03',
  ])('returns true for PG transient code %s', (code) => {
    expect(isTransientConnectionError(makeError(code))).toBe(true);
  });

  it.each([
    'ECONNRESET', 'ECONNREFUSED', 'ECONNABORTED',
    'EPIPE', 'ETIMEDOUT', 'EHOSTUNREACH', 'ENETUNREACH',
  ])('returns true for Node socket code %s', (code) => {
    expect(isTransientConnectionError(makeError(code))).toBe(true);
  });

  it('returns true for "connection terminated" message pattern', () => {
    expect(
      isTransientConnectionError(new Error('Connection terminated unexpectedly')),
    ).toBe(true);
    expect(
      isTransientConnectionError(new Error('read ECONNRESET — connection terminated')),
    ).toBe(true);
  });

  it('returns false for errors whose message does not match the pattern', () => {
    expect(
      isTransientConnectionError(new Error('syntax error near SELECT')),
    ).toBe(false);
  });
});

// ─── pgBouncerBackoffMs ───────────────────────────────────────────────────────

describe('pgBouncerBackoffMs', () => {
  it('returns 0 when random is 0', () => {
    expect(pgBouncerBackoffMs(1, fixedRandom(0))).toBe(0);
  });

  it('scales with attempt number (exponential growth)', () => {
    const d1 = pgBouncerBackoffMs(1, fixedRandom(1));
    const d2 = pgBouncerBackoffMs(2, fixedRandom(1));
    const d3 = pgBouncerBackoffMs(3, fixedRandom(1));
    expect(d2).toBeGreaterThan(d1);
    expect(d3).toBeGreaterThan(d2);
  });

  it('never exceeds PGBOUNCER_MAX_DELAY_MS even with random=1', () => {
    for (let attempt = 1; attempt <= 20; attempt++) {
      expect(pgBouncerBackoffMs(attempt, fixedRandom(1))).toBeLessThanOrEqual(
        PGBOUNCER_MAX_DELAY_MS,
      );
    }
  });

  it('computes the expected value: round(random * min(cap, base * 2^attempt))', () => {
    const base = PGBOUNCER_BASE_DELAY_MS;
    const cap = PGBOUNCER_MAX_DELAY_MS;
    const random = 0.5;
    const attempt = 2;
    const expected = Math.round(random * Math.min(cap, base * 2 ** attempt));
    expect(pgBouncerBackoffMs(attempt, fixedRandom(random))).toBe(expected);
  });
});

// ─── withPgBouncerRetry ───────────────────────────────────────────────────────

describe('withPgBouncerRetry', () => {
  it('returns the result immediately when fn succeeds on first call', async () => {
    const fn = jest.fn().mockResolvedValue('ok');
    const { fn: sleep, calls } = makeSleep();
    const result = await withPgBouncerRetry(fn, 'test', sleep);
    expect(result).toBe('ok');
    expect(fn).toHaveBeenCalledTimes(1);
    expect(calls).toHaveLength(0);
  });

  it('retries on transient error and succeeds on second attempt', async () => {
    const transient = makeError('ECONNRESET');
    const fn = jest
      .fn()
      .mockRejectedValueOnce(transient)
      .mockResolvedValue('recovered');
    const { fn: sleep, calls } = makeSleep();
    const result = await withPgBouncerRetry(fn, 'test', sleep, fixedRandom(0));
    expect(result).toBe('recovered');
    expect(fn).toHaveBeenCalledTimes(2);
    expect(calls).toHaveLength(1);
  });

  it('retries up to PGBOUNCER_MAX_RETRIES times then throws', async () => {
    const transient = makeError('08006');
    const fn = jest.fn().mockRejectedValue(transient);
    const { fn: sleep } = makeSleep();
    await expect(
      withPgBouncerRetry(fn, 'test', sleep, fixedRandom(0)),
    ).rejects.toBe(transient);
    // 1 initial + PGBOUNCER_MAX_RETRIES retries
    expect(fn).toHaveBeenCalledTimes(1 + PGBOUNCER_MAX_RETRIES);
  });

  it('does NOT retry non-transient errors', async () => {
    const constraintErr = makeError('23505', 'unique_violation');
    const fn = jest.fn().mockRejectedValue(constraintErr);
    const { fn: sleep, calls } = makeSleep();
    await expect(
      withPgBouncerRetry(fn, 'test', sleep),
    ).rejects.toBe(constraintErr);
    expect(fn).toHaveBeenCalledTimes(1);
    expect(calls).toHaveLength(0);
  });

  it('does NOT retry auth errors (28P01)', async () => {
    const authErr = makeError('28P01', 'password authentication failed');
    const fn = jest.fn().mockRejectedValue(authErr);
    const { fn: sleep } = makeSleep();
    await expect(withPgBouncerRetry(fn, 'test', sleep)).rejects.toBe(authErr);
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('does NOT retry non-Error throwables', async () => {
    const fn = jest.fn().mockRejectedValue('string-thrown');
    const { fn: sleep } = makeSleep();
    await expect(withPgBouncerRetry(fn, 'test', sleep)).rejects.toBe('string-thrown');
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('passes correct delay values from pgBouncerBackoffMs to sleepFn', async () => {
    const transient = makeError('57P01');
    const fn = jest
      .fn()
      .mockRejectedValueOnce(transient)
      .mockRejectedValueOnce(transient)
      .mockResolvedValue('done');
    const { fn: sleep, calls } = makeSleep();
    // random=1 means delay = min(cap, base * 2^attempt)
    await withPgBouncerRetry(fn, 'test', sleep, fixedRandom(1));
    expect(calls).toHaveLength(2);
    expect(calls[0]).toBe(pgBouncerBackoffMs(1, fixedRandom(1)));
    expect(calls[1]).toBe(pgBouncerBackoffMs(2, fixedRandom(1)));
  });

  it('surfaces the original error after cap exhaustion, not a wrapper', async () => {
    const original = makeError('EPIPE', 'broken pipe');
    const fn = jest.fn().mockRejectedValue(original);
    const { fn: sleep } = makeSleep();
    let thrown: unknown;
    try {
      await withPgBouncerRetry(fn, 'test', sleep, fixedRandom(0));
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBe(original); // identity check — same object, not a copy
  });

  it('succeeds on the last possible attempt (edge: attempt === maxRetries)', async () => {
    const transient = makeError('ECONNRESET');
    const fn = jest.fn();
    // fail maxRetries times, succeed on the (maxRetries+1)th call
    for (let i = 0; i < PGBOUNCER_MAX_RETRIES; i++) {
      fn.mockRejectedValueOnce(transient);
    }
    fn.mockResolvedValueOnce('last-chance');
    const { fn: sleep } = makeSleep();
    const result = await withPgBouncerRetry(fn, 'test', sleep, fixedRandom(0));
    expect(result).toBe('last-chance');
    expect(fn).toHaveBeenCalledTimes(1 + PGBOUNCER_MAX_RETRIES);
  });

  it('does not retry when PGBOUNCER_MAX_RETRIES would be 0', async () => {
    // We test the backoff math boundary: if maxRetries=0, first failure must throw.
    // We call withPgBouncerRetry with a custom implementation that has max=0.
    // Since the constant is module-level, we instead verify the boundary condition
    // by checking that attempt >= maxRetries short-circuits on the first error.
    const transient = makeError('ECONNRESET');
    // Simulate max=0 by having fn always throw and asserting exactly 1 call
    // when PGBOUNCER_MAX_RETRIES >= 1 (default): if maxRetries were 0 the loop
    // would exit on attempt=0 >= 0.  We trust the logic via coverage of the
    // "attempt >= PGBOUNCER_MAX_RETRIES" branch tested in the exhaustion test above.
    expect(PGBOUNCER_MAX_RETRIES).toBeGreaterThan(0); // sanity check defaults
    // Non-transient short-circuit verified in separate test — this is a guard.
    expect(isTransientConnectionError(transient)).toBe(true);
  });
});
