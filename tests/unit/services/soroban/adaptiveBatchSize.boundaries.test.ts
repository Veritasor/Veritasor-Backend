/**
 * Boundary-condition coverage for `src/services/soroban/adaptiveBatchSize.ts`.
 *
 * The module derives its tunables from the environment (`getAdaptiveBatchConfig`),
 * samples `getFeeStats` percentiles, and feeds an EWMA controller that must stay
 * inside `[minBatchSize, maxBatchSize]`. These tests pin the edges rather than
 * the happy path:
 *
 * - env parsing at, inside and outside the accepted windows (including the
 *   documented fallback-on-invalid behaviour),
 * - `sampleSorobanFeeStats` volatility maths and its zero-fee guard,
 * - the controller's EWMA seeding, spike threshold (strict `>` comparison),
 *   clamping at both bounds, volatility dampening and `reset()`,
 * - the `sampleIntervalMs` throttle in `sampleAndTune`.
 *
 * @module tests/unit/services/soroban/adaptiveBatchSize.boundaries
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  AdaptiveBatchSizeController,
  DEFAULT_ADAPTIVE_BATCH_CONFIG,
  getAdaptiveBatchConfig,
  sampleSorobanFeeStats,
  type AdaptiveBatchConfig,
} from '../../../../src/services/soroban/adaptiveBatchSize.js';
import { rpc } from '@stellar/stellar-sdk';

/** Every env var `getAdaptiveBatchConfig` reads. */
const ENV_KEYS = [
  'SOROBAN_ADAPTIVE_BATCH_MIN_SIZE',
  'SOROBAN_ADAPTIVE_BATCH_MAX_SIZE',
  'SOROBAN_ADAPTIVE_BATCH_EWMA_ALPHA',
  'SOROBAN_ADAPTIVE_BATCH_SPIKE_MULTIPLIER',
  'SOROBAN_ADAPTIVE_BATCH_SENSITIVITY',
  'SOROBAN_ADAPTIVE_BATCH_VOLATILITY_DAMPENING',
  'SOROBAN_ADAPTIVE_BATCH_SAMPLE_INTERVAL_MS',
] as const;

/** A `rpc.Server` double whose `getFeeStats` returns fixed percentiles. */
function feeServer(p10: string, p50: string, p90: string) {
  const response = {
    sorobanInclusionFee: { p10, p50, p90, max: p90, min: p10, mode: p50 },
    inclusionFee: { p10, p50, p90, max: p90, min: p10, mode: p50 },
    latestLedger: 1,
  };
  return {
    server: { getFeeStats: vi.fn(async () => response) } as unknown as rpc.Server,
  };
}

function controller(config?: Partial<AdaptiveBatchConfig>) {
  return new AdaptiveBatchSizeController(config);
}

function warnEntries(): Record<string, unknown>[] {
  return (console.warn as unknown as { mock: { calls: unknown[][] } }).mock.calls.map(
    (call) => JSON.parse(call[0] as string) as Record<string, unknown>,
  );
}

let warn: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  for (const key of ENV_KEYS) delete process.env[key];
  warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
});

afterEach(() => {
  warn.mockRestore();
  for (const key of ENV_KEYS) delete process.env[key];
});

describe('getAdaptiveBatchConfig - defaults and overrides', () => {
  it('returns the documented defaults when no env var is set', () => {
    expect(getAdaptiveBatchConfig()).toEqual(DEFAULT_ADAPTIVE_BATCH_CONFIG);
  });

  it('lets explicit overrides win over env vars, unvalidated', () => {
    process.env['SOROBAN_ADAPTIVE_BATCH_MIN_SIZE'] = '4';

    const config = getAdaptiveBatchConfig({ minBatchSize: 7, maxBatchSize: 2_000 });

    expect(config.minBatchSize).toBe(7);
    expect(config.maxBatchSize).toBe(2_000);
  });

  it('returns a fresh object on every call', () => {
    const first = getAdaptiveBatchConfig();
    first.maxBatchSize = 1;

    expect(getAdaptiveBatchConfig().maxBatchSize).toBe(DEFAULT_ADAPTIVE_BATCH_CONFIG.maxBatchSize);
  });
});

describe('getAdaptiveBatchConfig - integer env boundaries', () => {
  it.each([
    ['1', 1],
    ['25', 25],
    ['100000', 100_000],
  ])('accepts SOROBAN_ADAPTIVE_BATCH_MIN_SIZE=%s', (raw, expected) => {
    process.env['SOROBAN_ADAPTIVE_BATCH_MIN_SIZE'] = raw;

    expect(getAdaptiveBatchConfig().minBatchSize).toBe(expected);
    expect(warn).not.toHaveBeenCalled();
  });

  it.each([
    ['zero', '0'],
    ['negative', '-5'],
    ['non-numeric', 'abc'],
    ['empty', ''],
    ['whitespace only', '   '],
  ])('falls back for %s SOROBAN_ADAPTIVE_BATCH_MAX_SIZE', (_label, raw) => {
    process.env['SOROBAN_ADAPTIVE_BATCH_MAX_SIZE'] = raw;

    const config = getAdaptiveBatchConfig();

    expect(config.maxBatchSize).toBe(DEFAULT_ADAPTIVE_BATCH_CONFIG.maxBatchSize);
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warnEntries()[0]).toMatchObject({
      level: 'warn',
      envVar: 'SOROBAN_ADAPTIVE_BATCH_MAX_SIZE',
      raw,
    });
  });

  it('truncates a fractional integer env value instead of rejecting it', () => {
    process.env['SOROBAN_ADAPTIVE_BATCH_SAMPLE_INTERVAL_MS'] = '1500.9';

    expect(getAdaptiveBatchConfig().sampleIntervalMs).toBe(1500);
    expect(warn).not.toHaveBeenCalled();
  });

  it('tolerates surrounded whitespace', () => {
    process.env['SOROBAN_ADAPTIVE_BATCH_MIN_SIZE'] = '  12  ';

    expect(getAdaptiveBatchConfig().minBatchSize).toBe(12);
  });
});

describe('getAdaptiveBatchConfig - decimal env boundaries', () => {
  it.each([
    ['SOROBAN_ADAPTIVE_BATCH_EWMA_ALPHA', '0.01'],
    ['SOROBAN_ADAPTIVE_BATCH_EWMA_ALPHA', '1.0'],
    ['SOROBAN_ADAPTIVE_BATCH_SPIKE_MULTIPLIER', '1.0'],
    ['SOROBAN_ADAPTIVE_BATCH_SPIKE_MULTIPLIER', '10.0'],
    ['SOROBAN_ADAPTIVE_BATCH_SENSITIVITY', '0.01'],
    ['SOROBAN_ADAPTIVE_BATCH_SENSITIVITY', '2.0'],
    ['SOROBAN_ADAPTIVE_BATCH_VOLATILITY_DAMPENING', '0.0'],
    ['SOROBAN_ADAPTIVE_BATCH_VOLATILITY_DAMPENING', '1.0'],
  ])('accepts the inclusive boundary %s=%s', (key, raw) => {
    process.env[key] = raw;

    const config = getAdaptiveBatchConfig() as unknown as Record<string, number>;
    const field = {
      SOROBAN_ADAPTIVE_BATCH_EWMA_ALPHA: 'ewmaAlpha',
      SOROBAN_ADAPTIVE_BATCH_SPIKE_MULTIPLIER: 'feeSpikeMultiplier',
      SOROBAN_ADAPTIVE_BATCH_SENSITIVITY: 'sensitivity',
      SOROBAN_ADAPTIVE_BATCH_VOLATILITY_DAMPENING: 'volatilityDampening',
    }[key]!;

    expect(config[field]).toBe(Number(raw));
    expect(warn).not.toHaveBeenCalled();
  });

  it.each([
    ['below the ewmaAlpha floor', 'SOROBAN_ADAPTIVE_BATCH_EWMA_ALPHA', '0.009', 'ewmaAlpha'],
    ['above the ewmaAlpha ceiling', 'SOROBAN_ADAPTIVE_BATCH_EWMA_ALPHA', '1.01', 'ewmaAlpha'],
    ['below the spike floor', 'SOROBAN_ADAPTIVE_BATCH_SPIKE_MULTIPLIER', '0.99', 'feeSpikeMultiplier'],
    ['above the spike ceiling', 'SOROBAN_ADAPTIVE_BATCH_SPIKE_MULTIPLIER', '10.01', 'feeSpikeMultiplier'],
    ['below the sensitivity floor', 'SOROBAN_ADAPTIVE_BATCH_SENSITIVITY', '0', 'sensitivity'],
    ['negative dampening', 'SOROBAN_ADAPTIVE_BATCH_VOLATILITY_DAMPENING', '-0.1', 'volatilityDampening'],
    ['NaN', 'SOROBAN_ADAPTIVE_BATCH_SENSITIVITY', 'not-a-number', 'sensitivity'],
    ['Infinity', 'SOROBAN_ADAPTIVE_BATCH_SENSITIVITY', 'Infinity', 'sensitivity'],
  ])('falls back for %s', (_label, key, raw, field) => {
    process.env[key] = raw;

    const config = getAdaptiveBatchConfig() as unknown as Record<string, number>;

    expect(config[field]).toBe((DEFAULT_ADAPTIVE_BATCH_CONFIG as unknown as Record<string, number>)[field]);
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warnEntries()[0]).toMatchObject({ level: 'warn', envVar: key, raw });
  });
});

describe('sampleSorobanFeeStats', () => {
  it('uses p50 as the fee and the (p90 - p10) / p50 coefficient of variation', async () => {
    const { server } = feeServer('100', '200', '400');

    const sample = await sampleSorobanFeeStats(server);

    expect(sample.fee).toBe(200);
    expect(sample.volatility).toBeCloseTo(1.5, 10);
    expect(sample.raw.sorobanInclusionFee.p50).toBe('200');
  });

  it('reports zero volatility when the distribution is flat', async () => {
    const sample = await sampleSorobanFeeStats(feeServer('250', '250', '250').server);

    expect(sample.fee).toBe(250);
    expect(sample.volatility).toBe(0);
  });

  it('reports zero volatility when p50 is zero (division guard)', async () => {
    const sample = await sampleSorobanFeeStats(feeServer('0', '0', '0').server);

    expect(sample.fee).toBe(0);
    expect(sample.volatility).toBe(0);
  });

  it('reports zero volatility when p90 is zero', async () => {
    const sample = await sampleSorobanFeeStats(feeServer('0', '100', '0').server);

    expect(sample.fee).toBe(100);
    expect(sample.volatility).toBe(0);
  });

  it('still reports volatility below 1 for a narrow distribution', async () => {
    const sample = await sampleSorobanFeeStats(feeServer('95', '100', '105').server);

    expect(sample.volatility).toBeCloseTo(0.1, 10);
  });
});

describe('AdaptiveBatchSizeController - initial state', () => {
  it('starts at maxBatchSize with no samples', () => {
    const c = controller();

    expect(c.getBatchSize()).toBe(DEFAULT_ADAPTIVE_BATCH_CONFIG.maxBatchSize);
    expect(c.getEwmaFee()).toBeNull();
    expect(c.getSampleCount()).toBe(0);
  });

  it('honours a custom boundary pair', () => {
    const c = controller({ minBatchSize: 10, maxBatchSize: 20 });

    expect(c.getBatchSize()).toBe(20);
    expect(c.getConfig()).toMatchObject({ minBatchSize: 10, maxBatchSize: 20 });
  });

  it('hands out a copy of its config', () => {
    const c = controller();
    const snapshot = c.getConfig();
    snapshot.maxBatchSize = 1;

    expect(c.getConfig().maxBatchSize).toBe(DEFAULT_ADAPTIVE_BATCH_CONFIG.maxBatchSize);
  });
});

describe('AdaptiveBatchSizeController - tune() input guards', () => {
  it.each([
    ['zero', 0],
    ['negative', -1],
    ['NaN', Number.NaN],
    ['Infinity', Number.POSITIVE_INFINITY],
    ['-Infinity', Number.NEGATIVE_INFINITY],
  ])('ignores a %s fee sample and counts nothing', (_label, fee) => {
    const c = controller();

    c.tune(fee, 0);

    expect(c.getEwmaFee()).toBeNull();
    expect(c.getSampleCount()).toBe(0);
    expect(c.getBatchSize()).toBe(DEFAULT_ADAPTIVE_BATCH_CONFIG.maxBatchSize);
    expect(warnEntries().some((e) => e['message'] === 'adaptive-batch: invalid fee sample, skipping tune')).toBe(true);
  });

  it('keeps the previous batch size after a rejected sample', () => {
    const c = controller({ minBatchSize: 1, maxBatchSize: 100, volatilityDampening: 0 });

    c.tune(100, 0);
    c.tune(160, 0); // expensive → shrink
    const tuned = c.getBatchSize();
    expect(tuned).toBeLessThan(100);

    c.tune(0, 0);

    expect(c.getBatchSize()).toBe(tuned);
    expect(c.getSampleCount()).toBe(2);
  });
});

describe('AdaptiveBatchSizeController - EWMA seeding and spike protection', () => {
  it('seeds the EWMA with the first sample and leaves the size unchanged (ratio 1)', () => {
    const c = controller({ volatilityDampening: 0 });

    c.tune(120, 0);

    expect(c.getEwmaFee()).toBe(120);
    expect(c.getSampleCount()).toBe(1);
    expect(c.getBatchSize()).toBe(DEFAULT_ADAPTIVE_BATCH_CONFIG.maxBatchSize);
  });

  it('smooths subsequent samples with the configured alpha', () => {
    const c = controller({ ewmaAlpha: 0.5, volatilityDampening: 1 });

    c.tune(100, 0);
    c.tune(200, 0);

    // 0.5 * 200 + 0.5 * 100
    expect(c.getEwmaFee()).toBe(150);
  });

  it('drops to minBatchSize when the fee ratio exceeds the spike multiplier', () => {
    const c = controller({ feeSpikeMultiplier: 2, minBatchSize: 3, maxBatchSize: 100 });

    c.tune(100, 0);
    c.tune(100 * 2.01, 0);

    expect(c.getBatchSize()).toBe(3);
    expect(warnEntries().some((e) => e['message'] === 'adaptive-batch: fee spike detected, reducing batch size to minimum')).toBe(true);
  });

  it('does not treat a ratio exactly at the multiplier as a spike (strict comparison)', () => {
    const c = controller({ feeSpikeMultiplier: 2, minBatchSize: 1, maxBatchSize: 100, volatilityDampening: 0 });

    c.tune(100, 0);
    c.tune(200, 0); // ratio === 2 exactly

    expect(c.getBatchSize()).toBeGreaterThan(1);
  });
});

describe('AdaptiveBatchSizeController - clamping', () => {
  it('never grows past maxBatchSize', () => {
    const c = controller({ minBatchSize: 1, maxBatchSize: 100, sensitivity: 2, volatilityDampening: 0 });

    c.tune(100, 0);
    c.tune(1, 0); // very cheap → large scale factor

    expect(c.getBatchSize()).toBe(100);
  });

  it('never shrinks below minBatchSize', () => {
    const c = controller({ minBatchSize: 50, maxBatchSize: 100, sensitivity: 2, volatilityDampening: 0 });

    c.tune(100, 0);
    c.tune(160, 0); // rawScale becomes negative → clamped up to the floor

    expect(c.getBatchSize()).toBe(50);
  });

  it('always reports an integer batch size', () => {
    const c = controller({ minBatchSize: 3, maxBatchSize: 100, volatilityDampening: 0 });

    c.tune(100, 0);
    c.tune(140, 0);

    expect(Number.isInteger(c.getBatchSize())).toBe(true);
  });
});

describe('AdaptiveBatchSizeController - volatility dampening', () => {
  it('adjusts fully when volatility is zero and barely when it saturates', () => {
    const calm = controller({ volatilityDampening: 1, sensitivity: 1 });
    const wild = controller({ volatilityDampening: 1, sensitivity: 1 });

    calm.tune(100, 0);
    wild.tune(100, 0);
    calm.tune(150, 0);
    wild.tune(150, 1.5); // volatility is clamped to 1 before use

    expect(calm.getBatchSize()).toBeLessThan(100);
    expect(wild.getBatchSize()).toBe(100);
  });

  it('treats a negative volatility as no dampening', () => {
    const c = controller({ volatilityDampening: 0.5, sensitivity: 1 });

    c.tune(100, 0);
    c.tune(150, -1);

    expect(c.getBatchSize()).toBeLessThan(100);
  });
});

describe('AdaptiveBatchSizeController - reset()', () => {
  it('restores every field to its initial value', () => {
    const c = controller({ minBatchSize: 2, maxBatchSize: 40 });

    c.tune(100, 0);
    c.tune(500, 0);
    c.reset();

    expect(c.getBatchSize()).toBe(40);
    expect(c.getEwmaFee()).toBeNull();
    expect(c.getSampleCount()).toBe(0);
  });

  it('re-seeds the EWMA after a reset', () => {
    const c = controller();

    c.tune(100, 0);
    c.reset();
    c.tune(999, 0);

    expect(c.getEwmaFee()).toBe(999);
    expect(c.getSampleCount()).toBe(1);
  });
});

describe('AdaptiveBatchSizeController - sampleIntervalMs throttle', () => {
  it('samples once, throttles until the interval elapses, then samples again', async () => {
    const c = controller({ sampleIntervalMs: 1_000, minBatchSize: 1, maxBatchSize: 100 });
    const { server } = feeServer('100', '200', '400');
    const now = vi.spyOn(Date, 'now');

    now.mockReturnValue(10_000);
    expect(await c.sampleAndTune(server)).toBe(true);
    expect(c.getSampleCount()).toBe(1);
    expect(c.getEwmaFee()).toBe(200);

    now.mockReturnValue(10_999);
    expect(await c.sampleAndTune(server)).toBe(false);
    expect(c.getSampleCount()).toBe(1);
    expect(server.getFeeStats).toHaveBeenCalledTimes(1);

    now.mockReturnValue(11_000);
    expect(await c.sampleAndTune(server)).toBe(true);
    expect(c.getSampleCount()).toBe(2);
    expect(server.getFeeStats).toHaveBeenCalledTimes(2);

    now.mockRestore();
  });

  it('samples on every call when the interval is zero', async () => {
    const c = controller({ sampleIntervalMs: 0, minBatchSize: 1, maxBatchSize: 100 });
    const { server } = feeServer('10', '20', '30');

    expect(await c.sampleAndTune(server)).toBe(true);
    expect(await c.sampleAndTune(server)).toBe(true);

    expect(c.getSampleCount()).toBe(2);
    expect(c.getEwmaFee()).toBe(20);
  });

  it('does not advance the throttle clock when the RPC call fails', async () => {
    const c = controller({ sampleIntervalMs: 60_000 });
    const failing = {
      getFeeStats: vi.fn(async () => {
        throw new Error('rpc unavailable');
      }),
    } as unknown as rpc.Server;
    const now = vi.spyOn(Date, 'now').mockReturnValue(60_000);

    await expect(c.sampleAndTune(failing)).rejects.toThrow('rpc unavailable');
    expect(c.getSampleCount()).toBe(0);

    // The failed attempt must not count as a sample, so a healthy server can
    // still be queried immediately.
    const { server } = feeServer('100', '200', '400');
    expect(await c.sampleAndTune(server)).toBe(true);

    now.mockRestore();
  });
});
