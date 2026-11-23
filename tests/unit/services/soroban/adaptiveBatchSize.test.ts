import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  AdaptiveBatchSizeController,
  sampleSorobanFeeStats,
  getAdaptiveBatchConfig,
  DEFAULT_ADAPTIVE_BATCH_CONFIG,
} from '../../../../src/services/soroban/adaptiveBatchSize.js';
import type { FeeSample } from '../../../../src/services/soroban/adaptiveBatchSize.js';
import { rpc } from '@stellar/stellar-sdk';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function mockFeeStatsResponse(overrides?: Partial<rpc.Api.GetFeeStatsResponse>): rpc.Api.GetFeeStatsResponse {
  return {
    latestLedger: 100,
    sorobanInclusionFee: {
      max: '10000',
      min: '100',
      mode: '500',
      p10: '200',
      p20: '250',
      p30: '300',
      p40: '350',
      p50: '500',
      p60: '600',
      p70: '700',
      p80: '800',
      p90: '1000',
      p95: '2000',
      p99: '5000',
      transactionCount: '100',
    },
    inclusionFee: {
      max: '10000',
      min: '100',
      mode: '500',
      p10: '200',
      p20: '250',
      p30: '300',
      p40: '350',
      p50: '500',
      p60: '600',
      p70: '700',
      p80: '800',
      p90: '1000',
      p95: '2000',
      p99: '5000',
      transactionCount: '100',
    },
    ...overrides,
  };
}

function mockServer(feeStatsResponse?: rpc.Api.GetFeeStatsResponse) {
  return {
    getFeeStats: vi.fn().mockResolvedValue(feeStatsResponse ?? mockFeeStatsResponse()),
  } as unknown as rpc.Server;
}

// ---------------------------------------------------------------------------
// getAdaptiveBatchConfig
// ---------------------------------------------------------------------------

describe('getAdaptiveBatchConfig', () => {
  const OLD_ENV = process.env;

  beforeEach(() => {
    process.env = { ...OLD_ENV };
  });

  afterEach(() => {
    process.env = OLD_ENV;
  });

  it('returns defaults when no env vars are set', () => {
    const config = getAdaptiveBatchConfig();
    expect(config).toEqual(DEFAULT_ADAPTIVE_BATCH_CONFIG);
  });

  it('reads min batch size from env', () => {
    process.env.SOROBAN_ADAPTIVE_BATCH_MIN_SIZE = '5';
    expect(getAdaptiveBatchConfig().minBatchSize).toBe(5);
  });

  it('reads max batch size from env', () => {
    process.env.SOROBAN_ADAPTIVE_BATCH_MAX_SIZE = '200';
    expect(getAdaptiveBatchConfig().maxBatchSize).toBe(200);
  });

  it('reads ewma alpha from env', () => {
    process.env.SOROBAN_ADAPTIVE_BATCH_EWMA_ALPHA = '0.1';
    expect(getAdaptiveBatchConfig().ewmaAlpha).toBeCloseTo(0.1);
  });

  it('reads spike multiplier from env', () => {
    process.env.SOROBAN_ADAPTIVE_BATCH_SPIKE_MULTIPLIER = '3.5';
    expect(getAdaptiveBatchConfig().feeSpikeMultiplier).toBeCloseTo(3.5);
  });

  it('reads sensitivity from env', () => {
    process.env.SOROBAN_ADAPTIVE_BATCH_SENSITIVITY = '1.0';
    expect(getAdaptiveBatchConfig().sensitivity).toBeCloseTo(1.0);
  });

  it('reads volatility dampening from env', () => {
    process.env.SOROBAN_ADAPTIVE_BATCH_VOLATILITY_DAMPENING = '0.8';
    expect(getAdaptiveBatchConfig().volatilityDampening).toBeCloseTo(0.8);
  });

  it('reads sample interval from env', () => {
    process.env.SOROBAN_ADAPTIVE_BATCH_SAMPLE_INTERVAL_MS = '30000';
    expect(getAdaptiveBatchConfig().sampleIntervalMs).toBe(30000);
  });

  it('falls back to defaults for invalid env values', () => {
    process.env.SOROBAN_ADAPTIVE_BATCH_MIN_SIZE = 'not-a-number';
    process.env.SOROBAN_ADAPTIVE_BATCH_EWMA_ALPHA = '99';
    const config = getAdaptiveBatchConfig();
    expect(config.minBatchSize).toBe(DEFAULT_ADAPTIVE_BATCH_CONFIG.minBatchSize);
    expect(config.ewmaAlpha).toBe(DEFAULT_ADAPTIVE_BATCH_CONFIG.ewmaAlpha);
  });

  it('merges overrides with env-derived config', () => {
    process.env.SOROBAN_ADAPTIVE_BATCH_MIN_SIZE = '5';
    const config = getAdaptiveBatchConfig({ maxBatchSize: 300 });
    expect(config.minBatchSize).toBe(5);
    expect(config.maxBatchSize).toBe(300);
  });
});

// ---------------------------------------------------------------------------
// sampleSorobanFeeStats
// ---------------------------------------------------------------------------

describe('sampleSorobanFeeStats', () => {
  it('extracts fee and volatility from getFeeStats response', async () => {
    const server = mockServer();
    const result = await sampleSorobanFeeStats(server);
    expect(result.fee).toBe(500);
    expect(result.volatility).toBeCloseTo((1000 - 200) / 500);
    expect(result.raw).toBeDefined();
  });

  it('computes zero volatility when p90 equals p10', async () => {
    const server = mockServer({
      sorobanInclusionFee: {
        ...mockFeeStatsResponse().sorobanInclusionFee,
        p10: '500',
        p90: '500',
        p50: '500',
      },
    });
    const result = await sampleSorobanFeeStats(server);
    expect(result.volatility).toBe(0);
  });

  it('computes zero volatility when p50 is zero', async () => {
    const server = mockServer({
      sorobanInclusionFee: {
        ...mockFeeStatsResponse().sorobanInclusionFee,
        p10: '0',
        p50: '0',
        p90: '100',
      },
    });
    const result = await sampleSorobanFeeStats(server);
    expect(result.volatility).toBe(0);
  });

  it('throws when getFeeStats fails', async () => {
    const server = {
      getFeeStats: vi.fn().mockRejectedValue(new Error('RPC error')),
    } as unknown as rpc.Server;
    await expect(sampleSorobanFeeStats(server)).rejects.toThrow('RPC error');
  });
});

// ---------------------------------------------------------------------------
// AdaptiveBatchSizeController - Construction
// ---------------------------------------------------------------------------

describe('AdaptiveBatchSizeController', () => {
  describe('construction', () => {
    it('starts with batch size equal to max', () => {
      const ctrl = new AdaptiveBatchSizeController({ minBatchSize: 1, maxBatchSize: 50 });
      expect(ctrl.getBatchSize()).toBe(50);
    });

    it('initialises with null EWMA fee', () => {
      const ctrl = new AdaptiveBatchSizeController();
      expect(ctrl.getEwmaFee()).toBeNull();
    });

    it('initialises with zero sample count', () => {
      const ctrl = new AdaptiveBatchSizeController();
      expect(ctrl.getSampleCount()).toBe(0);
    });

    it('accepts partial config overrides', () => {
      const ctrl = new AdaptiveBatchSizeController({ minBatchSize: 5 });
      expect(ctrl.getConfig().minBatchSize).toBe(5);
      expect(ctrl.getConfig().maxBatchSize).toBe(DEFAULT_ADAPTIVE_BATCH_CONFIG.maxBatchSize);
    });
  });

  // -----------------------------------------------------------------------
  // tune
  // -----------------------------------------------------------------------

  describe('tune', () => {
    it('ignores non-finite fee values', () => {
      const ctrl = new AdaptiveBatchSizeController();
      const original = ctrl.getBatchSize();
      ctrl.tune(NaN, 0);
      expect(ctrl.getBatchSize()).toBe(original);
      ctrl.tune(Infinity, 0);
      expect(ctrl.getBatchSize()).toBe(original);
      ctrl.tune(-1, 0);
      expect(ctrl.getBatchSize()).toBe(original);
    });

    it('initialises EWMA on first valid sample', () => {
      const ctrl = new AdaptiveBatchSizeController();
      ctrl.tune(500, 0);
      expect(ctrl.getEwmaFee()).toBe(500);
      expect(ctrl.getSampleCount()).toBe(1);
    });

    it('updates EWMA with subsequent samples', () => {
      const ctrl = new AdaptiveBatchSizeController({ ewmaAlpha: 0.5 });
      ctrl.tune(500, 0);  // ewma = 500
      ctrl.tune(100, 0);  // ewma = 0.5*100 + 0.5*500 = 300
      expect(ctrl.getEwmaFee()).toBe(300);
      expect(ctrl.getSampleCount()).toBe(2);
    });

    it('decreases batch size when fee is above EWMA', () => {
      const ctrl = new AdaptiveBatchSizeController({
        minBatchSize: 1,
        maxBatchSize: 100,
        ewmaAlpha: 0.5,
        sensitivity: 1.0,
        volatilityDampening: 0,
      });
      // First sample initialises EWMA to 100
      ctrl.tune(100, 0);
      expect(ctrl.getBatchSize()).toBe(100);

      // Fee increases to 200 → ratio = 2 → rawScale = 1 + (1-2)*1 = 0
      // So batch size should drop
      ctrl.tune(200, 0);
      expect(ctrl.getBatchSize()).toBeLessThan(100);
    });

    it('increases batch size when fee is below EWMA', () => {
      const ctrl = new AdaptiveBatchSizeController({
        minBatchSize: 1,
        maxBatchSize: 500,
        ewmaAlpha: 0.5,
        sensitivity: 0.5,
        volatilityDampening: 0,
      });
      // First tune initialises EWMA at a high fee
      ctrl.tune(1000, 0);
      const afterFirst = ctrl.getBatchSize();
      // Fee hasn't deviated from EWMA yet, so batch should be at max
      expect(afterFirst).toBe(500);

      // Now fee drops well below the EWMA (100 vs 1000)
      ctrl.tune(100, 0);
      // EWMA = 0.5*100 + 0.5*1000 = 550
      // prev EWMA = 1000, ratio = 100/1000 = 0.1
      // rawScale = 1 + (1-0.1)*0.5 = 1.45
      // newSize = round(500 * 1.45) = 725 → clamped to 500
      // It's already at max (500) so it stays there
      // Let's instead set up so batch can grow

      const growingCtrl = new AdaptiveBatchSizeController({
        minBatchSize: 10,
        maxBatchSize: 500,
        ewmaAlpha: 0.5,
        sensitivity: 0.5,
        volatilityDampening: 0,
      });
      // Drive the batch size down first
      growingCtrl.tune(100, 0);
      growingCtrl.tune(200, 0); // fee above EWMA → batch shrinks
      growingCtrl.tune(300, 0); // fee above EWMA → batch shrinks more
      const shrunkSize = growingCtrl.getBatchSize();
      expect(shrunkSize).toBeLessThan(500);

      // Now fee drops below the EWMA → batch should grow
      growingCtrl.tune(50, 0);
      const newSize = growingCtrl.getBatchSize();
      expect(newSize).toBeGreaterThan(shrunkSize);
      expect(newSize).toBeLessThanOrEqual(500);
    });

    it('clamps batch size between min and max', () => {
      const ctrl = new AdaptiveBatchSizeController({
        minBatchSize: 10,
        maxBatchSize: 50,
        ewmaAlpha: 0.5,
        sensitivity: 2.0,
        volatilityDampening: 0,
      });
      ctrl.tune(100, 0);  // initialise EWMA
      // Fee much higher → should try to go below min
      ctrl.tune(10000, 0);
      expect(ctrl.getBatchSize()).toBe(10);  // clamps to min
    });

    it('applies spike protection when ratio exceeds spikeMultiplier', () => {
      const ctrl = new AdaptiveBatchSizeController({
        minBatchSize: 5,
        maxBatchSize: 100,
        ewmaAlpha: 0.5,
        feeSpikeMultiplier: 2.0,
      });
      ctrl.tune(100, 0);  // initialise EWMA = 100
      // Fee spikes to 300 → ratio = 3 > 2 → spike protection
      ctrl.tune(300, 0);
      expect(ctrl.getBatchSize()).toBe(5);
    });

    it('volatility dampens the adjustment magnitude', () => {
      const ctrlNoDamp = new AdaptiveBatchSizeController({
        minBatchSize: 1,
        maxBatchSize: 200,
        ewmaAlpha: 0.5,
        sensitivity: 1.0,
        volatilityDampening: 0,
      });
      const ctrlWithDamp = new AdaptiveBatchSizeController({
        minBatchSize: 1,
        maxBatchSize: 200,
        ewmaAlpha: 0.5,
        sensitivity: 1.0,
        volatilityDampening: 0.8,
      });

      // Initialise both the same way
      ctrlNoDamp.tune(100, 0);
      ctrlWithDamp.tune(100, 0);

      // Apply same fee change with volatility
      ctrlNoDamp.tune(200, 1.0);   // high volatility, no dampening
      ctrlWithDamp.tune(200, 1.0); // high volatility, dampened

      // The dampened controller should change less
      // Actually with volatilityDampening=0.8 and volatility=1.0,
      // the dampening factor is (1 - 0.8*min(1,1)) = 0.2
      // So ctrlWithDamp should be closer to the original
      expect(ctrlWithDamp.getBatchSize()).toBeGreaterThan(ctrlNoDamp.getBatchSize());
    });
  });

  // -----------------------------------------------------------------------
  // sampleAndTune
  // -----------------------------------------------------------------------

  describe('sampleAndTune', () => {
    it('samples fee stats and tunes batch size', async () => {
      const ctrl = new AdaptiveBatchSizeController({ sampleIntervalMs: 0 });
      const server = mockServer();
      const result = await ctrl.sampleAndTune(server);
      expect(result).toBe(true);
      expect(ctrl.getSampleCount()).toBe(1);
      expect(ctrl.getEwmaFee()).not.toBeNull();
    });

    it('respects sample interval throttle', async () => {
      const ctrl = new AdaptiveBatchSizeController({ sampleIntervalMs: 60_000 });
      const server = mockServer();

      // First call should sample
      const first = await ctrl.sampleAndTune(server);
      expect(first).toBe(true);
      expect(ctrl.getSampleCount()).toBe(1);

      // Second call immediately after should be throttled
      const second = await ctrl.sampleAndTune(server);
      expect(second).toBe(false);
      expect(ctrl.getSampleCount()).toBe(1);
    });

    it('samples again after interval has elapsed', async () => {
      vi.useFakeTimers();
      const ctrl = new AdaptiveBatchSizeController({ sampleIntervalMs: 10_000 });
      const server = mockServer();

      await ctrl.sampleAndTune(server);
      expect(ctrl.getSampleCount()).toBe(1);

      // Advance time past interval
      vi.advanceTimersByTime(10_001);
      const second = await ctrl.sampleAndTune(server);
      expect(second).toBe(true);
      expect(ctrl.getSampleCount()).toBe(2);

      vi.useRealTimers();
    });
  });

  // -----------------------------------------------------------------------
  // reset
  // -----------------------------------------------------------------------

  describe('reset', () => {
    it('resets EWMA fee, batch size, sample count, and last sample time', () => {
      const ctrl = new AdaptiveBatchSizeController({ minBatchSize: 1, maxBatchSize: 100 });
      ctrl.tune(500, 0);
      expect(ctrl.getSampleCount()).toBe(1);
      expect(ctrl.getEwmaFee()).toBe(500);

      ctrl.reset();
      expect(ctrl.getEwmaFee()).toBeNull();
      expect(ctrl.getBatchSize()).toBe(100);
      expect(ctrl.getSampleCount()).toBe(0);
    });
  });

  // -----------------------------------------------------------------------
  // getConfig
  // -----------------------------------------------------------------------

  describe('getConfig', () => {
    it('returns a copy of the config', () => {
      const ctrl = new AdaptiveBatchSizeController({ minBatchSize: 3 });
      const config = ctrl.getConfig();
      expect(config.minBatchSize).toBe(3);
      // Mutating the returned config should not affect the controller
      config.minBatchSize = 999;
      expect(ctrl.getConfig().minBatchSize).toBe(3);
    });
  });
});
