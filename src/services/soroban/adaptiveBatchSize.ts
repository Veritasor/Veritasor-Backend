import { rpc } from '@stellar/stellar-sdk';
import { logger } from '../../utils/logger.js';

/**
 * Configuration for the adaptive batch-size controller.
 * All fields have safe defaults and can be overridden via env vars.
 */
export type AdaptiveBatchConfig = {
  /** Minimum batch size (inclusive). */
  minBatchSize: number;
  /** Maximum batch size (inclusive). */
  maxBatchSize: number;
  /** EWMA smoothing factor (0 < alpha <= 1). Higher = more responsive. */
  ewmaAlpha: number;
  /**
   * Fee ratio threshold for spike protection.
   * If currentFee / ewmaFee exceeds this, batch size drops to min.
   */
  feeSpikeMultiplier: number;
  /**
   * How aggressively the controller adjusts batch size in response
   * to fee deviations. Higher = more aggressive.
   */
  sensitivity: number;
  /**
   * How much fee volatility dampens the adjustment (0 = no dampening,
   * 1 = full dampening).
   */
  volatilityDampening: number;
  /**
   * Minimum interval (ms) between fee samples to avoid hammering the RPC.
   */
  sampleIntervalMs: number;
};

export const DEFAULT_ADAPTIVE_BATCH_CONFIG: AdaptiveBatchConfig = {
  minBatchSize: 1,
  maxBatchSize: 100,
  ewmaAlpha: 0.3,
  feeSpikeMultiplier: 2.0,
  sensitivity: 0.5,
  volatilityDampening: 0.5,
  sampleIntervalMs: 60_000,
};

/**
 * Resolves adaptive batch config from environment variables with fallback
 * to sensible defaults.
 */
export function getAdaptiveBatchConfig(
  overrides?: Partial<AdaptiveBatchConfig>,
): AdaptiveBatchConfig {
  const fromEnv: AdaptiveBatchConfig = {
    minBatchSize: parsePositiveIntEnv(
      'SOROBAN_ADAPTIVE_BATCH_MIN_SIZE',
      DEFAULT_ADAPTIVE_BATCH_CONFIG.minBatchSize,
    ),
    maxBatchSize: parsePositiveIntEnv(
      'SOROBAN_ADAPTIVE_BATCH_MAX_SIZE',
      DEFAULT_ADAPTIVE_BATCH_CONFIG.maxBatchSize,
    ),
    ewmaAlpha: parseDecimalEnv(
      'SOROBAN_ADAPTIVE_BATCH_EWMA_ALPHA',
      DEFAULT_ADAPTIVE_BATCH_CONFIG.ewmaAlpha,
      0.01,
      1.0,
    ),
    feeSpikeMultiplier: parseDecimalEnv(
      'SOROBAN_ADAPTIVE_BATCH_SPIKE_MULTIPLIER',
      DEFAULT_ADAPTIVE_BATCH_CONFIG.feeSpikeMultiplier,
      1.0,
      10.0,
    ),
    sensitivity: parseDecimalEnv(
      'SOROBAN_ADAPTIVE_BATCH_SENSITIVITY',
      DEFAULT_ADAPTIVE_BATCH_CONFIG.sensitivity,
      0.01,
      2.0,
    ),
    volatilityDampening: parseDecimalEnv(
      'SOROBAN_ADAPTIVE_BATCH_VOLATILITY_DAMPENING',
      DEFAULT_ADAPTIVE_BATCH_CONFIG.volatilityDampening,
      0.0,
      1.0,
    ),
    sampleIntervalMs: parsePositiveIntEnv(
      'SOROBAN_ADAPTIVE_BATCH_SAMPLE_INTERVAL_MS',
      DEFAULT_ADAPTIVE_BATCH_CONFIG.sampleIntervalMs,
    ),
  };

  return { ...fromEnv, ...overrides };
}

function parsePositiveIntEnv(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined) return fallback;
  const val = Number.parseInt(raw.trim(), 10);
  if (!Number.isInteger(val) || val <= 0) {
    logger.warn({ envVar: name, raw }, `Invalid positive integer env ${name}, using fallback`);
    return fallback;
  }
  return val;
}

function parseDecimalEnv(name: string, fallback: number, min: number, max: number): number {
  const raw = process.env[name];
  if (raw === undefined) return fallback;
  const val = Number(raw);
  if (!Number.isFinite(val) || val < min || val > max) {
    logger.warn({ envVar: name, raw, min, max }, `Invalid decimal env ${name}, using fallback`);
    return fallback;
  }
  return val;
}

/**
 * Result from sampling Soroban network fee stats.
 */
export type FeeSample = {
  /** Current fee level (p50 of sorobanInclusionFee). */
  fee: number;
  /** Coefficient of variation: (p90 - p10) / p50. */
  volatility: number;
  /** The raw GetFeeStatsResponse for auditability. */
  raw: rpc.Api.GetFeeStatsResponse;
};

/**
 * Samples fee statistics from a Soroban RPC server.
 *
 * Uses `getFeeStats` which returns percentile fee distributions for
 * both standard and Soroban inclusion fees. We track the Soroban-specific
 * fee distribution.
 */
export async function sampleSorobanFeeStats(
  server: rpc.Server,
): Promise<FeeSample> {
  const raw = await server.getFeeStats();

  const dist = raw.sorobanInclusionFee;
  const p10 = Number(dist.p10);
  const p50 = Number(dist.p50);
  const p90 = Number(dist.p90);
  const fee = p50;

  // Coefficient of variation: (p90 - p10) / p50
  // Measures fee dispersion. Higher = more volatile.
  let volatility = 0;
  if (fee > 0 && p90 > 0 && p10 >= 0) {
    volatility = (p90 - p10) / fee;
  }

  return { fee, volatility, raw };
}

/**
 * EWMA-tuned adaptive batch-size controller.
 *
 * Samples Soroban network fee statistics and adjusts a batch size
 * within configured bounds. Uses an Exponentially Weighted Moving
 * Average to smooth fee observations and reacts to deviations.
 *
 * **Spike protection:** when currentFee / ewmaFee exceeds the spike
 * multiplier, the batch size is immediately dropped to the configured
 * minimum.
 *
 * Thread-safe for single-writer / multiple-reader usage (the typical
 * Node.js single-threaded model).
 */
export class AdaptiveBatchSizeController {
  private ewmaFee: number | null = null;
  private currentBatchSize: number;
  private lastSampleTime = 0;
  private readonly config: AdaptiveBatchConfig;
  private feeSampleCount = 0;

  constructor(config?: Partial<AdaptiveBatchConfig>) {
    this.config = getAdaptiveBatchConfig(config);
    this.currentBatchSize = this.config.maxBatchSize;
  }

  /** Returns the currently tuned batch size. */
  getBatchSize(): number {
    return this.currentBatchSize;
  }

  /** Returns the current EWMA fee, or null if no samples yet. */
  getEwmaFee(): number | null {
    return this.ewmaFee;
  }

  /** Returns how many fee samples have been taken. */
  getSampleCount(): number {
    return this.feeSampleCount;
  }

  /** Returns the active config. */
  getConfig(): AdaptiveBatchConfig {
    return { ...this.config };
  }

  /**
   * Samples fee stats from the Soroban RPC server and tunes the batch
   * size accordingly. If `sampleIntervalMs` has not elapsed since the
   * last sample, the call is a no-op and returns false.
   *
   * @returns true if a new sample was taken, false if it was skipped
   *          (throttle).
   */
  async sampleAndTune(server: rpc.Server): Promise<boolean> {
    const now = Date.now();
    if (now - this.lastSampleTime < this.config.sampleIntervalMs) {
      return false;
    }

    const { fee, volatility } = await sampleSorobanFeeStats(server);
    this.lastSampleTime = now;
    this.tune(fee, volatility);
    return true;
  }

  /**
   * Updates the EWMA and adjusts the batch size based on the given fee
   * and volatility.
   */
  tune(fee: number, volatility: number): void {
    if (!Number.isFinite(fee) || fee <= 0) {
      logger.warn({ fee }, 'adaptive-batch: invalid fee sample, skipping tune');
      return;
    }

    // Capture previous EWMA before updating — the ratio must reflect
    // deviation from the *prior* smoothed value, not the updated one,
    // otherwise a single high fee sample partially resets the baseline
    // and dilutes the spike signal.
    const prevEwma = this.ewmaFee;

    // Update EWMA
    if (this.ewmaFee === null) {
      this.ewmaFee = fee;
    } else {
      this.ewmaFee =
        this.config.ewmaAlpha * fee +
        (1 - this.config.ewmaAlpha) * this.ewmaFee;
    }
    this.feeSampleCount++;

    const baseline = prevEwma ?? fee;
    const ratio = fee / baseline;

    // Spike protection: if fee is way above the EWMA, drop to minimum
    if (ratio > this.config.feeSpikeMultiplier) {
      logger.warn(
        {
          fee,
          ewmaFee: this.ewmaFee,
          ratio,
          spikeMultiplier: this.config.feeSpikeMultiplier,
        },
        'adaptive-batch: fee spike detected, reducing batch size to minimum',
      );
      this.currentBatchSize = this.config.minBatchSize;
      return;
    }

    // Compute target scale factor.
    // When ratio < 1 (cheap), scale > 1 → increase batch size.
    // When ratio > 1 (expensive), scale < 1 → decrease batch size.
    const rawScale = 1 + (1 - ratio) * this.config.sensitivity;

    // Dampen the adjustment by volatility.
    // High volatility → more dampening → smaller adjustment.
    const dampening = 1 - this.config.volatilityDampening * Math.min(volatility, 1);
    const adjustedScale = 1 + (rawScale - 1) * dampening;

    const newSize = Math.round(this.currentBatchSize * adjustedScale);
    this.currentBatchSize = Math.max(
      this.config.minBatchSize,
      Math.min(this.config.maxBatchSize, newSize),
    );
  }

  /** Resets the controller to its initial state. */
  reset(): void {
    this.ewmaFee = null;
    this.currentBatchSize = this.config.maxBatchSize;
    this.lastSampleTime = 0;
    this.feeSampleCount = 0;
  }
}
