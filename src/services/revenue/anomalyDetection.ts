/**
 * Anomaly detection for monthly revenue series.
 *
 * Uses a simple month-over-month percentage change algorithm by default.
 * Calibration hooks allow callers to override thresholds or inject a custom
 * scoring function per consecutive pair, making it easy to swap in a real
 * model (z-score, IQR, Prophet) without touching the public API.
 *
 * ---------------------------------------------------------------------------
 * Operator Tuning — Environment Variables
 * ---------------------------------------------------------------------------
 *
 * All threshold defaults can be overridden at process start via environment
 * variables. Set them in your `.env` (or deployment config) before the
 * service boots; changes take effect on the next process restart.
 *
 * | Variable                          | Type   | Default | Description                                                    |
 * |-----------------------------------|--------|---------|----------------------------------------------------------------|
 * | ANOMALY_DROP_THRESHOLD            | float  | 0.4     | MoM fractional drop that triggers `unusual_drop` (e.g. 0.3 = 30%). |
 * | ANOMALY_SPIKE_THRESHOLD           | float  | 3.0     | MoM fractional rise that triggers `unusual_spike` (e.g. 2.0 = 200%). |
 * | ANOMALY_MIN_DATA_POINTS           | int    | 2       | Minimum series length required for detection.                  |
 * | ANOMALY_CALIBRATION_SIGMA         | float  | 2.0     | Std-dev multiplier used by `calibrateFromSeries`.              |
 *
 * Validation rules
 * - DROP_THRESHOLD  must be in (0, 1].  Values outside this range are ignored and the
 *   hard-coded default is used, with a warning logged to stderr.
 * - SPIKE_THRESHOLD must be > 0.        Same fallback behaviour.
 * - MIN_DATA_POINTS must be an integer ≥ 2.
 * - CALIBRATION_SIGMA must be > 0.
 *
 * Example `.env` entry:
 * ```
 * ANOMALY_DROP_THRESHOLD=0.30
 * ANOMALY_SPIKE_THRESHOLD=2.00
 * ANOMALY_MIN_DATA_POINTS=3
 * ANOMALY_CALIBRATION_SIGMA=2.5
 * ```
 *
 * ---------------------------------------------------------------------------
 * Failure Modes
 * ---------------------------------------------------------------------------
 *
 * | Condition                          | Behaviour                                                   |
 * |------------------------------------|-------------------------------------------------------------|
 * | Series length < minDataPoints      | Returns `{ flag: "insufficient_data", score: 0 }`. Never throws. |
 * | All previous-period amounts are 0  | Pairs with prev.amount === 0 are skipped silently.          |
 * | scoreHook throws                   | Exception propagates to the caller — wrap externally if needed. |
 * | Invalid env-var values             | Hard-coded defaults are used; warning emitted to stderr.    |
 *
 * ---------------------------------------------------------------------------
 * Seasonality & False-Positive Guidance
 * ---------------------------------------------------------------------------
 *
 * Month-over-month thresholds can fire spuriously for businesses with strong
 * seasonal patterns (e.g. e-commerce spikes in Q4, SaaS annual renewals).
 *
 * Mitigation strategies:
 * 1. **Use `calibrateFromSeries`** on ≥12 months of historical data so that
 *    thresholds are derived from your actual distribution (mean ± N·σ).
 * 2. **Raise `sigmaMultiplier`** (via `ANOMALY_CALIBRATION_SIGMA`) to widen
 *    the acceptable band — 2 is conservative; 3 reduces false positives at the
 *    cost of missing smaller anomalies.
 * 3. **Inject a `scoreHook`** that encodes business rules, e.g. suppress the
 *    spike flag during a known promotional period.
 * 4. **Missing baselines** (fewer than 2 training points): `calibrateFromSeries`
 *    falls back to module defaults automatically.
 *
 * ---------------------------------------------------------------------------
 * Security / Threat-Model Notes
 * ---------------------------------------------------------------------------
 *
 * • **Spike attacks** — an adversary submitting artificially inflated revenue
 *   figures to obscure a later drop will surface as `unusual_spike` first.
 *   Pair anomaly detection with source-level webhook signature verification so
 *   that only authenticated payloads reach this function.
 *
 * • **Replay attacks on baselines** — `calibrateFromSeries` is a pure function;
 *   it does not persist state. Callers are responsible for persisting and
 *   versioning `CalibrationResult` objects so that an attacker cannot force a
 *   recalibration with manipulated historical data.
 *
 * • **Env-var injection** — threshold env vars are read once at module load and
 *   validated strictly. An attacker who can write to the process environment
 *   before boot could widen thresholds; treat your deployment secrets accordingly.
 *
 * • **Log-injection** — the `detail` string in `AnomalyResult` and structured
 *   log payloads embed `period` and `amount` values from the input series. Ensure
 *   your log aggregator escapes or sanitises these fields before display.
 *
 * ---------------------------------------------------------------------------
 * Idempotency
 * ---------------------------------------------------------------------------
 *
 * Both `detectRevenueAnomaly` and `calibrateFromSeries` are **pure functions**:
 * same inputs always produce the same outputs, no side effects, no I/O. Safe to
 * call multiple times with the same series.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** A single data point in a monthly revenue series. */
export type MonthlyRevenue = {
	/** Period string, e.g. "2026-01". Chronological sort order must be ascending. */
	period: string;
	/** Total revenue for the period in major currency units. */
	amount: number;
};

export type AnomalyFlag =
	| "ok"                // no anomaly detected
	| "unusual_drop"      // revenue fell sharply vs prior period
	| "unusual_spike"     // revenue rose sharply vs prior period
	| "insufficient_data"; // not enough data points to make a judgement

export type AnomalyResult = {
	/** Normalised anomaly score: 0 = normal, 1 = highly anomalous. */
	score: number;
	flag: AnomalyFlag;
	/** Human-readable explanation. Useful for logs and future UI display. */
	detail: string;
};

// ---------------------------------------------------------------------------
// Calibration types
// ---------------------------------------------------------------------------

/**
 * Optional calibration parameters for `detectRevenueAnomaly`.
 *
 * All fields are optional — omitting a field falls back to the resolved
 * module default (hard-coded constant or env-var override).
 */
export type CalibrationConfig = {
	/**
	 * Month-over-month fractional drop that triggers `unusual_drop`.
	 * E.g. 0.3 = flag when revenue drops ≥ 30%.
	 * Default: ANOMALY_DROP_THRESHOLD env var, or 0.4.
	 */
	dropThreshold?: number;
	/**
	 * Month-over-month fractional rise that triggers `unusual_spike`.
	 * E.g. 2.0 = flag when revenue rises ≥ 200%.
	 * Default: ANOMALY_SPIKE_THRESHOLD env var, or 3.0.
	 */
	spikeThreshold?: number;
	/**
	 * Minimum number of data points required to attempt detection.
	 * Default: ANOMALY_MIN_DATA_POINTS env var, or 2.
	 */
	minDataPoints?: number;
	/**
	 * Optional per-pair score hook called for every consecutive `(prev, curr)`.
	 *
	 * - Return `{ score, flag }` to override built-in logic for that pair.
	 * - Return `null` to fall back to the built-in threshold comparison.
	 *
	 * `change` is the signed fractional MoM change: `(curr − prev) / prev`.
	 */
	scoreHook?: (
		prev: MonthlyRevenue,
		curr: MonthlyRevenue,
		change: number
	) => { score: number; flag: AnomalyFlag } | null;
};

/**
 * Statistical thresholds derived by `calibrateFromSeries`.
 * Can be spread directly into `CalibrationConfig`.
 */
export type CalibrationResult = {
	/** Calibrated drop threshold (fraction). */
	dropThreshold: number;
	/** Calibrated spike threshold (fraction). */
	spikeThreshold: number;
	/** Mean of all valid MoM changes in the training series. */
	mean: number;
	/** Population standard deviation of MoM changes in the training series. */
	stdDev: number;
};

// ---------------------------------------------------------------------------
// Structured log type
// ---------------------------------------------------------------------------

/**
 * Structured log record emitted by `detectRevenueAnomaly` when an anomaly
 * is found. Consume this in your log aggregator (e.g. Datadog, Loki) to
 * build alerts and dashboards.
 */
export type AnomalyLogRecord = {
	event: "anomaly_detected" | "anomaly_check_ok" | "anomaly_insufficient_data";
	flag: AnomalyFlag;
	score: number;
	detail: string;
	/** Thresholds that were active for this invocation. */
	thresholds: {
		drop: number;
		spike: number;
		minDataPoints: number;
	};
	/** ISO timestamp of the detection run. */
	detectedAt: string;
};

// ---------------------------------------------------------------------------
// Env-var resolved defaults
// ---------------------------------------------------------------------------

const _RAW_DROP    = process.env["ANOMALY_DROP_THRESHOLD"];
const _RAW_SPIKE   = process.env["ANOMALY_SPIKE_THRESHOLD"];
const _RAW_MIN     = process.env["ANOMALY_MIN_DATA_POINTS"];
const _RAW_SIGMA   = process.env["ANOMALY_CALIBRATION_SIGMA"];

/** Parse and validate a float env var; fall back to `fallback` with a warning. */
function resolveFloatEnv(
	raw: string | undefined,
	name: string,
	fallback: number,
	validate: (v: number) => boolean
): number {
	if (raw === undefined || raw.trim() === "") return fallback;
	const parsed = parseFloat(raw);
	if (isNaN(parsed) || !validate(parsed)) {
		process.stderr.write(
			`[anomalyDetection] WARNING: ${name}="${raw}" is invalid — using default ${fallback}\n`
		);
		return fallback;
	}
	return parsed;
}

function resolveIntEnv(
	raw: string | undefined,
	name: string,
	fallback: number,
	validate: (v: number) => boolean
): number {
	if (raw === undefined || raw.trim() === "") return fallback;
	const parsed = parseInt(raw, 10);
	if (isNaN(parsed) || !validate(parsed)) {
		process.stderr.write(
			`[anomalyDetection] WARNING: ${name}="${raw}" is invalid — using default ${fallback}\n`
		);
		return fallback;
	}
	return parsed;
}

const DROP_THRESHOLD        = resolveFloatEnv(_RAW_DROP,  "ANOMALY_DROP_THRESHOLD",  0.4, (v) => v > 0 && v <= 1);
const SPIKE_THRESHOLD       = resolveFloatEnv(_RAW_SPIKE, "ANOMALY_SPIKE_THRESHOLD", 3.0, (v) => v > 0);
const MIN_DATA_POINTS       = resolveIntEnv  (_RAW_MIN,   "ANOMALY_MIN_DATA_POINTS", 2,   (v) => Number.isInteger(v) && v >= 2);
const DEFAULT_SIGMA_MULTIPLIER = resolveFloatEnv(_RAW_SIGMA, "ANOMALY_CALIBRATION_SIGMA", 2, (v) => v > 0);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Analyse a monthly revenue series and return an anomaly score and flag.
 *
 * The series is expected to be sorted in ascending chronological order
 * (earliest period first). If it is not sorted the function sorts it
 * internally by the `period` string, which works correctly for ISO
 * year-month strings (`"YYYY-MM"`).
 *
 * @param series       Array of `{ period, amount }` data points.
 * @param calibration  Optional calibration config to override defaults or
 *                     inject a custom score hook.
 * @param logger       Optional structured-log callback. Receives an
 *                     `AnomalyLogRecord` for every invocation. Wire this to
 *                     your application logger (e.g. `pino`, `winston`) to get
 *                     observable, queryable anomaly events.
 * @returns            `AnomalyResult` with `score`, `flag`, and `detail`.
 *
 * @example
 * // Default usage
 * const result = detectRevenueAnomaly([
 *   { period: '2026-01', amount: 10_000 },
 *   { period: '2026-02', amount: 10_500 },
 *   { period: '2026-03', amount: 3_000 },
 * ]);
 * // → { score: 0.7, flag: 'unusual_drop', detail: '...' }
 *
 * @example
 * // With calibrated thresholds from historical data
 * const cal = calibrateFromSeries(historicalSeries);
 * const result = detectRevenueAnomaly(currentSeries, cal);
 *
 * @example
 * // With structured logging (e.g. pino)
 * const result = detectRevenueAnomaly(series, {}, (record) => {
 *   logger.info(record);
 * });
 */
export function detectRevenueAnomaly(
	series: MonthlyRevenue[],
	calibration: CalibrationConfig = {},
	logger?: (record: AnomalyLogRecord) => void
): AnomalyResult {
	const minDataPoints = calibration.minDataPoints ?? MIN_DATA_POINTS;
	const activeDropThreshold  = calibration.dropThreshold  ?? DROP_THRESHOLD;
	const activeSpikeThreshold = calibration.spikeThreshold ?? SPIKE_THRESHOLD;

	if (!series || series.length < minDataPoints) {
		const result: AnomalyResult = {
			score: 0,
			flag: "insufficient_data",
			detail: `Need at least ${minDataPoints} data points; received ${series?.length ?? 0}.`,
		};
		logger?.({
			event: "anomaly_insufficient_data",
			flag: result.flag,
			score: result.score,
			detail: result.detail,
			thresholds: { drop: activeDropThreshold, spike: activeSpikeThreshold, minDataPoints },
			detectedAt: new Date().toISOString(),
		});
		return result;
	}

	// Sort ascending by period string (works for "YYYY-MM" and "YYYY-QN").
	const sorted = [...series].sort((a, b) => a.period.localeCompare(b.period));

	const result = scoreSeriesAnomaly(sorted, calibration);

	logger?.({
		event: result.flag === "ok" ? "anomaly_check_ok" : "anomaly_detected",
		flag: result.flag,
		score: result.score,
		detail: result.detail,
		thresholds: { drop: activeDropThreshold, spike: activeSpikeThreshold, minDataPoints },
		detectedAt: new Date().toISOString(),
	});

	return result;
}

/**
 * Derive calibration thresholds from a historical revenue series using
 * mean ± N standard deviations of month-over-month fractional changes.
 *
 * The returned object can be spread directly into `CalibrationConfig` and
 * passed to `detectRevenueAnomaly`:
 *
 * ```ts
 * const cal = calibrateFromSeries(historicalData);
 * const result = detectRevenueAnomaly(currentData, cal);
 * ```
 *
 * Falls back to module defaults when the series has fewer than 2 points or
 * all previous-period amounts are zero.
 *
 * @param series           Training series — the more months the better.
 * @param options.sigmaMultiplier  Number of standard deviations from the mean
 *                                 used to set the thresholds.
 *                                 Default: ANOMALY_CALIBRATION_SIGMA env var, or 2.
 */
export function calibrateFromSeries(
	series: MonthlyRevenue[],
	options: { sigmaMultiplier?: number } = {}
): CalibrationResult {
	const sigma = options.sigmaMultiplier ?? DEFAULT_SIGMA_MULTIPLIER;

	if (!series || series.length < 2) {
		return {
			dropThreshold: DROP_THRESHOLD,
			spikeThreshold: SPIKE_THRESHOLD,
			mean: 0,
			stdDev: 0,
		};
	}

	const sorted = [...series].sort((a, b) => a.period.localeCompare(b.period));

	// Collect all valid MoM fractional changes.
	const changes: number[] = [];
	for (let i = 1; i < sorted.length; i++) {
		const prev = sorted[i - 1];
		if (prev.amount !== 0) {
			changes.push((sorted[i].amount - prev.amount) / prev.amount);
		}
	}

	if (changes.length === 0) {
		return {
			dropThreshold: DROP_THRESHOLD,
			spikeThreshold: SPIKE_THRESHOLD,
			mean: 0,
			stdDev: 0,
		};
	}

	const mean = changes.reduce((s, c) => s + c, 0) / changes.length;
	const variance =
		changes.reduce((s, c) => s + (c - mean) ** 2, 0) / changes.length;
	const stdDev = Math.sqrt(variance);

	// Drop threshold: magnitude of (mean − N·σ), or fall back to default.
	const dropBound = mean - sigma * stdDev;
	const dropThreshold = dropBound < 0 ? Math.abs(dropBound) : DROP_THRESHOLD;

	// Spike threshold: (mean + N·σ), or fall back to default.
	const spikeBound = mean + sigma * stdDev;
	const spikeThreshold = spikeBound > 0 ? spikeBound : SPIKE_THRESHOLD;

	return { dropThreshold, spikeThreshold, mean, stdDev };
}

// ---------------------------------------------------------------------------
// Internal algorithm
// ---------------------------------------------------------------------------

/**
 * Iterates consecutive pairs, applies calibration config, and returns the
 * worst anomaly found.
 *
 * @internal
 */
function scoreSeriesAnomaly(
	sorted: MonthlyRevenue[],
	calibration: CalibrationConfig
): AnomalyResult {
	const dropThreshold  = calibration.dropThreshold  ?? DROP_THRESHOLD;
	const spikeThreshold = calibration.spikeThreshold ?? SPIKE_THRESHOLD;
	const { scoreHook }  = calibration;

	let worstScore  = 0;
	let worstFlag: AnomalyFlag = "ok";
	let worstDetail = "No anomaly detected.";

	for (let i = 1; i < sorted.length; i++) {
		const prev = sorted[i - 1];
		const curr = sorted[i];

		// Skip if previous amount is zero to avoid division by zero.
		if (prev.amount === 0) continue;

		const change = (curr.amount - prev.amount) / prev.amount; // signed fraction

		// Delegate to the score hook when provided; null means use built-in logic.
		if (scoreHook) {
			const hookResult = scoreHook(prev, curr, change);
			if (hookResult !== null) {
				if (hookResult.score > worstScore) {
					worstScore  = hookResult.score;
					worstFlag   = hookResult.flag;
					worstDetail =
						`Hook scored ${hookResult.flag} at ${curr.period} ` +
						`(score ${hookResult.score.toFixed(3)}).`;
				}
				continue;
			}
		}

		const absChange = Math.abs(change);
		const score     = Math.min(absChange, 1); // clamp to [0, 1]

		if (change <= -dropThreshold && score > worstScore) {
			worstScore  = score;
			worstFlag   = "unusual_drop";
			worstDetail =
				`Revenue dropped ${(absChange * 100).toFixed(1)}% from ` +
				`${prev.period} (${prev.amount}) to ${curr.period} (${curr.amount}).`;
		} else if (change >= spikeThreshold && score > worstScore) {
			worstScore  = score;
			worstFlag   = "unusual_spike";
			worstDetail =
				`Revenue spiked ${(absChange * 100).toFixed(1)}% from ` +
				`${prev.period} (${prev.amount}) to ${curr.period} (${curr.amount}).`;
		}
	}

	return { score: worstScore, flag: worstFlag, detail: worstDetail };
}