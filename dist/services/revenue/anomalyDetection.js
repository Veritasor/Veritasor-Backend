/**
 * Anomaly detection for monthly revenue series.
 *
 * Uses a simple month-over-month percentage change algorithm by default.
 * Calibration hooks allow callers to override thresholds or inject a custom
 * scoring function per consecutive pair, making it easy to swap in a real
 * model (z-score, IQR, Prophet) without touching the public API.
 */
// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------
const DROP_THRESHOLD = 0.4;
const SPIKE_THRESHOLD = 3.0;
const MIN_DATA_POINTS = 2;
const DEFAULT_SIGMA_MULTIPLIER = 2;
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
 */
export function detectRevenueAnomaly(series, calibration = {}) {
    const minDataPoints = calibration.minDataPoints ?? MIN_DATA_POINTS;
    if (!series || series.length < minDataPoints) {
        return {
            score: 0,
            flag: "insufficient_data",
            detail: `Need at least ${minDataPoints} data points; received ${series?.length ?? 0}.`,
        };
    }
    // Sort ascending by period string (works for "YYYY-MM" and "YYYY-QN").
    const sorted = [...series].sort((a, b) => a.period.localeCompare(b.period));
    return scoreSeriesAnomaly(sorted, calibration);
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
 *                                 used to set the thresholds. Default: 2.
 */
export function calibrateFromSeries(series, options = {}) {
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
    const changes = [];
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
    const variance = changes.reduce((s, c) => s + (c - mean) ** 2, 0) / changes.length;
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
function scoreSeriesAnomaly(sorted, calibration) {
    const dropThreshold = calibration.dropThreshold ?? DROP_THRESHOLD;
    const spikeThreshold = calibration.spikeThreshold ?? SPIKE_THRESHOLD;
    const { scoreHook } = calibration;
    let worstScore = 0;
    let worstFlag = "ok";
    let worstDetail = "No anomaly detected.";
    for (let i = 1; i < sorted.length; i++) {
        const prev = sorted[i - 1];
        const curr = sorted[i];
        // Skip if previous amount is zero to avoid division by zero.
        if (prev.amount === 0)
            continue;
        const change = (curr.amount - prev.amount) / prev.amount; // signed fraction
        // Delegate to the score hook when provided; null means use built-in logic.
        if (scoreHook) {
            const hookResult = scoreHook(prev, curr, change);
            if (hookResult !== null) {
                if (hookResult.score > worstScore) {
                    worstScore = hookResult.score;
                    worstFlag = hookResult.flag;
                    worstDetail =
                        `Hook scored ${hookResult.flag} at ${curr.period} ` +
                            `(score ${hookResult.score.toFixed(3)}).`;
                }
                continue;
            }
        }
        const absChange = Math.abs(change);
        const score = Math.min(absChange, 1); // clamp to [0, 1]
        if (change <= -dropThreshold && score > worstScore) {
            worstScore = score;
            worstFlag = "unusual_drop";
            worstDetail =
                `Revenue dropped ${(absChange * 100).toFixed(1)}% from ` +
                    `${prev.period} (${prev.amount}) to ${curr.period} (${curr.amount}).`;
        }
        else if (change >= spikeThreshold && score > worstScore) {
            worstScore = score;
            worstFlag = "unusual_spike";
            worstDetail =
                `Revenue spiked ${(absChange * 100).toFixed(1)}% from ` +
                    `${prev.period} (${prev.amount}) to ${curr.period} (${curr.amount}).`;
        }
    }
    return { score: worstScore, flag: worstFlag, detail: worstDetail };
}
