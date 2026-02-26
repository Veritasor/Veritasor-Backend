/**
 * Anomaly detection placeholder for monthly revenue series.
 *
 * Current implementation uses a simple month-over-month percentage change
 * algorithm. Replace the body of `scoreSeriesAnomaly` with a real model
 * (e.g. z-score, IQR, Prophet) without changing the public API.
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
	| "ok" // no anomaly detected
	| "unusual_drop" // revenue fell sharply vs prior period
	| "unusual_spike" // revenue rose sharply vs prior period
	| "insufficient_data"; // not enough data points to make a judgement

export type AnomalyResult = {
	/** Normalised anomaly score: 0 = normal, 1 = highly anomalous. */
	score: number;
	flag: AnomalyFlag;
	/** Human-readable explanation. Useful for logs and future UI display. */
	detail: string;
};

// ---------------------------------------------------------------------------
// Thresholds (adjust or move to config when a real model lands)
// ---------------------------------------------------------------------------

/** Month-over-month drop that triggers `unusual_drop` (fraction, e.g. 0.4 = 40%). */
const DROP_THRESHOLD = 0.4;

/** Month-over-month rise that triggers `unusual_spike` (fraction, e.g. 3.0 = 300%). */
const SPIKE_THRESHOLD = 3.0;

/** Minimum number of data points required to attempt detection. */
const MIN_DATA_POINTS = 2;

// ---------------------------------------------------------------------------
// Core function
// ---------------------------------------------------------------------------

/**
 * Analyse a monthly revenue series and return an anomaly score and flag.
 *
 * The series is expected to be sorted in ascending chronological order
 * (earliest period first). If it is not sorted the function sorts it
 * internally by the `period` string, which works correctly for ISO
 * year-month strings (`"YYYY-MM"`).
 *
 * @param series  Array of `{ period, amount }` data points.
 * @returns       `AnomalyResult` with `score`, `flag`, and `detail`.
 *
 * @example
 * const result = detectRevenueAnomaly([
 *   { period: '2026-01', amount: 10_000 },
 *   { period: '2026-02', amount: 10_500 },
 *   { period: '2026-03', amount: 3_000 },   // sharp drop
 * ])
 * // → { score: 0.7, flag: 'unusual_drop', detail: '...' }
 */
export function detectRevenueAnomaly(series: MonthlyRevenue[]): AnomalyResult {
	if (!series || series.length < MIN_DATA_POINTS) {
		return {
			score: 0,
			flag: "insufficient_data",
			detail: `Need at least ${MIN_DATA_POINTS} data points; received ${series?.length ?? 0}.`,
		};
	}

	// Sort ascending by period string (works for "YYYY-MM" and "YYYY-QN").
	const sorted = [...series].sort((a, b) => a.period.localeCompare(b.period));

	return scoreSeriesAnomaly(sorted);
}

// ---------------------------------------------------------------------------
// Internal algorithm (swap this out for a real model later)
// ---------------------------------------------------------------------------

/**
 * Simple month-over-month percentage change detector.
 *
 * Iterates through consecutive pairs and reports the worst deviation found.
 * Score is the absolute fractional change clamped to [0, 1].
 *
 * @internal
 */
function scoreSeriesAnomaly(sorted: MonthlyRevenue[]): AnomalyResult {
	let worstScore = 0;
	let worstFlag: AnomalyFlag = "ok";
	let worstDetail = "No anomaly detected.";

	for (let i = 1; i < sorted.length; i++) {
		const prev = sorted[i - 1];
		const curr = sorted[i];

		// Skip if previous amount is zero to avoid division by zero.
		if (prev.amount === 0) continue;

		const change = (curr.amount - prev.amount) / prev.amount; // signed fraction
		const absChange = Math.abs(change);
		const score = Math.min(absChange, 1); // clamp to [0, 1]

		if (change <= -DROP_THRESHOLD && score > worstScore) {
			worstScore = score;
			worstFlag = "unusual_drop";
			worstDetail =
				`Revenue dropped ${(absChange * 100).toFixed(1)}% from ` +
				`${prev.period} (${prev.amount}) to ${curr.period} (${curr.amount}).`;
		} else if (change >= SPIKE_THRESHOLD && score > worstScore) {
			worstScore = score;
			worstFlag = "unusual_spike";
			worstDetail =
				`Revenue spiked ${(absChange * 100).toFixed(1)}% from ` +
				`${prev.period} (${prev.amount}) to ${curr.period} (${curr.amount}).`;
		}
	}

	return { score: worstScore, flag: worstFlag, detail: worstDetail };
}
