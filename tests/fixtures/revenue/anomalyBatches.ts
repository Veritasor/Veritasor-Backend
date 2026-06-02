/**
 * Labeled synthetic revenue batches for anomaly threshold regression testing.
 * All fixtures are deterministic and seeded for reproducible test results.
 */

export type MonthlyRevenue = {
	period: string;
	amount: number;
};

/** Helper to create monthly revenue entries */
function makePeriod(period: string, amount: number): MonthlyRevenue {
	return { period, amount };
}

/**
 * Fixture 1: Clean Baseline
 * Stable revenue with no anomalies — MUST NOT FLAG
 * Expected: flag: "ok", score: 0
 */
export const cleanBaseline: MonthlyRevenue[] = [
	makePeriod("2025-01", 10_000),
	makePeriod("2025-02", 10_000),
	makePeriod("2025-03", 10_000),
	makePeriod("2025-04", 10_000),
	makePeriod("2025-05", 10_000),
	makePeriod("2025-06", 10_000),
	makePeriod("2025-07", 10_000),
	makePeriod("2025-08", 10_000),
	makePeriod("2025-09", 10_000),
	makePeriod("2025-10", 10_000),
	makePeriod("2025-11", 10_000),
	makePeriod("2025-12", 10_000),
];

/**
 * Fixture 2: Refund Spike
 * Sharp revenue drop due to large refunds — MUST FLAG
 * Expected: flag: "unusual_drop"
 * Analysis: Baseline ~$10,000, spike to -$50,000 = >40% drop
 */
export const refundSpike: MonthlyRevenue[] = [
	makePeriod("2025-01", 10_000),
	makePeriod("2025-02", 10_500),
	makePeriod("2025-03", 9_800),
	makePeriod("2025-04", 10_200),
	makePeriod("2025-05", 10_100),
	makePeriod("2025-06", 9_900),
	makePeriod("2025-07", 10_300),
	makePeriod("2025-08", 10_000),
	makePeriod("2025-09", 10_150),
	makePeriod("2025-10", -45_000), // Large negative = refund spike
];

/**
 * Fixture 3: Currency Swap
 * Revenue stable, but payment sources vary — MUST NOT FLAG
 * Expected: flag: "ok"
 * (Currency changes don't affect anomaly detection directly)
 */
export const currencySwap: MonthlyRevenue[] = [
	makePeriod("2025-01", 10_000),
	makePeriod("2025-02", 10_500),
	makePeriod("2025-03", 9_200),
	makePeriod("2025-04", 11_000),
	makePeriod("2025-05", 10_800),
];

/**
 * Fixture 4: Gradual Drift
 * Slow decline over months, each change below threshold — MUST NOT FLAG
 * Expected: flag: "ok"
 * Each month ~$500 decline = 5% change, below 40% threshold
 */
export const gradualDrift: MonthlyRevenue[] = [
	makePeriod("2025-01", 10_000),
	makePeriod("2025-02", 9_500),
	makePeriod("2025-03", 9_000),
	makePeriod("2025-04", 8_500),
	makePeriod("2025-05", 8_000),
];

/**
 * Fixture 5: Refund Spike Just Under Threshold
 * Drop of ~39% (just below 40% threshold) — MUST NOT FLAG
 * Expected: flag: "ok", score: ~0.39
 */
export const refundSpikeUnderThreshold: MonthlyRevenue[] = [
	makePeriod("2025-01", 10_000),
	makePeriod("2025-02", 6_100), // -39% drop, just under threshold
	makePeriod("2025-03", 10_000),
	makePeriod("2025-04", 9_800),
];

/**
 * Fixture 6: Baseline With Sparse Data
 * Only one data point — MUST RETURN insufficient_data
 * Expected: flag: "insufficient_data", score: 0
 */
export const sparseData: MonthlyRevenue[] = [
	makePeriod("2025-01", 10_000),
];

/**
 * Fixture 7: All-Zero Batch
 * All amounts are zero — MUST NOT FLAG (no valid baseline for comparison)
 * Expected: flag: "ok"
 */
export const allZeroBatch: MonthlyRevenue[] = [
	makePeriod("2025-01", 0),
	makePeriod("2025-02", 0),
	makePeriod("2025-03", 0),
	makePeriod("2025-04", 0),
	makePeriod("2025-05", 0),
];

/**
 * Fixture 8: Sharp Spike (300%+ rise) — MUST FLAG unusual_spike
 * Expected: flag: "unusual_spike"
 */
export const sharpSpike: MonthlyRevenue[] = [
	makePeriod("2025-01", 10_000),
	makePeriod("2025-02", 40_000), // +300% spike = threshold boundary
];

/**
 * Fixture 9: Sharp Spike Just Under Threshold
 * Rise of ~290% (just below 300% threshold) — MUST NOT FLAG
 * Expected: flag: "ok"
 */
export const spikeUnderThreshold: MonthlyRevenue[] = [
	makePeriod("2025-01", 10_000),
	makePeriod("2025-02", 39_000), // +290% spike, just under threshold
];

/**
 * Fixture 10: Sustained Drop
 * Multiple months of significant decline — MUST FLAG
 * Expected: flag: "unusual_drop"
 */
export const sustainedDrop: MonthlyRevenue[] = [
	makePeriod("2025-01", 10_000),
	makePeriod("2025-02", 10_000),
	makePeriod("2025-03", 10_000),
	makePeriod("2025-04", 4_000), // -60% vs rolling avg = flagged
	makePeriod("2025-05", 3_800),
];

/**
 * Threshold configuration snapshot for regression visibility.
 * Changes to these values require fixture review.
 */
export const THRESHOLD_SNAPSHOT = {
	DROP_THRESHOLD: 0.4,
	SPIKE_THRESHOLD: 3.0,
	MIN_DATA_POINTS: 2,
	DEFAULT_SIGMA_MULTIPLIER: 2,
	DEFAULT_ROLLING_WINDOW: 3,
} as const;