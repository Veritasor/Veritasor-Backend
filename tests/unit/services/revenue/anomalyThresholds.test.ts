import { describe, it, expect } from "vitest";
import {
	detectRevenueAnomaly,
	calibrateFromSeries,
} from "../../../../src/services/revenue/anomalyDetection.js";
import {
	cleanBaseline,
	refundSpike,
	currencySwap,
	gradualDrift,
	refundSpikeUnderThreshold,
	sparseData,
	allZeroBatch,
	sharpSpike,
	spikeUnderThreshold,
	sustainedDrop,
	THRESHOLD_SNAPSHOT,
} from "../../../fixtures/revenue/anomalyBatches.js";

describe("anomaly threshold regression fixtures", () => {
	describe("[cleanBaseline] — stable revenue", () => {
		it("must not flag", () => {
			const result = detectRevenueAnomaly(cleanBaseline);
			expect(result.flag).toBe("ok");
			expect(result.score).toBe(0);
		});

		it("detail confirms no anomaly detected", () => {
			const result = detectRevenueAnomaly(cleanBaseline);
			expect(result.detail).toBe("No anomaly detected.");
		});
	});

	describe("[refundSpike] — sharp revenue drop from large refunds", () => {
		it("must flag unusual_drop", () => {
			const result = detectRevenueAnomaly(refundSpike);
			expect(result.flag).toBe("unusual_drop");
			expect(result.score).toBeGreaterThan(THRESHOLD_SNAPSHOT.DROP_THRESHOLD);
		});

		it("score exceeds threshold", () => {
			const result = detectRevenueAnomaly(refundSpike);
			expect(result.score).toBeGreaterThan(0.4);
		});
	});

	describe("[currencySwap] — stable amounts, varying sources", () => {
		it("must not flag", () => {
			const result = detectRevenueAnomaly(currencySwap);
			expect(result.flag).toBe("ok");
		});
	});

	describe("[gradualDrift] — slow decline below threshold per period", () => {
		it("must not flag", () => {
			const result = detectRevenueAnomaly(gradualDrift);
			expect(result.flag).toBe("ok");
		});

		it("score remains below threshold", () => {
			const result = detectRevenueAnomaly(gradualDrift);
			expect(result.score).toBeLessThan(THRESHOLD_SNAPSHOT.DROP_THRESHOLD);
		});
	});
});

describe("anomaly threshold edge cases", () => {
	describe("[refundSpikeUnderThreshold] — drop just under 40% threshold", () => {
		it("must not flag", () => {
			const result = detectRevenueAnomaly(refundSpikeUnderThreshold);
			expect(result.flag).toBe("ok");
		});

		it("score is zero when no anomaly flagged", () => {
			const result = detectRevenueAnomaly(refundSpikeUnderThreshold);
			expect(result.score).toBe(0);
		});
	});

	describe("[sparseData] — single data point", () => {
		it("must return insufficient_data", () => {
			const result = detectRevenueAnomaly(sparseData);
			expect(result.flag).toBe("insufficient_data");
			expect(result.score).toBe(0);
		});

		it("detail reports minimum data points required", () => {
			const result = detectRevenueAnomaly(sparseData);
			expect(result.detail).toContain("2");
		});
	});

	describe("[allZeroBatch] — all amounts zero", () => {
		it("must not flag (no valid baseline)", () => {
			const result = detectRevenueAnomaly(allZeroBatch);
			expect(result.flag).toBe("ok");
		});

		it("score is zero", () => {
			const result = detectRevenueAnomaly(allZeroBatch);
			expect(result.score).toBe(0);
		});
	});

	describe("[sharpSpike] — 300% revenue rise", () => {
		it("must flag unusual_spike at threshold boundary", () => {
			const result = detectRevenueAnomaly(sharpSpike);
			expect(result.flag).toBe("unusual_spike");
		});
	});

	describe("[spikeUnderThreshold] — 290% rise (just under 300%)", () => {
		it("must not flag", () => {
			const result = detectRevenueAnomaly(spikeUnderThreshold);
			expect(result.flag).toBe("ok");
		});
	});

	describe("[sustainedDrop] — multi-month decline exceeding threshold", () => {
		it("must flag unusual_drop", () => {
			const result = detectRevenueAnomaly(sustainedDrop);
			expect(result.flag).toBe("unusual_drop");
		});

		it("detail references the declining period", () => {
			const result = detectRevenueAnomaly(sustainedDrop);
			expect(result.detail).toContain("2025-04");
		});
	});
});

describe("threshold configuration snapshot validation", () => {
	it("defaults match expected snapshot values", () => {
		// This test ensures fixture expectations stay aligned with defaults
		expect(THRESHOLD_SNAPSHOT.DROP_THRESHOLD).toBe(0.4);
		expect(THRESHOLD_SNAPSHOT.SPIKE_THRESHOLD).toBe(3.0);
		expect(THRESHOLD_SNAPSHOT.MIN_DATA_POINTS).toBe(2);
		expect(THRESHOLD_SNAPSHOT.DEFAULT_SIGMA_MULTIPLIER).toBe(2);
	});

	it("calibrateFromSeries produces consistent thresholds for stable input", () => {
		const cal = calibrateFromSeries(cleanBaseline);
		expect(cal.dropThreshold).toBeGreaterThan(0);
		expect(cal.spikeThreshold).toBeGreaterThan(0);
	});
});