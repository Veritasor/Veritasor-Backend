import { describe, it, expect, vi } from "vitest";
import {
  detectRevenueAnomaly,
  calibrateFromSeries,
} from "../../../../src/services/revenue/anomalyDetection.js";
import type {
  AnomalyFlag,
  AnomalyLogRecord,
  AnomalyResult,
  CalibrationConfig,
  MonthlyRevenue,
} from "../../../../src/services/revenue/anomalyDetection.js";

/**
 * Focused behavior coverage for `src/services/revenue/anomalyDetection.ts`.
 *
 * The module ships without a direct test fixture: the existing
 * `anomalyThresholds.test.ts` only replays curated business batches, so the
 * public surface described in the module header (`MonthlyRevenue`,
 * `AnomalyFlag`, `AnomalyResult`, the documented failure modes and the
 * calibration contract) is unguarded. This suite exercises that surface
 * directly, with the exact numbers the algorithm promises.
 */

const point = (period: string, amount: number): MonthlyRevenue => ({ period, amount });

/** All four members of the documented `AnomalyFlag` union. */
const ALL_FLAGS: AnomalyFlag[] = ["ok", "unusual_drop", "unusual_spike", "insufficient_data"];

/** Calibration that makes every threshold explicit, so env vars cannot shift results. */
const EXPLICIT: CalibrationConfig = {
  minDataPoints: 2,
  dropThreshold: 0.4,
  spikeThreshold: 3,
  rollingWindow: 1,
};

describe("anomalyDetection — AnomalyFlag / AnomalyResult contract", () => {
  it("returns exactly the three documented AnomalyResult keys", () => {
    const result: AnomalyResult = detectRevenueAnomaly(
      [point("2026-01", 100), point("2026-02", 105)],
      EXPLICIT,
    );

    expect(Object.keys(result).sort()).toEqual(["detail", "flag", "score"]);
    expect(typeof result.detail).toBe("string");
    expect(result.detail.length).toBeGreaterThan(0);
  });

  it("only ever emits members of the AnomalyFlag union", () => {
    const results = [
      detectRevenueAnomaly([], EXPLICIT),
      detectRevenueAnomaly([point("2026-01", 100)], EXPLICIT),
      detectRevenueAnomaly([point("2026-01", 100), point("2026-02", 105)], EXPLICIT),
      detectRevenueAnomaly([point("2026-01", 1000), point("2026-02", 10)], EXPLICIT),
      detectRevenueAnomaly([point("2026-01", 10), point("2026-02", 1000)], EXPLICIT),
    ];

    for (const result of results) {
      expect(ALL_FLAGS).toContain(result.flag);
    }
  });

  it("keeps built-in scores inside the documented [0, 1] range", () => {
    const results = [
      detectRevenueAnomaly([point("2026-01", 100), point("2026-02", 105)], EXPLICIT),
      detectRevenueAnomaly([point("2026-01", 100), point("2026-02", 1)], EXPLICIT),
      detectRevenueAnomaly([point("2026-01", 1), point("2026-02", 1_000_000)], EXPLICIT),
    ];

    for (const result of results) {
      expect(result.score).toBeGreaterThanOrEqual(0);
      expect(result.score).toBeLessThanOrEqual(1);
    }
  });

  it("accepts the documented MonthlyRevenue shape and ignores extra keys", () => {
    const withExtras = [
      { period: "2026-01", amount: 100, source: "razorpay" },
      { period: "2026-02", amount: 105, source: "razorpay" },
    ] as unknown as MonthlyRevenue[];

    expect(detectRevenueAnomaly(withExtras, EXPLICIT).flag).toBe("ok");
  });

  it("reports insufficient_data with a zero score and an explicit detail string", () => {
    const result = detectRevenueAnomaly([point("2026-01", 100)], EXPLICIT);

    expect(result).toEqual({
      score: 0,
      flag: "insufficient_data",
      detail: "Need at least 2 data points; received 1.",
    });
  });
});

describe("anomalyDetection — representative invalid inputs", () => {
  it("never throws for null or undefined series", () => {
    expect(detectRevenueAnomaly(null as unknown as MonthlyRevenue[], EXPLICIT)).toEqual({
      score: 0,
      flag: "insufficient_data",
      detail: "Need at least 2 data points; received 0.",
    });
    expect(detectRevenueAnomaly(undefined as unknown as MonthlyRevenue[], EXPLICIT).flag).toBe(
      "insufficient_data",
    );
  });

  it("rejects a non-iterable series rather than silently returning ok", () => {
    expect(() => detectRevenueAnomaly({} as unknown as MonthlyRevenue[], EXPLICIT)).toThrow(
      TypeError,
    );
  });

  it("coerces a missing period to the string \"undefined\" instead of rejecting it", () => {
    // `String.prototype.localeCompare` coerces the missing argument to
    // "undefined", and "2026-02" sorts before "undefined", so the malformed
    // entry is silently moved to the end and its amount is reported as a
    // 900% spike against the real period's 10.
    const malformed = [
      { period: undefined, amount: 100 },
      { period: "2026-02", amount: 10 },
    ] as unknown as MonthlyRevenue[];

    const result = detectRevenueAnomaly(malformed, EXPLICIT);

    expect(result.flag).toBe("unusual_spike");
    expect(result.score).toBe(1);
    expect(result.detail).toContain("(baseline 10)");
  });

  it("throws when no entry has a sortable period", () => {
    const malformed = [
      { period: undefined, amount: 100 },
      { period: undefined, amount: 10 },
    ] as unknown as MonthlyRevenue[];

    expect(() => detectRevenueAnomaly(malformed, EXPLICIT)).toThrow(TypeError);
  });

  it("treats a NaN amount as unremarkable instead of throwing", () => {
    const result = detectRevenueAnomaly(
      [point("2026-01", 100), point("2026-02", Number.NaN)],
      EXPLICIT,
    );

    // Every comparison against NaN is false, so the point is silently ignored.
    expect(result.flag).toBe("ok");
    expect(result.score).toBe(0);
  });

  it("clamps an infinite spike to a score of 1", () => {
    const result = detectRevenueAnomaly(
      [point("2026-01", 100), point("2026-02", Number.POSITIVE_INFINITY)],
      EXPLICIT,
    );

    expect(result.flag).toBe("unusual_spike");
    expect(result.score).toBe(1);
  });

  it("flags negative amounts as a drop rather than rejecting them", () => {
    const result = detectRevenueAnomaly([point("2026-01", 100), point("2026-02", -50)], EXPLICIT);

    expect(result.flag).toBe("unusual_drop");
    expect(result.score).toBe(1);
  });

  it("corrupts the rolling baseline when amounts arrive as strings", () => {
    // MonthlyRevenue.amount is typed `number`; at runtime a JSON payload can
    // still carry a string. The `sum + p.amount` reduction then concatenates
    // ("0100200") and the baseline becomes 50100 instead of 300.
    const stringy = [
      { period: "2026-01", amount: "100" },
      { period: "2026-02", amount: "200" },
      { period: "2026-03", amount: "300" },
    ] as unknown as MonthlyRevenue[];

    const result = detectRevenueAnomaly(stringy, { ...EXPLICIT, rollingWindow: 3 });

    expect(result.flag).toBe("unusual_drop");
    expect(result.detail).toContain("baseline 50100");
  });

  it("rejects a null series for calibrateFromSeries", () => {
    expect(calibrateFromSeries(null as unknown as MonthlyRevenue[])).toEqual({
      dropThreshold: 0.4,
      spikeThreshold: 3,
      mean: 0,
      stdDev: 0,
    });
  });
});

describe("anomalyDetection — minDataPoints boundary", () => {
  it("requires the configured minimum before scoring", () => {
    const result = detectRevenueAnomaly(
      [point("2026-01", 100), point("2026-02", 105)],
      { ...EXPLICIT, minDataPoints: 3 },
    );

    expect(result.flag).toBe("insufficient_data");
    expect(result.detail).toBe("Need at least 3 data points; received 2.");
  });

  it("scores as soon as the series length equals minDataPoints", () => {
    const result = detectRevenueAnomaly(
      [point("2026-01", 100), point("2026-02", 105)],
      { ...EXPLICIT, minDataPoints: 2 },
    );

    expect(result.flag).toBe("ok");
  });

  it("returns ok — not insufficient_data — when a single point meets minDataPoints: 1", () => {
    const result = detectRevenueAnomaly([point("2026-01", 100)], {
      ...EXPLICIT,
      minDataPoints: 1,
    });

    // There is no pair to compare, so no anomaly can be reported.
    expect(result).toEqual({ score: 0, flag: "ok", detail: "No anomaly detected." });
  });

  it("turns an empty series into ok when minDataPoints is lowered to 0", () => {
    const result = detectRevenueAnomaly([], { ...EXPLICIT, minDataPoints: 0 });

    expect(result.flag).toBe("ok");
    expect(result.score).toBe(0);
  });
});

describe("anomalyDetection — rolling average baseline", () => {
  it("flags a change that lands exactly on the drop threshold", () => {
    const result = detectRevenueAnomaly(
      [point("2026-01", 100), point("2026-02", 60)],
      { ...EXPLICIT, dropThreshold: 0.4 },
    );

    expect(result.flag).toBe("unusual_drop");
    expect(result.score).toBeCloseTo(0.4, 10);
  });

  it("stays quiet for a drop just short of the threshold", () => {
    const result = detectRevenueAnomaly(
      [point("2026-01", 100), point("2026-02", 60.5)],
      { ...EXPLICIT, dropThreshold: 0.4 },
    );

    expect(result.flag).toBe("ok");
    expect(result.score).toBe(0);
  });

  it("flags a change that lands exactly on the spike threshold", () => {
    const result = detectRevenueAnomaly(
      [point("2026-01", 100), point("2026-02", 400)],
      { ...EXPLICIT, spikeThreshold: 3 },
    );

    expect(result.flag).toBe("unusual_spike");
    // The reported score is clamped even though the raw change is 3.0.
    expect(result.score).toBe(1);
  });

  it("stays quiet for a spike just short of the threshold", () => {
    const result = detectRevenueAnomaly(
      [point("2026-01", 100), point("2026-02", 399)],
      { ...EXPLICIT, spikeThreshold: 3 },
    );

    expect(result.flag).toBe("ok");
    expect(result.score).toBe(0);
  });

  it("uses the wider window to smooth a stale outlier out of the baseline", () => {
    const series = [
      point("2026-01", 1000),
      point("2026-02", 100),
      point("2026-03", 100),
      point("2026-04", 20),
    ];

    const narrow = detectRevenueAnomaly(series, { ...EXPLICIT, rollingWindow: 1 });
    const wide = detectRevenueAnomaly(series, { ...EXPLICIT, rollingWindow: 3 });

    // window 1 reports the -90% drop from 1000 to 100; window 3 compares 20
    // against the 400 average of [1000, 100, 100], i.e. -95%, which is worse.
    expect(narrow.score).toBeCloseTo(0.9, 10);
    expect(wide.score).toBeCloseTo(0.95, 10);
    expect(wide.score).toBeGreaterThan(narrow.score);
  });

  it("excludes zero-amount periods from the baseline average", () => {
    const result = detectRevenueAnomaly(
      [point("2026-01", 0), point("2026-02", 100), point("2026-03", 60)],
      { ...EXPLICIT, rollingWindow: 3 },
    );

    // Averaging [0, 100] would give 50 and turn the -40% drop into a +20% rise;
    // the zero period is filtered out, so the baseline stays 100.
    expect(result.flag).toBe("unusual_drop");
    expect(result.score).toBeCloseTo(0.4, 10);
  });

  it("never flags a jump away from an all-zero baseline", () => {
    const result = detectRevenueAnomaly(
      [point("2026-01", 0), point("2026-02", 0), point("2026-03", 5)],
      { ...EXPLICIT, rollingWindow: 3 },
    );

    expect(result).toEqual({ score: 0, flag: "ok", detail: "No anomaly detected." });
  });

  it("clamps a zero or negative rollingWindow to a single predecessor", () => {
    const series = [point("2026-01", 100), point("2026-02", 400)];
    const expected = detectRevenueAnomaly(series, { ...EXPLICIT, rollingWindow: 1 });

    for (const rollingWindow of [0, -5]) {
      expect(detectRevenueAnomaly(series, { ...EXPLICIT, rollingWindow })).toEqual(expected);
    }
  });

  it("compares against the immediately preceding period when rollingWindow is 1", () => {
    const result = detectRevenueAnomaly(
      [point("2026-01", 100), point("2026-02", 150), point("2026-03", 75)],
      { ...EXPLICIT, rollingWindow: 1, dropThreshold: 0.5 },
    );

    // -50% vs 150 is exactly on the threshold; -25% vs the earlier 100 is not.
    expect(result.flag).toBe("unusual_drop");
    expect(result.score).toBeCloseTo(0.5, 10);
  });

  it("keeps the worst pair when several anomalies are present", () => {
    const result = detectRevenueAnomaly(
      [point("2026-01", 100), point("2026-02", 40), point("2026-03", 120), point("2026-04", 10)],
      { ...EXPLICIT, rollingWindow: 1 },
    );

    // -60% vs 100, then +200% vs 40, then -91.7% vs 120.
    expect(result.flag).toBe("unusual_drop");
    expect(result.score).toBeCloseTo(0.9166666, 5);
  });
});

describe("anomalyDetection — ordering and purity", () => {
  it("sorts an unordered series internally", () => {
    const ordered = [
      point("2026-01", 10_000),
      point("2026-02", 10_500),
      point("2026-03", 3_000),
    ];

    const sorted = detectRevenueAnomaly(ordered, EXPLICIT);
    const shuffled = detectRevenueAnomaly([ordered[2], ordered[0], ordered[1]], EXPLICIT);

    expect(shuffled).toEqual(sorted);
    expect(shuffled.flag).toBe("unusual_drop");
    expect(shuffled.detail).toContain("2026-03");
  });

  it("does not mutate the caller's array", () => {
    const input = [point("2026-03", 3_000), point("2026-01", 10_000), point("2026-02", 10_500)];
    const snapshot = JSON.stringify(input);

    detectRevenueAnomaly(input, EXPLICIT);

    expect(JSON.stringify(input)).toBe(snapshot);
  });

  it("is idempotent for identical input", () => {
    const series = [point("2026-01", 1_000), point("2026-02", 100)];

    expect(detectRevenueAnomaly(series, EXPLICIT)).toEqual(detectRevenueAnomaly(series, EXPLICIT));
  });

  it("mis-orders double-digit quarter labels because sorting is lexicographic", () => {
    // "2026-Q10" < "2026-Q2" as strings, so the later quarter is evaluated
    // first and the real drop (100 -> 10) is reported as a +900% spike.
    const result = detectRevenueAnomaly(
      [point("2026-Q2", 100), point("2026-Q10", 10)],
      EXPLICIT,
    );

    expect(result.flag).toBe("unusual_spike");
    expect(result.detail).toContain("2026-Q2");
  });
});

describe("anomalyDetection — scoreHook contract", () => {
  it("calls the hook once per comparable pair with (prev, curr, change)", () => {
    const hook = vi.fn().mockReturnValue(null);

    detectRevenueAnomaly(
      [point("2026-01", 100), point("2026-02", 120), point("2026-03", 150)],
      { ...EXPLICIT, scoreHook: hook },
    );

    expect(hook).toHaveBeenCalledTimes(2);
    expect(hook.mock.calls[0][0]).toEqual(point("2026-01", 100));
    expect(hook.mock.calls[0][1]).toEqual(point("2026-02", 120));
    expect(hook.mock.calls[0][2]).toBeCloseTo(0.2, 10);
    expect(hook.mock.calls[1][0]).toEqual(point("2026-02", 120));
    expect(hook.mock.calls[1][2]).toBeCloseTo(0.25, 10);
  });

  it("is skipped for pairs whose baseline is zero", () => {
    const hook = vi.fn().mockReturnValue(null);

    detectRevenueAnomaly([point("2026-01", 0), point("2026-02", 500)], {
      ...EXPLICIT,
      scoreHook: hook,
    });

    expect(hook).not.toHaveBeenCalled();
  });

  it("lets a hook verdict override the built-in drop flag", () => {
    const result = detectRevenueAnomaly(
      [point("2026-01", 1_000), point("2026-02", 100)],
      { ...EXPLICIT, scoreHook: () => ({ score: 0.95, flag: "ok" }) },
    );

    expect(result.flag).toBe("ok");
    expect(result.score).toBeCloseTo(0.95, 10);
    expect(result.detail).toBe("Hook scored ok at 2026-02 (score 0.950).");
  });

  it("suppresses the built-in verdict even when the hook score does not win", () => {
    const result = detectRevenueAnomaly(
      [point("2026-01", 1_000), point("2026-02", 100)],
      { ...EXPLICIT, scoreHook: () => ({ score: 0, flag: "unusual_spike" }) },
    );

    // A non-null hook verdict is authoritative for that pair. `0 > 0` is false,
    // so nothing is recorded and the pair is *not* re-scored by the built-in
    // thresholds — the -90% drop is deliberately ignored.
    expect(result).toEqual({ score: 0, flag: "ok", detail: "No anomaly detected." });
  });

  it("does not clamp hook scores to the [0, 1] range", () => {
    const result = detectRevenueAnomaly(
      [point("2026-01", 100), point("2026-02", 105)],
      { ...EXPLICIT, scoreHook: () => ({ score: 5, flag: "unusual_spike" }) },
    );

    expect(result.score).toBe(5);
  });

  it("falls back to built-in thresholds when the hook returns null", () => {
    const result = detectRevenueAnomaly(
      [point("2026-01", 1_000), point("2026-02", 100)],
      { ...EXPLICIT, scoreHook: () => null },
    );

    expect(result.flag).toBe("unusual_drop");
    expect(result.score).toBeCloseTo(0.9, 10);
  });

  it("propagates a hook exception to the caller", () => {
    expect(() =>
      detectRevenueAnomaly([point("2026-01", 100), point("2026-02", 105)], {
        ...EXPLICIT,
        scoreHook: () => {
          throw new Error("model unavailable");
        },
      }),
    ).toThrow("model unavailable");
  });
});

describe("anomalyDetection — calibrateFromSeries", () => {
  it("falls back to module defaults below two data points", () => {
    expect(calibrateFromSeries([point("2026-01", 100)])).toEqual({
      dropThreshold: 0.4,
      spikeThreshold: 3,
      mean: 0,
      stdDev: 0,
    });
  });

  it("falls back to module defaults when no previous amount is non-zero", () => {
    expect(calibrateFromSeries([point("2026-01", 0), point("2026-02", 0)])).toEqual({
      dropThreshold: 0.4,
      spikeThreshold: 3,
      mean: 0,
      stdDev: 0,
    });
  });

  it("computes the mean and population standard deviation of MoM changes", () => {
    const result = calibrateFromSeries([
      point("2026-01", 100),
      point("2026-02", 110),
      point("2026-03", 99),
    ]);

    // changes: +0.1, -0.1 -> mean 0, population stdDev 0.1
    expect(result.mean).toBeCloseTo(0, 10);
    expect(result.stdDev).toBeCloseTo(0.1, 10);
    expect(result.dropThreshold).toBeCloseTo(0.2, 10);
    expect(result.spikeThreshold).toBeCloseTo(0.2, 10);
  });

  it("scales both thresholds with sigmaMultiplier", () => {
    const series = [point("2026-01", 100), point("2026-02", 110), point("2026-03", 99)];

    expect(calibrateFromSeries(series, { sigmaMultiplier: 1 }).dropThreshold).toBeCloseTo(0.1, 10);
    expect(calibrateFromSeries(series, { sigmaMultiplier: 3 }).dropThreshold).toBeCloseTo(0.3, 10);
    expect(calibrateFromSeries(series, { sigmaMultiplier: 3 }).spikeThreshold).toBeCloseTo(0.3, 10);
  });

  it("falls back to the default drop threshold when the band stays positive", () => {
    // A steadily growing series has mean > sigma * stdDev, so mean - sigma*stdDev
    // is positive and no drop threshold can be derived from it; the spike
    // threshold is then just the mean of the training changes.
    const result = calibrateFromSeries([
      point("2026-01", 100),
      point("2026-02", 200),
      point("2026-03", 400),
    ]);

    expect(result.dropThreshold).toBe(0.4);
    expect(result.spikeThreshold).toBeCloseTo(1, 10);
  });

  it("skips pairs whose previous amount is zero", () => {
    const result = calibrateFromSeries([
      point("2026-01", 0),
      point("2026-02", 100),
      point("2026-03", 200),
    ]);

    // Only the 100 -> 200 change (+1.0) is usable.
    expect(result.mean).toBeCloseTo(1, 10);
    expect(result.stdDev).toBeCloseTo(0, 10);
  });

  it("sorts the training series and leaves the input untouched", () => {
    const input = [point("2026-03", 99), point("2026-01", 100), point("2026-02", 110)];
    const snapshot = JSON.stringify(input);

    const result = calibrateFromSeries(input);

    expect(result.mean).toBeCloseTo(0, 10);
    expect(JSON.stringify(input)).toBe(snapshot);
  });

  it("produces thresholds that round-trip through detectRevenueAnomaly", () => {
    const calibration = calibrateFromSeries([
      point("2026-01", 100),
      point("2026-02", 110),
      point("2026-03", 99),
    ]);

    const quiet = detectRevenueAnomaly(
      [point("2026-03", 99), point("2026-04", 104)],
      { ...calibration, rollingWindow: 1 },
    );
    const spiking = detectRevenueAnomaly(
      [point("2026-03", 100), point("2026-04", 300)],
      { ...calibration, rollingWindow: 1 },
    );

    expect(quiet.flag).toBe("ok");
    expect(spiking.flag).toBe("unusual_spike");
  });
});

describe("anomalyDetection — structured logging", () => {
  const thresholds: CalibrationConfig = {
    minDataPoints: 3,
    dropThreshold: 0.5,
    spikeThreshold: 2,
  };
  const expectedThresholds = { drop: 0.5, spike: 2, minDataPoints: 3 };

  it("emits anomaly_insufficient_data when the series is too short", () => {
    const logger = vi.fn();
    const result = detectRevenueAnomaly(
      [point("2026-01", 100), point("2026-02", 105)],
      thresholds,
      logger,
    );

    expect(logger).toHaveBeenCalledTimes(1);
    const record = logger.mock.calls[0][0] as AnomalyLogRecord;
    expect(record.event).toBe("anomaly_insufficient_data");
    expect(record.flag).toBe(result.flag);
    expect(record.score).toBe(result.score);
    expect(record.detail).toBe(result.detail);
    expect(record.thresholds).toEqual(expectedThresholds);
    expect(new Date(record.detectedAt).toISOString()).toBe(record.detectedAt);
  });

  it("emits anomaly_check_ok when nothing is flagged", () => {
    const logger = vi.fn();

    detectRevenueAnomaly(
      [point("2026-01", 100), point("2026-02", 105), point("2026-03", 108)],
      thresholds,
      logger,
    );

    expect(logger).toHaveBeenCalledTimes(1);
    expect((logger.mock.calls[0][0] as AnomalyLogRecord).event).toBe("anomaly_check_ok");
  });

  it("emits anomaly_detected with the winning flag, score and thresholds", () => {
    const logger = vi.fn();

    detectRevenueAnomaly(
      [point("2026-01", 100), point("2026-02", 40), point("2026-03", 45)],
      { ...thresholds, rollingWindow: 1 },
      logger,
    );

    expect(logger).toHaveBeenCalledTimes(1);
    const record = logger.mock.calls[0][0] as AnomalyLogRecord;
    expect(record.event).toBe("anomaly_detected");
    expect(record.flag).toBe("unusual_drop");
    expect(record.score).toBeCloseTo(0.6, 10);
    expect(record.thresholds).toEqual(expectedThresholds);
    expect(record.detail).toContain("Revenue dropped 60.0%");
  });

  it("does not require a logger", () => {
    expect(() =>
      detectRevenueAnomaly([point("2026-01", 100), point("2026-02", 105)], EXPLICIT),
    ).not.toThrow();
  });
});

describe("anomalyDetection — worst-pair aggregation across a growing series", () => {
  it("moves ok -> unusual_drop as the series evolves", () => {
    const base = [point("2026-01", 100), point("2026-02", 105)];

    expect(detectRevenueAnomaly(base, EXPLICIT).flag).toBe("ok");
    expect(detectRevenueAnomaly([...base, point("2026-03", 40)], EXPLICIT).flag).toBe(
      "unusual_drop",
    );
  });

  it("keeps reporting the historical worst pair after the series recovers", () => {
    const series = [
      point("2026-01", 100),
      point("2026-02", 105),
      point("2026-03", 40),
      point("2026-04", 42),
    ];

    // The healthy 2026-04 month does not reset the flag: the result is the
    // worst pair over the whole series, not the state of the latest period.
    expect(detectRevenueAnomaly(series, EXPLICIT).flag).toBe("unusual_drop");
  });

  it("reports a later spike when it outscores an earlier drop", () => {
    const series = [
      point("2026-01", 100),
      point("2026-02", 105),
      point("2026-03", 40),
      point("2026-04", 400),
    ];

    // +900% vs 40 scores 1, beating the -61.9% drop that scored 0.619.
    const result = detectRevenueAnomaly(series, EXPLICIT);

    expect(result.flag).toBe("unusual_spike");
    expect(result.score).toBe(1);
  });
});
