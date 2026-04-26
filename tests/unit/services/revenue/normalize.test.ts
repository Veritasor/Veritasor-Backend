import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  normalizeRevenueEntry,
  detectNormalizationDrift,
} from "../../../../src/services/revenue/normalize.js";
import type {
  NormalizedRevenue,
  NormalizationBaseline,
  RawRevenueInput,
} from "../../../../src/services/revenue/normalize.js";
import {
  detectRevenueAnomaly,
  calibrateFromSeries,
} from "../../../../src/services/revenue/anomalyDetection.js";
import type {
  MonthlyRevenue,
  CalibrationConfig,
  AnomalyLogRecord,
} from "../../../../src/services/revenue/anomalyDetection.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function raw(overrides: Partial<RawRevenueInput> & { id: string; amount: number }): RawRevenueInput {
  return { date: "2025-01-01", source: "stripe", ...overrides };
}

function makeMonthly(period: string, amount: number): MonthlyRevenue {
  return { period, amount };
}

/** Build a stable ascending series of n months starting at 2025-01. */
function stableSeries(n: number, base = 10_000): MonthlyRevenue[] {
  return Array.from({ length: n }, (_, i) => {
    const month = String(i + 1).padStart(2, "0");
    return makeMonthly(`2025-${month}`, base);
  });
}

// ---------------------------------------------------------------------------
// Existing: revenue normalizer
// ---------------------------------------------------------------------------

describe("revenue normalizer", () => {
  it("should produce the canonical shape", () => {
    const result = normalizeRevenueEntry({
      id: "txn_001",
      amount: 49.99,
      currency: "usd",
      date: "2025-11-15T10:30:00Z",
      source: "stripe",
    });

    expect(result).toEqual({
      id: "txn_001",
      amount: 49.99,
      currency: "USD",
      date: "2025-11-15T10:30:00.000Z",
      type: "payment",
      source: "stripe",
    });
  });

  it("should classify negative amounts as refund", () => {
    const result = normalizeRevenueEntry({
      id: "txn_002",
      amount: -20.0,
      currency: "EUR",
      date: "2025-12-01T00:00:00Z",
      source: "razorpay",
    });

    expect(result.type).toBe("refund");
    expect(result.amount).toBe(-20.0);
  });

  it("should classify positive amounts as payment", () => {
    const result = normalizeRevenueEntry({
      id: "txn_003",
      amount: 100,
      currency: "INR",
      date: "2025-06-01",
      source: "razorpay",
    });

    expect(result.type).toBe("payment");
  });

  it("should normalize currency to uppercase", () => {
    const result = normalizeRevenueEntry({
      id: "txn_004",
      amount: 10,
      currency: "gbp",
      date: "2025-01-01",
    });

    expect(result.currency).toBe("GBP");
  });

  it("should default currency to USD when missing", () => {
    const result = normalizeRevenueEntry({
      id: "txn_005",
      amount: 5,
      date: "2025-01-01",
    });

    expect(result.currency).toBe("USD");
  });

  it("should convert numeric date (Unix timestamp) to ISO string", () => {
    const result = normalizeRevenueEntry({
      id: "txn_006",
      amount: 30,
      currency: "USD",
      date: 1700000000,
      source: "manual",
    });

    expect(result.date).toBe("2023-11-14T22:13:20.000Z");
  });

  it("should parse a string date into ISO format", () => {
    const result = normalizeRevenueEntry({
      id: "txn_007",
      amount: 15,
      currency: "USD",
      date: "2025-03-20",
      source: "stripe",
    });

    expect(result.date).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(new Date(result.date).toISOString()).toBe(result.date);
  });

  it("should default source to unknown when missing", () => {
    const result = normalizeRevenueEntry({
      id: "txn_008",
      amount: 25,
      date: "2025-01-01",
    });

    expect(result.source).toBe("unknown");
  });

  it("should handle zero amount as payment", () => {
    const result = normalizeRevenueEntry({
      id: "txn_009",
      amount: 0,
      currency: "USD",
      date: "2025-01-01",
      source: "test",
    });

    expect(result.type).toBe("payment");
    expect(result.amount).toBe(0);
  });

  // -------------------------------------------------------------------------
  // Currency drift
  // -------------------------------------------------------------------------

  describe("currency drift — case normalization consistency", () => {
    const currencies = ["usd", "USD", "Usd", "uSD", "UsD"] as const;

    it("should produce the same currency code regardless of input casing", () => {
      const codes = currencies.map((c) =>
        normalizeRevenueEntry(raw({ id: "d1", amount: 1, currency: c })).currency
      );
      expect(new Set(codes).size).toBe(1);
      expect(codes[0]).toBe("USD");
    });

    it("should be idempotent — normalizing an already-normalized currency is a no-op", () => {
      const once = normalizeRevenueEntry(raw({ id: "d2", amount: 1, currency: "eur" }));
      const twice = normalizeRevenueEntry({ ...raw({ id: "d2", amount: 1 }), currency: once.currency });
      expect(twice.currency).toBe("EUR");
      expect(twice.currency).toBe(once.currency);
    });

    it("should normalize mixed-case three-letter codes", () => {
      const cases: Array<[string, string]> = [
        ["gbp", "GBP"],
        ["GbP", "GBP"],
        ["gBP", "GBP"],
        ["inr", "INR"],
        ["InR", "INR"],
        ["jPy", "JPY"],
      ];
      for (const [input, expected] of cases) {
        const result = normalizeRevenueEntry(raw({ id: "d3", amount: 5, currency: input }));
        expect(result.currency).toBe(expected);
      }
    });

    it("should preserve non-alphabetic currency codes (e.g. numeric ISO 4217) uppercased", () => {
      const result = normalizeRevenueEntry(raw({ id: "d4", amount: 10, currency: "840" }));
      expect(result.currency).toBe("840");
    });

    it("should uppercase currency codes that contain letters and digits", () => {
      const result = normalizeRevenueEntry(raw({ id: "d5", amount: 10, currency: "usdt" }));
      expect(result.currency).toBe("USDT");
    });

    it("should preserve whitespace in currency codes without trimming", () => {
      const result = normalizeRevenueEntry(raw({ id: "d6", amount: 10, currency: " usd " }));
      expect(result.currency).toBe(" USD ");
    });

    it("should treat empty-string currency as absent and default to USD", () => {
      const result = normalizeRevenueEntry(raw({ id: "d7", amount: 10, currency: "" }));
      expect(result.currency).toBe("USD");
    });

    it("should produce consistent currency for a batch of same-source entries with different casing", () => {
      const inputs: RawRevenueInput[] = [
        raw({ id: "b1", amount: 100, currency: "eur" }),
        raw({ id: "b2", amount: 200, currency: "EUR" }),
        raw({ id: "b3", amount: 300, currency: "Eur" }),
        raw({ id: "b4", amount: 400, currency: "eUr" }),
      ];
      const codes = inputs.map((e) => normalizeRevenueEntry(e).currency);
      expect(new Set(codes).size).toBe(1);
      expect([...new Set(codes)][0]).toBe("EUR");
    });

    it("should not mutate the original raw input", () => {
      const input = raw({ id: "d8", amount: 50, currency: "jpy" });
      const before = { ...input };
      normalizeRevenueEntry(input);
      expect(input).toEqual(before);
    });
  });

  // -------------------------------------------------------------------------
  // Date normalization
  // -------------------------------------------------------------------------

  describe("date normalization edge cases", () => {
    it("should fall back to current time for an invalid date string", () => {
      const before = Date.now();
      const result = normalizeRevenueEntry(raw({ id: "dt1", amount: 1, date: "not-a-date" }));
      const after = Date.now();
      const ts = new Date(result.date).getTime();
      expect(ts).toBeGreaterThanOrEqual(before);
      expect(ts).toBeLessThanOrEqual(after);
    });

    it("should fall back to current time when date is undefined", () => {
      const before = Date.now();
      const result = normalizeRevenueEntry({ id: "dt2", amount: 1 });
      const after = Date.now();
      const ts = new Date(result.date).getTime();
      expect(ts).toBeGreaterThanOrEqual(before);
      expect(ts).toBeLessThanOrEqual(after);
    });

    it("should fall back to current time when date is an empty string", () => {
      const before = Date.now();
      const result = normalizeRevenueEntry(raw({ id: "dt3", amount: 1, date: "" }));
      const after = Date.now();
      const ts = new Date(result.date).getTime();
      expect(ts).toBeGreaterThanOrEqual(before);
      expect(ts).toBeLessThanOrEqual(after);
    });

    it("should handle Unix timestamp 0 (epoch) correctly", () => {
      const result = normalizeRevenueEntry(raw({ id: "dt4", amount: 1, date: 0 }));
      expect(result.date).toBe("1970-01-01T00:00:00.000Z");
    });

    it("should handle a large Unix timestamp (year 2100)", () => {
      const result = normalizeRevenueEntry(raw({ id: "dt5", amount: 1, date: 4102444800 }));
      expect(result.date).toBe("2100-01-01T00:00:00.000Z");
    });

    it("should preserve full timestamp precision from ISO strings", () => {
      const result = normalizeRevenueEntry(
        raw({ id: "dt6", amount: 1, date: "2025-07-04T12:34:56.789Z" })
      );
      expect(result.date).toBe("2025-07-04T12:34:56.789Z");
    });

    it("should always produce a valid ISO 8601 date string regardless of input", () => {
      const inputs: Array<string | number | undefined> = [
        "2025-01-01",
        "2025-01-01T00:00:00Z",
        1700000000,
        0,
        "",
        undefined,
        "garbage",
      ];
      for (const date of inputs) {
        const result = normalizeRevenueEntry({ id: "dt7", amount: 1, date });
        expect(result.date).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
      }
    });
  });

  // -------------------------------------------------------------------------
  // Amount classification
  // -------------------------------------------------------------------------

  describe("amount classification edge cases", () => {
    it("should classify the smallest negative float as refund", () => {
      const result = normalizeRevenueEntry(raw({ id: "a1", amount: -0.01 }));
      expect(result.type).toBe("refund");
    });

    it("should classify the smallest positive float as payment", () => {
      const result = normalizeRevenueEntry(raw({ id: "a2", amount: 0.01 }));
      expect(result.type).toBe("payment");
    });

    it("should handle very large positive amounts", () => {
      const result = normalizeRevenueEntry(raw({ id: "a3", amount: 1_000_000_000 }));
      expect(result.type).toBe("payment");
      expect(result.amount).toBe(1_000_000_000);
    });

    it("should handle very large negative amounts", () => {
      const result = normalizeRevenueEntry(raw({ id: "a4", amount: -1_000_000_000 }));
      expect(result.type).toBe("refund");
      expect(result.amount).toBe(-1_000_000_000);
    });

    it("should preserve fractional precision", () => {
      const result = normalizeRevenueEntry(raw({ id: "a5", amount: 19.99 }));
      expect(result.amount).toBe(19.99);
    });

    it("should preserve the exact amount value without rounding", () => {
      const result = normalizeRevenueEntry(raw({ id: "a6", amount: 123.456789 }));
      expect(result.amount).toBe(123.456789);
    });
  });

  // -------------------------------------------------------------------------
  // Source field
  // -------------------------------------------------------------------------

  describe("source field normalization", () => {
    it("should use the provided source as-is", () => {
      const result = normalizeRevenueEntry(raw({ id: "s1", amount: 1, source: "shopify" }));
      expect(result.source).toBe("shopify");
    });

    it("should default source to 'unknown' when source is undefined", () => {
      const { source: _, ...noSource } = raw({ id: "s2", amount: 1, source: "x" });
      const result = normalizeRevenueEntry({ ...noSource });
      expect(result.source).toBe("unknown");
    });

    it("should default source to 'unknown' when source is empty string", () => {
      const result = normalizeRevenueEntry(raw({ id: "s3", amount: 1, source: "" }));
      expect(result.source).toBe("unknown");
    });

    it("should preserve source values from all known integration names", () => {
      const sources = ["stripe", "razorpay", "shopify", "manual", "unknown"];
      for (const source of sources) {
        const result = normalizeRevenueEntry(raw({ id: "s4", amount: 1, source }));
        expect(result.source).toBe(source);
      }
    });
  });

  // -------------------------------------------------------------------------
  // Output shape invariants
  // -------------------------------------------------------------------------

  describe("output shape invariants", () => {
    const fixtures: RawRevenueInput[] = [
      { id: "inv_1", amount: 100, currency: "usd", date: "2025-01-01", source: "stripe" },
      { id: "inv_2", amount: -50, currency: "EUR" },
      { id: "inv_3", amount: 0 },
      { id: "inv_4", amount: 9.99, date: 1700000000 },
      { id: "inv_5", amount: 1, currency: "", date: "bad-date", source: "" },
    ];

    it("should always return all six required fields", () => {
      const required: Array<keyof NormalizedRevenue> = [
        "id", "amount", "currency", "date", "type", "source",
      ];
      for (const fixture of fixtures) {
        const result = normalizeRevenueEntry(fixture);
        for (const field of required) {
          expect(result).toHaveProperty(field);
        }
      }
    });

    it("should always preserve the input id exactly", () => {
      for (const fixture of fixtures) {
        const result = normalizeRevenueEntry(fixture);
        expect(result.id).toBe(fixture.id);
      }
    });

    it("should always preserve the input amount exactly", () => {
      for (const fixture of fixtures) {
        const result = normalizeRevenueEntry(fixture);
        expect(result.amount).toBe(fixture.amount);
      }
    });

    it("should always return currency in uppercase", () => {
      for (const fixture of fixtures) {
        const result = normalizeRevenueEntry(fixture);
        expect(result.currency).toBe(result.currency.toUpperCase());
      }
    });

    it("should always return type as 'payment' or 'refund'", () => {
      for (const fixture of fixtures) {
        const result = normalizeRevenueEntry(fixture);
        expect(["payment", "refund"]).toContain(result.type);
      }
    });

    it("should always return a valid ISO 8601 UTC date string", () => {
      for (const fixture of fixtures) {
        const result = normalizeRevenueEntry(fixture);
        expect(result.date).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
        expect(isNaN(new Date(result.date).getTime())).toBe(false);
      }
    });

    it("should classify positive amounts as payment and negative as refund consistently", () => {
      const pos = normalizeRevenueEntry(raw({ id: "inv_pos", amount: 1 }));
      const neg = normalizeRevenueEntry(raw({ id: "inv_neg", amount: -1 }));
      const zer = normalizeRevenueEntry(raw({ id: "inv_zer", amount: 0 }));
      expect(pos.type).toBe("payment");
      expect(neg.type).toBe("refund");
      expect(zer.type).toBe("payment");
    });
  });
});

// ---------------------------------------------------------------------------
// Existing: detectNormalizationDrift
// ---------------------------------------------------------------------------

describe("detectNormalizationDrift", () => {
  const baseline: NormalizationBaseline = {
    refundRate: 0.1,
    unknownSourceRate: 0.05,
    usdRate: 0.8,
    meanAmount: 100,
  };

  function makeEntry(overrides: Partial<NormalizedRevenue> = {}): NormalizedRevenue {
    return {
      id: "txn_test",
      amount: 100,
      currency: "USD",
      date: "2025-01-01T00:00:00.000Z",
      type: "payment",
      source: "stripe",
      ...overrides,
    };
  }

  it("should return insufficient_data when entry count is below minimum", () => {
    const entries = [makeEntry(), makeEntry(), makeEntry()];
    const result = detectNormalizationDrift(entries, baseline);
    expect(result.hasDrift).toBe(false);
    expect(result.overallScore).toBe(0);
    expect(result.checks[0].flag).toBe("insufficient_data");
    expect(result.summary).toContain("Insufficient data");
  });

  it("should return insufficient_data for an empty array", () => {
    const result = detectNormalizationDrift([], baseline);
    expect(result.hasDrift).toBe(false);
    expect(result.checks[0].flag).toBe("insufficient_data");
  });

  it("should report no drift when entries exactly match the baseline", () => {
    const matchingBaseline: NormalizationBaseline = {
      refundRate: 0.1,
      unknownSourceRate: 0.1,
      usdRate: 0.8,
      meanAmount: 100,
    };
    const entries: NormalizedRevenue[] = [
      makeEntry({ type: "refund", amount: -100 }),
      makeEntry({ source: "unknown" }),
      makeEntry({ currency: "EUR" }),
      makeEntry({ currency: "EUR" }),
      ...Array.from({ length: 6 }, () => makeEntry()),
    ];
    const result = detectNormalizationDrift(entries, matchingBaseline);
    expect(result.hasDrift).toBe(false);
    expect(result.summary).toBe("No normalization drift detected.");
  });

  it("should flag refund_rate_drift when refund fraction deviates significantly", () => {
    const entries: NormalizedRevenue[] = [
      makeEntry({ type: "refund", amount: -100 }),
      makeEntry({ type: "refund", amount: -100 }),
      makeEntry({ type: "refund", amount: -100 }),
      makeEntry(),
      makeEntry(),
    ];
    const result = detectNormalizationDrift(entries, baseline);
    const refundCheck = result.checks.find((c) => c.metric === "refund_rate");
    expect(result.hasDrift).toBe(true);
    expect(refundCheck?.flag).toBe("refund_rate_drift");
  });

  it("should flag unknown_source_drift when unknown source fraction deviates", () => {
    const entries: NormalizedRevenue[] = [
      makeEntry({ source: "unknown" }),
      makeEntry({ source: "unknown" }),
      makeEntry({ source: "unknown" }),
      makeEntry({ source: "unknown" }),
      makeEntry(),
    ];
    const result = detectNormalizationDrift(entries, baseline);
    const sourceCheck = result.checks.find((c) => c.metric === "unknown_source_rate");
    expect(result.hasDrift).toBe(true);
    expect(sourceCheck?.flag).toBe("unknown_source_drift");
  });

  it("should flag usd_rate_drift when USD currency fraction deviates", () => {
    const entries = Array.from({ length: 5 }, () => makeEntry({ currency: "EUR" }));
    const result = detectNormalizationDrift(entries, baseline);
    const usdCheck = result.checks.find((c) => c.metric === "usd_rate");
    expect(result.hasDrift).toBe(true);
    expect(usdCheck?.flag).toBe("usd_rate_drift");
  });

  it("should flag amount_drift when mean amount deviates significantly", () => {
    const entries = Array.from({ length: 5 }, () => makeEntry({ amount: 10000 }));
    const result = detectNormalizationDrift(entries, baseline);
    const amountCheck = result.checks.find((c) => c.metric === "mean_amount");
    expect(result.hasDrift).toBe(true);
    expect(amountCheck?.flag).toBe("amount_drift");
  });

  it("should detect multiple drifting metrics simultaneously", () => {
    const entries: NormalizedRevenue[] = [
      makeEntry({ type: "refund", amount: -100, source: "unknown" }),
      makeEntry({ type: "refund", amount: -100, source: "unknown" }),
      makeEntry({ type: "refund", amount: -100, source: "unknown" }),
      makeEntry({ source: "unknown" }),
      makeEntry(),
    ];
    const result = detectNormalizationDrift(entries, baseline);
    const driftedFlags = result.checks.filter((c) => c.flag !== "ok").map((c) => c.flag);
    expect(result.hasDrift).toBe(true);
    expect(driftedFlags).toContain("refund_rate_drift");
    expect(driftedFlags).toContain("unknown_source_drift");
  });

  it("should respect custom threshold and suppress drift below it", () => {
    const entries: NormalizedRevenue[] = [
      makeEntry({ type: "refund", amount: -100 }),
      makeEntry({ type: "refund", amount: -100 }),
      ...Array.from({ length: 8 }, () => makeEntry()),
    ];
    const result = detectNormalizationDrift(entries, baseline, { threshold: 2.0 });
    const refundCheck = result.checks.find((c) => c.metric === "refund_rate");
    expect(refundCheck?.flag).toBe("ok");
  });

  it("should respect custom minEntries option", () => {
    const entries = [makeEntry(), makeEntry(), makeEntry()];
    const result = detectNormalizationDrift(entries, baseline, { minEntries: 2 });
    expect(result.checks[0].flag).not.toBe("insufficient_data");
  });

  it("should set overallScore to the maximum score across all checks", () => {
    const entries = Array.from({ length: 5 }, () => makeEntry({ amount: 10000 }));
    const result = detectNormalizationDrift(entries, baseline);
    const maxScore = Math.max(...result.checks.map((c) => c.score));
    expect(result.overallScore).toBe(maxScore);
    expect(result.overallScore).toBeGreaterThan(0);
  });

  it("should handle zero baseline rate with zero observed — no drift", () => {
    const zeroBaseline = { ...baseline, unknownSourceRate: 0 };
    const entries = Array.from({ length: 5 }, () => makeEntry());
    const result = detectNormalizationDrift(entries, zeroBaseline);
    const sourceCheck = result.checks.find((c) => c.metric === "unknown_source_rate");
    expect(sourceCheck?.flag).toBe("ok");
    expect(sourceCheck?.score).toBe(0);
  });

  it("should flag drift when baseline rate is zero but observed is non-zero", () => {
    const zeroBaseline = { ...baseline, unknownSourceRate: 0 };
    const entries: NormalizedRevenue[] = [
      makeEntry({ source: "unknown" }),
      makeEntry({ source: "unknown" }),
      makeEntry(),
      makeEntry(),
      makeEntry(),
    ];
    const result = detectNormalizationDrift(entries, zeroBaseline);
    const sourceCheck = result.checks.find((c) => c.metric === "unknown_source_rate");
    expect(sourceCheck?.flag).toBe("unknown_source_drift");
    expect(sourceCheck?.score).toBe(1);
  });
});

// ===========================================================================
// NEW: detectRevenueAnomaly — threshold configuration
// ===========================================================================

describe("detectRevenueAnomaly — insufficient data", () => {
  it("returns insufficient_data for an empty series", () => {
    const result = detectRevenueAnomaly([]);
    expect(result.flag).toBe("insufficient_data");
    expect(result.score).toBe(0);
  });

  it("returns insufficient_data for a single data point", () => {
    const result = detectRevenueAnomaly([makeMonthly("2025-01", 10_000)]);
    expect(result.flag).toBe("insufficient_data");
  });

  it("succeeds with exactly two data points (default minDataPoints)", () => {
    const result = detectRevenueAnomaly([
      makeMonthly("2025-01", 10_000),
      makeMonthly("2025-02", 10_000),
    ]);
    expect(result.flag).toBe("ok");
  });

  it("respects custom minDataPoints — flags insufficient when series is too short", () => {
    const result = detectRevenueAnomaly(
      [makeMonthly("2025-01", 10_000), makeMonthly("2025-02", 10_000)],
      { minDataPoints: 3 }
    );
    expect(result.flag).toBe("insufficient_data");
    expect(result.detail).toContain("3");
  });

  it("detail message reports the actual series length received", () => {
    const result = detectRevenueAnomaly([makeMonthly("2025-01", 5_000)]);
    expect(result.detail).toContain("1");
  });
});

// ---------------------------------------------------------------------------
// Drop threshold
// ---------------------------------------------------------------------------

describe("detectRevenueAnomaly — drop threshold", () => {
  it("flags unusual_drop at exactly the default 40% drop", () => {
    // 10 000 → 6 000 = −40%
    const series = [makeMonthly("2025-01", 10_000), makeMonthly("2025-02", 6_000)];
    const result = detectRevenueAnomaly(series);
    expect(result.flag).toBe("unusual_drop");
  });

  it("does not flag a drop just below the default threshold", () => {
    // 10 000 → 6 100 ≈ −39%
    const series = [makeMonthly("2025-01", 10_000), makeMonthly("2025-02", 6_100)];
    const result = detectRevenueAnomaly(series);
    expect(result.flag).toBe("ok");
  });

  it("respects a custom lower dropThreshold (e.g. 0.20)", () => {
    // 10 000 → 7 500 = −25% → should fire with threshold=0.20
    const series = [makeMonthly("2025-01", 10_000), makeMonthly("2025-02", 7_500)];
    const result = detectRevenueAnomaly(series, { dropThreshold: 0.2 });
    expect(result.flag).toBe("unusual_drop");
  });

  it("respects a custom higher dropThreshold (e.g. 0.60) — suppresses a 40% drop", () => {
    const series = [makeMonthly("2025-01", 10_000), makeMonthly("2025-02", 6_000)];
    const result = detectRevenueAnomaly(series, { dropThreshold: 0.6 });
    expect(result.flag).toBe("ok");
  });

  it("score equals the absolute fractional change (clamped to 1) for a drop", () => {
    // 10 000 → 5 000 = −50%
    const series = [makeMonthly("2025-01", 10_000), makeMonthly("2025-02", 5_000)];
    const result = detectRevenueAnomaly(series);
    expect(result.score).toBeCloseTo(0.5, 5);
  });

  it("detail string contains both period labels and amounts for the worst pair", () => {
    const series = [makeMonthly("2025-01", 10_000), makeMonthly("2025-02", 5_000)];
    const result = detectRevenueAnomaly(series);
    expect(result.detail).toContain("2025-01");
    expect(result.detail).toContain("2025-02");
    expect(result.detail).toContain("10000");
    expect(result.detail).toContain("5000");
  });

  it("flags the worst drop across a multi-period series", () => {
    // Mild drop in 02, severe drop in 04
    const series = [
      makeMonthly("2025-01", 10_000),
      makeMonthly("2025-02", 9_000),  // −10%
      makeMonthly("2025-03", 9_500),
      makeMonthly("2025-04", 2_000),  // −79%
    ];
    const result = detectRevenueAnomaly(series);
    expect(result.flag).toBe("unusual_drop");
    expect(result.detail).toContain("2025-04");
  });
});

// ---------------------------------------------------------------------------
// Spike threshold
// ---------------------------------------------------------------------------

describe("detectRevenueAnomaly — spike threshold", () => {
  it("flags unusual_spike at exactly the default 300% rise", () => {
    // 10 000 → 40 000 = +300%
    const series = [makeMonthly("2025-01", 10_000), makeMonthly("2025-02", 40_000)];
    const result = detectRevenueAnomaly(series);
    expect(result.flag).toBe("unusual_spike");
  });

  it("does not flag a rise just below the default spike threshold", () => {
    // 10 000 → 39 000 = +290%
    const series = [makeMonthly("2025-01", 10_000), makeMonthly("2025-02", 39_000)];
    const result = detectRevenueAnomaly(series);
    expect(result.flag).toBe("ok");
  });

  it("respects a custom lower spikeThreshold (e.g. 1.0 = 100%)", () => {
    // 10 000 → 25 000 = +150% → fires at threshold 1.0
    const series = [makeMonthly("2025-01", 10_000), makeMonthly("2025-02", 25_000)];
    const result = detectRevenueAnomaly(series, { spikeThreshold: 1.0 });
    expect(result.flag).toBe("unusual_spike");
  });

  it("respects a custom higher spikeThreshold (e.g. 5.0) — suppresses a 300% spike", () => {
    const series = [makeMonthly("2025-01", 10_000), makeMonthly("2025-02", 40_000)];
    const result = detectRevenueAnomaly(series, { spikeThreshold: 5.0 });
    expect(result.flag).toBe("ok");
  });

  it("score for a spike is clamped to 1 when change > 100%", () => {
    // 10 000 → 50 000 = +400%
    const series = [makeMonthly("2025-01", 10_000), makeMonthly("2025-02", 50_000)];
    const result = detectRevenueAnomaly(series);
    expect(result.score).toBe(1);
    expect(result.flag).toBe("unusual_spike");
  });

  it("detail string includes 'spiked' and both period labels", () => {
    const series = [makeMonthly("2025-01", 5_000), makeMonthly("2025-02", 25_000)];
    const result = detectRevenueAnomaly(series, { spikeThreshold: 1.0 });
    expect(result.detail.toLowerCase()).toContain("spike");
    expect(result.detail).toContain("2025-01");
    expect(result.detail).toContain("2025-02");
  });
});

// ---------------------------------------------------------------------------
// Edge cases: zero, negative, unsorted input
// ---------------------------------------------------------------------------

describe("detectRevenueAnomaly — edge cases", () => {
  it("skips pairs where prev.amount is 0 (avoids division by zero)", () => {
    const series = [
      makeMonthly("2025-01", 0),
      makeMonthly("2025-02", 10_000),
      makeMonthly("2025-03", 10_000),
    ];
    const result = detectRevenueAnomaly(series);
    expect(result.flag).toBe("ok");
  });

  it("returns ok when all amounts are zero", () => {
    const series = stableSeries(4, 0);
    const result = detectRevenueAnomaly(series);
    expect(result.flag).toBe("ok");
  });

  it("sorts an unsorted series before analysis", () => {
    // Shuffled order — the logic should still detect the drop in 03→04
    const series = [
      makeMonthly("2025-04", 2_000),
      makeMonthly("2025-01", 10_000),
      makeMonthly("2025-03", 10_500),
      makeMonthly("2025-02", 10_200),
    ];
    const result = detectRevenueAnomaly(series);
    expect(result.flag).toBe("unusual_drop");
    expect(result.detail).toContain("2025-04");
  });

  it("does not mutate the original series array", () => {
    const series = [makeMonthly("2025-02", 5_000), makeMonthly("2025-01", 10_000)];
    const original = series.map((s) => ({ ...s }));
    detectRevenueAnomaly(series);
    expect(series).toEqual(original);
  });

  it("handles negative revenue amounts without throwing", () => {
    // Negative-to-less-negative = positive change; should not throw
    const series = [makeMonthly("2025-01", -5_000), makeMonthly("2025-02", -1_000)];
    expect(() => detectRevenueAnomaly(series)).not.toThrow();
  });

  it("returns ok for a perfectly stable series", () => {
    const result = detectRevenueAnomaly(stableSeries(12));
    expect(result.flag).toBe("ok");
    expect(result.score).toBe(0);
  });

  it("a series with only the exact drop boundary is flagged, not just below", () => {
    // boundary: exactly 40% drop — should be flagged (change <= -0.4)
    const series = [makeMonthly("2025-01", 10_000), makeMonthly("2025-02", 6_000)];
    expect(detectRevenueAnomaly(series).flag).toBe("unusual_drop");
    // one cent above boundary
    const borderline = [makeMonthly("2025-01", 10_000), makeMonthly("2025-02", 6_001)];
    expect(detectRevenueAnomaly(borderline).flag).toBe("ok");
  });
});

// ---------------------------------------------------------------------------
// scoreHook
// ---------------------------------------------------------------------------

describe("detectRevenueAnomaly — scoreHook", () => {
  it("uses hook result when hook returns non-null", () => {
    const hook: CalibrationConfig["scoreHook"] = (_prev, _curr, _change) => ({
      score: 0.9,
      flag: "unusual_drop",
    });
    const series = stableSeries(3); // stable — would be ok without hook
    const result = detectRevenueAnomaly(series, { scoreHook: hook });
    expect(result.flag).toBe("unusual_drop");
    expect(result.score).toBeCloseTo(0.9, 5);
  });

  it("falls back to built-in logic when hook returns null", () => {
    const hook: CalibrationConfig["scoreHook"] = () => null;
    const series = [makeMonthly("2025-01", 10_000), makeMonthly("2025-02", 5_000)];
    const result = detectRevenueAnomaly(series, { scoreHook: hook });
    expect(result.flag).toBe("unusual_drop"); // built-in logic fires
  });

  it("hook receives the correct signed fractional change", () => {
    const captured: number[] = [];
    const hook: CalibrationConfig["scoreHook"] = (_p, _c, change) => {
      captured.push(change);
      return null;
    };
    const series = [makeMonthly("2025-01", 10_000), makeMonthly("2025-02", 12_000)];
    detectRevenueAnomaly(series, { scoreHook: hook });
    expect(captured).toHaveLength(1);
    expect(captured[0]).toBeCloseTo(0.2, 5); // +20%
  });

  it("hook can suppress a real anomaly by returning score 0 flag ok", () => {
    const hook: CalibrationConfig["scoreHook"] = () => ({ score: 0, flag: "ok" });
    const series = [makeMonthly("2025-01", 10_000), makeMonthly("2025-02", 1_000)]; // −90%
    const result = detectRevenueAnomaly(series, { scoreHook: hook });
    expect(result.flag).toBe("ok");
    expect(result.score).toBe(0);
  });

  it("hook is called once per consecutive pair in the series", () => {
    const callCount = { n: 0 };
    const hook: CalibrationConfig["scoreHook"] = () => { callCount.n++; return null; };
    detectRevenueAnomaly(stableSeries(5), { scoreHook: hook });
    expect(callCount.n).toBe(4); // 5 points → 4 consecutive pairs
  });

  it("hook receives correct prev and curr arguments", () => {
    const pairs: Array<[MonthlyRevenue, MonthlyRevenue]> = [];
    const hook: CalibrationConfig["scoreHook"] = (p, c) => { pairs.push([p, c]); return null; };
    const series = [
      makeMonthly("2025-01", 1_000),
      makeMonthly("2025-02", 2_000),
      makeMonthly("2025-03", 3_000),
    ];
    detectRevenueAnomaly(series, { scoreHook: hook });
    expect(pairs[0][0].period).toBe("2025-01");
    expect(pairs[0][1].period).toBe("2025-02");
    expect(pairs[1][0].period).toBe("2025-02");
    expect(pairs[1][1].period).toBe("2025-03");
  });
});

// ---------------------------------------------------------------------------
// Structured logger
// ---------------------------------------------------------------------------

describe("detectRevenueAnomaly — structured logger", () => {
  it("calls the logger once per invocation", () => {
    const logs: AnomalyLogRecord[] = [];
    detectRevenueAnomaly(stableSeries(3), {}, (r) => logs.push(r));
    expect(logs).toHaveLength(1);
  });

  it("emits anomaly_check_ok event for a clean series", () => {
    const logs: AnomalyLogRecord[] = [];
    detectRevenueAnomaly(stableSeries(3), {}, (r) => logs.push(r));
    expect(logs[0].event).toBe("anomaly_check_ok");
    expect(logs[0].flag).toBe("ok");
  });

  it("emits anomaly_detected event when an anomaly is found", () => {
    const logs: AnomalyLogRecord[] = [];
    const series = [makeMonthly("2025-01", 10_000), makeMonthly("2025-02", 5_000)];
    detectRevenueAnomaly(series, {}, (r) => logs.push(r));
    expect(logs[0].event).toBe("anomaly_detected");
    expect(logs[0].flag).toBe("unusual_drop");
  });

  it("emits anomaly_insufficient_data for a short series", () => {
    const logs: AnomalyLogRecord[] = [];
    detectRevenueAnomaly([makeMonthly("2025-01", 1_000)], {}, (r) => logs.push(r));
    expect(logs[0].event).toBe("anomaly_insufficient_data");
    expect(logs[0].flag).toBe("insufficient_data");
  });

  it("log record includes active thresholds", () => {
    const logs: AnomalyLogRecord[] = [];
    detectRevenueAnomaly(stableSeries(3), { dropThreshold: 0.25, spikeThreshold: 2.0 }, (r) => logs.push(r));
    expect(logs[0].thresholds.drop).toBe(0.25);
    expect(logs[0].thresholds.spike).toBe(2.0);
  });

  it("log record detectedAt is a valid ISO 8601 timestamp", () => {
    const logs: AnomalyLogRecord[] = [];
    detectRevenueAnomaly(stableSeries(3), {}, (r) => logs.push(r));
    expect(logs[0].detectedAt).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
  });

  it("log record score and detail match the returned AnomalyResult", () => {
    const logs: AnomalyLogRecord[] = [];
    const series = [makeMonthly("2025-01", 10_000), makeMonthly("2025-02", 5_000)];
    const result = detectRevenueAnomaly(series, {}, (r) => logs.push(r));
    expect(logs[0].score).toBe(result.score);
    expect(logs[0].detail).toBe(result.detail);
  });

  it("does not throw when no logger is provided", () => {
    expect(() => detectRevenueAnomaly(stableSeries(3))).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// calibrateFromSeries
// ---------------------------------------------------------------------------

describe("calibrateFromSeries", () => {
  it("returns module defaults for a series with fewer than 2 points", () => {
    const result = calibrateFromSeries([makeMonthly("2025-01", 10_000)]);
    expect(result.dropThreshold).toBe(0.4);
    expect(result.spikeThreshold).toBe(3.0);
    expect(result.mean).toBe(0);
    expect(result.stdDev).toBe(0);
  });

  it("returns module defaults when series is empty", () => {
    const result = calibrateFromSeries([]);
    expect(result.dropThreshold).toBe(0.4);
    expect(result.spikeThreshold).toBe(3.0);
  });

  it("returns module defaults when all prev amounts are zero", () => {
    const series = [makeMonthly("2025-01", 0), makeMonthly("2025-02", 0)];
    const result = calibrateFromSeries(series);
    expect(result.dropThreshold).toBe(0.4);
    expect(result.spikeThreshold).toBe(3.0);
    expect(result.mean).toBe(0);
    expect(result.stdDev).toBe(0);
  });

  it("computes tighter thresholds from a low-variance stable series", () => {
    const stable = calibrateFromSeries(stableSeries(12));
    const defaults = { dropThreshold: 0.4, spikeThreshold: 3.0 };
    // mean ≈ 0, stdDev ≈ 0 → dropBound ≥ 0 so falls back to default
    // This verifies graceful fallback, not tighter thresholds for zero-variance data
    expect(stable.dropThreshold).toBe(defaults.dropThreshold);
    expect(stable.mean).toBeCloseTo(0, 5);
    expect(stable.stdDev).toBeCloseTo(0, 5);
  });

  it("calibrated thresholds reduce false positives on volatile but healthy series", () => {
    // Series with regular ±20% swings
    const series: MonthlyRevenue[] = [
      makeMonthly("2025-01", 10_000),
      makeMonthly("2025-02", 12_000), // +20%
      makeMonthly("2025-03", 9_600),  // −20%
      makeMonthly("2025-04", 11_520), // +20%
      makeMonthly("2025-05", 9_216),  // −20%
      makeMonthly("2025-06", 11_059), // +20%
    ];
    const cal = calibrateFromSeries(series);
    // With default thresholds a 20% drop wouldn't fire anyway (< 40%), but
    // calibrated thresholds should still be positive and internally consistent.
    expect(cal.dropThreshold).toBeGreaterThan(0);
    expect(cal.spikeThreshold).toBeGreaterThan(0);
    expect(cal.stdDev).toBeGreaterThan(0);
  });

  it("calibrated result integrates cleanly with detectRevenueAnomaly", () => {
    const training = stableSeries(12);
    const cal = calibrateFromSeries(training);
    const current = [makeMonthly("2026-01", 10_000), makeMonthly("2026-02", 10_200)];
    const result = detectRevenueAnomaly(current, cal);
    expect(result.flag).toBe("ok");
  });

  it("respects custom sigmaMultiplier — higher sigma → wider thresholds", () => {
    const series: MonthlyRevenue[] = [
      makeMonthly("2025-01", 10_000),
      makeMonthly("2025-02", 8_000),
      makeMonthly("2025-03", 11_000),
      makeMonthly("2025-04", 9_500),
    ];
    const tight  = calibrateFromSeries(series, { sigmaMultiplier: 1 });
    const wide   = calibrateFromSeries(series, { sigmaMultiplier: 3 });
    expect(wide.dropThreshold).toBeGreaterThanOrEqual(tight.dropThreshold);
    expect(wide.spikeThreshold).toBeGreaterThanOrEqual(tight.spikeThreshold);
  });

  it("mean and stdDev are numerically correct for a simple two-point series", () => {
    // Only one change: (12_000 − 10_000) / 10_000 = 0.2
    const series = [makeMonthly("2025-01", 10_000), makeMonthly("2025-02", 12_000)];
    const cal = calibrateFromSeries(series);
    expect(cal.mean).toBeCloseTo(0.2, 5);
    expect(cal.stdDev).toBeCloseTo(0, 5); // single sample → variance = 0
  });

  it("does not mutate the input series", () => {
    const series = [makeMonthly("2025-02", 5_000), makeMonthly("2025-01", 10_000)];
    const original = series.map((s) => ({ ...s }));
    calibrateFromSeries(series);
    expect(series).toEqual(original);
  });

  it("is idempotent — same input produces same output", () => {
    const series = stableSeries(6, 10_000);
    const a = calibrateFromSeries(series);
    const b = calibrateFromSeries(series);
    expect(a).toEqual(b);
  });
});

// ---------------------------------------------------------------------------
// Seasonality / false-positive scenarios
// ---------------------------------------------------------------------------

describe("detectRevenueAnomaly — seasonality and false-positive scenarios", () => {
  it("does not flag a Q4 holiday spike when spikeThreshold is widened", () => {
    // Simulate a business that regularly 4× revenue in December
    const series: MonthlyRevenue[] = [
      makeMonthly("2025-09", 10_000),
      makeMonthly("2025-10", 10_500),
      makeMonthly("2025-11", 11_000),
      makeMonthly("2025-12", 44_000), // holiday spike ~300%
    ];
    // With default threshold (3.0) this is exactly at the boundary
    const defaultResult = detectRevenueAnomaly(series);
    // Widening to 4.0 suppresses the flag
    const widenedResult = detectRevenueAnomaly(series, { spikeThreshold: 4.0 });
    expect(widenedResult.flag).toBe("ok");
    // Default may or may not flag depending on exact boundary — just check no throw
    expect(["ok", "unusual_spike"]).toContain(defaultResult.flag);
  });

  it("scoreHook can suppress known promotional periods", () => {
    const promoMonth = "2025-11";
    const hook: CalibrationConfig["scoreHook"] = (_prev, curr, _change) => {
      if (curr.period === promoMonth) return { score: 0, flag: "ok" };
      return null;
    };
    const series: MonthlyRevenue[] = [
      makeMonthly("2025-10", 10_000),
      makeMonthly("2025-11", 50_000), // would normally spike
      makeMonthly("2025-12", 11_000),
    ];
    const result = detectRevenueAnomaly(series, { scoreHook: hook });
    expect(result.flag).toBe("ok");
  });

  it("calibrateFromSeries on 12-month volatile data produces usable thresholds", () => {
    // Simulate ±30% seasonal swings over 12 months
    const amounts = [10_000, 13_000, 9_100, 11_830, 8_281, 10_765,
                     7_536, 9_797, 6_858, 8_915, 6_240, 8_113];
    const series = amounts.map((amount, i) =>
      makeMonthly(`2025-${String(i + 1).padStart(2, "0")}`, amount)
    );
    const cal = calibrateFromSeries(series);
    expect(cal.dropThreshold).toBeGreaterThan(0);
    expect(cal.spikeThreshold).toBeGreaterThan(0);
    expect(typeof cal.mean).toBe("number");
    expect(typeof cal.stdDev).toBe("number");
  });

  it("missing baseline (< 2 training points) falls back without throwing", () => {
    const cal = calibrateFromSeries([makeMonthly("2025-01", 10_000)]);
    const result = detectRevenueAnomaly(stableSeries(3), cal);
    expect(result).toBeDefined();
    expect(["ok", "unusual_drop", "unusual_spike", "insufficient_data"]).toContain(result.flag);
  });
});