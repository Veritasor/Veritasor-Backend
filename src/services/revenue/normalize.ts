/**
 * Revenue normalizer — converts raw revenue data from any payment source
 * into a canonical, consistent shape.
 */

export type RawRevenueInput = {
  id: string;
  amount: number;
  currency?: string;
  date?: string | number;
  source?: string;
  [key: string]: unknown;
};

export type NormalizedRevenue = {
  id: string;
  amount: number;
  currency: string;
  date: string; // ISO 8601
  type: "payment" | "refund";
  source: string;
};

/**
 * Normalize a raw revenue entry into a canonical shape.
 *
 * - Negative amounts are classified as `type: 'refund'`; positive as `type: 'payment'`.
 * - Currency codes are normalized to uppercase (e.g. `'usd'` → `'USD'`).
 * - Dates are normalized to ISO 8601 strings. Numeric values are treated as Unix
 *   timestamps in seconds.
 */
export function normalizeRevenueEntry(raw: RawRevenueInput): NormalizedRevenue {
  // Determine type from amount sign
  const type: "payment" | "refund" = raw.amount < 0 ? "refund" : "payment";

  // Normalize currency to uppercase; default to 'USD'
  const currency = raw.currency ? raw.currency.toUpperCase() : "USD";

  // Normalize date to ISO string
  let date: string;
  if (typeof raw.date === "number") {
    // Treat as Unix timestamp in seconds
    date = new Date(raw.date * 1000).toISOString();
  } else if (typeof raw.date === "string" && raw.date.length > 0) {
    // Try parsing as date string
    const parsed = new Date(raw.date);
    date = isNaN(parsed.getTime())
      ? new Date().toISOString()
      : parsed.toISOString();
  } else {
    date = new Date().toISOString();
  }

  const source = raw.source || "unknown";

  return {
    id: raw.id,
    amount: raw.amount,
    currency,
    date,
    type,
    source,
  };
}

export default normalizeRevenueEntry;

// ---------------------------------------------------------------------------
// Normalization Drift Detection
// ---------------------------------------------------------------------------

/** Minimum entries required for drift analysis by default. */
const DEFAULT_MIN_ENTRIES = 5;

/** Relative deviation from baseline that triggers a drift flag by default. */
const DEFAULT_DRIFT_THRESHOLD = 0.25;

/**
 * Statistical baseline describing expected normalization behaviour.
 * All rates are fractions in [0, 1].
 */
export type NormalizationBaseline = {
  /** Expected fraction of entries classified as refunds. */
  refundRate: number;
  /** Expected fraction of entries whose source defaulted to "unknown". */
  unknownSourceRate: number;
  /** Expected fraction of entries whose currency is "USD" (explicit or defaulted). */
  usdRate: number;
  /** Expected mean absolute amount across entries. */
  meanAmount: number;
};

export type DriftFlag =
  | "ok"
  | "refund_rate_drift"
  | "unknown_source_drift"
  | "usd_rate_drift"
  | "amount_drift"
  | "insufficient_data";

export type DriftCheck = {
  /** Name of the metric being checked. */
  metric: string;
  /** Baseline (expected) value for this metric. */
  expected: number;
  /** Observed value for this metric in the current batch. */
  observed: number;
  /** Relative deviation score clamped to [0, 1]. 0 = no drift, 1 = maximum. */
  score: number;
  flag: DriftFlag;
  /** Human-readable explanation of the check result. */
  detail: string;
};

export type NormalizationDriftResult = {
  /** True if at least one metric exceeded the drift threshold. */
  hasDrift: boolean;
  /** Maximum score across all checks; 0 = no drift, 1 = severe drift. */
  overallScore: number;
  checks: DriftCheck[];
  /** Human-readable summary of the drift analysis. */
  summary: string;
};

export type DriftOptions = {
  /**
   * Relative deviation required to flag drift.
   * E.g. 0.25 means flag when |observed − expected| / expected > 25%.
   * Default: 0.25.
   */
  threshold?: number;
  /** Minimum number of entries needed for analysis. Default: 5. */
  minEntries?: number;
};

/**
 * Detect statistical drift in a batch of already-normalized revenue entries.
 *
 * Computes four metrics from the batch—refund rate, unknown-source rate,
 * USD-currency rate, and mean absolute amount—then compares each against
 * the provided `baseline`. A metric is flagged when its relative deviation
 * from the baseline exceeds `options.threshold` (default 25%).
 *
 * Use this after running `normalizeRevenueEntry` on each raw entry to catch
 * pipeline regressions such as a spike in missing source fields or an
 * unexpected shift in refund volume.
 *
 * @param entries   Array of already-normalized revenue entries.
 * @param baseline  Expected statistical properties of a healthy batch.
 * @param options   Optional tuning parameters.
 * @returns         Drift analysis with per-metric checks and a summary.
 *
 * @example
 * const normalized = rawEntries.map(normalizeRevenueEntry);
 * const baseline = { refundRate: 0.05, unknownSourceRate: 0.02, usdRate: 0.8, meanAmount: 150 };
 * const result = detectNormalizationDrift(normalized, baseline);
 * if (result.hasDrift) console.warn("Drift detected:", result.summary);
 */
export function detectNormalizationDrift(
  entries: NormalizedRevenue[],
  baseline: NormalizationBaseline,
  options: DriftOptions = {}
): NormalizationDriftResult {
  const threshold = options.threshold ?? DEFAULT_DRIFT_THRESHOLD;
  const minEntries = options.minEntries ?? DEFAULT_MIN_ENTRIES;

  if (!entries || entries.length < minEntries) {
    return {
      hasDrift: false,
      overallScore: 0,
      checks: [
        {
          metric: "entry_count",
          expected: minEntries,
          observed: entries?.length ?? 0,
          score: 0,
          flag: "insufficient_data",
          detail: `Need at least ${minEntries} entries; received ${entries?.length ?? 0}.`,
        },
      ],
      summary: `Insufficient data for drift analysis (${entries?.length ?? 0} entries).`,
    };
  }

  const total = entries.length;
  const refundCount = entries.filter((e) => e.type === "refund").length;
  const unknownSourceCount = entries.filter((e) => e.source === "unknown").length;
  const usdCount = entries.filter((e) => e.currency === "USD").length;
  const meanAbsAmount =
    entries.reduce((sum, e) => sum + Math.abs(e.amount), 0) / total;

  const checks: DriftCheck[] = [
    buildDriftCheck("refund_rate", baseline.refundRate, refundCount / total, threshold, "refund_rate_drift"),
    buildDriftCheck("unknown_source_rate", baseline.unknownSourceRate, unknownSourceCount / total, threshold, "unknown_source_drift"),
    buildDriftCheck("usd_rate", baseline.usdRate, usdCount / total, threshold, "usd_rate_drift"),
    buildDriftCheck("mean_amount", baseline.meanAmount, meanAbsAmount, threshold, "amount_drift"),
  ];

  const driftedChecks = checks.filter((c) => c.flag !== "ok");
  const overallScore = Math.max(...checks.map((c) => c.score));
  const hasDrift = driftedChecks.length > 0;

  const summary = hasDrift
    ? `Drift detected in ${driftedChecks.length} metric(s): ${driftedChecks.map((c) => c.metric).join(", ")}.`
    : "No normalization drift detected.";

  return { hasDrift, overallScore, checks, summary };
}

/**
 * Build a single `DriftCheck` by comparing an observed value against a baseline.
 * @internal
 */
function buildDriftCheck(
  metric: string,
  expected: number,
  observed: number,
  threshold: number,
  driftFlag: DriftFlag
): DriftCheck {
  const relativeDeviation =
    expected === 0
      ? observed === 0 ? 0 : 1
      : Math.abs(observed - expected) / expected;

  const score = Math.min(relativeDeviation, 1);
  const hasDrift = relativeDeviation > threshold;

  return {
    metric,
    expected,
    observed,
    score,
    flag: hasDrift ? driftFlag : "ok",
    detail: hasDrift
      ? `${metric} drifted ${(relativeDeviation * 100).toFixed(1)}% from baseline ` +
        `(expected ${expected.toFixed(4)}, observed ${observed.toFixed(4)}).`
      : `${metric} within acceptable range ` +
        `(expected ${expected.toFixed(4)}, observed ${observed.toFixed(4)}).`,
  };
}
