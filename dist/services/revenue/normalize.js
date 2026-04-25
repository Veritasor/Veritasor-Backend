/**
 * Revenue normalizer — converts raw revenue data from any payment source
 * into a canonical, consistent shape.
 */
/**
 * Normalize a raw revenue entry into a canonical shape.
 *
 * - Negative amounts are classified as `type: 'refund'`; positive as `type: 'payment'`.
 * - Currency codes are normalized to uppercase (e.g. `'usd'` → `'USD'`).
 * - Dates are normalized to ISO 8601 strings. Numeric values are treated as Unix
 *   timestamps in seconds.
 */
export function normalizeRevenueEntry(raw) {
    // Determine type from amount sign
    const type = raw.amount < 0 ? "refund" : "payment";
    // Normalize currency to uppercase; default to 'USD'
    const currency = raw.currency ? raw.currency.toUpperCase() : "USD";
    // Normalize date to ISO string
    let date;
    if (typeof raw.date === "number") {
        // Treat as Unix timestamp in seconds
        date = new Date(raw.date * 1000).toISOString();
    }
    else if (typeof raw.date === "string" && raw.date.length > 0) {
        // Try parsing as date string
        const parsed = new Date(raw.date);
        date = isNaN(parsed.getTime())
            ? new Date().toISOString()
            : parsed.toISOString();
    }
    else {
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
export function detectNormalizationDrift(entries, baseline, options = {}) {
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
    const meanAbsAmount = entries.reduce((sum, e) => sum + Math.abs(e.amount), 0) / total;
    const checks = [
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
function buildDriftCheck(metric, expected, observed, threshold, driftFlag) {
    const relativeDeviation = expected === 0
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
