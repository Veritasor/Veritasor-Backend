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
