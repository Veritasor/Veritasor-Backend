/**
 * @module periods
 *
 * @description
 * DST-safe analytics period helpers.
 *
 * ## Why UTC matters for period boundaries
 *
 * When the server runs in a non-UTC timezone (or when users span multiple
 * timezones), JavaScript's local-time `Date` methods introduce DST hazards:
 *
 *   - In the US/Eastern zone, clocks spring forward at 2024-03-10 02:00 local,
 *     meaning `new Date(2024, 2, 10, 2, 0, 0)` is invalid local time.
 *   - In the US/Eastern zone, clocks fall back at 2024-11-03 02:00 local,
 *     creating an ambiguous hour that can silently misclassify timestamps.
 *
 * By anchoring every period boundary to **UTC midnight** via `Date.UTC`, and
 * reading timestamps with `getUTC*` methods, we ensure that a YYYY-MM period
 * always spans exactly the intended calendar month, regardless of where the
 * server process is running.
 *
 * @security
 * Period strings are validated with a strict YYYY-MM regex before any numeric
 * parsing, preventing injection through malformed date inputs.
 */
import { attestationRepository } from '../../repositories/attestation.js';
// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
/** Strict YYYY-MM regex. Rejects partial matches and arbitrary separators. */
const PERIOD_REGEX = /^\d{4}-\d{2}$/;
// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------
/**
 * Thrown when a period string cannot be parsed.
 * Callers (e.g. route handlers) should catch this and return HTTP 400.
 */
export class PeriodParseError extends Error {
    code = 'INVALID_PERIOD';
    constructor(value) {
        super(`Invalid period string "${value}". Expected YYYY-MM (e.g. 2025-10).`);
        this.name = 'PeriodParseError';
    }
}
// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
/**
 * Convert a YYYY-MM period string to DST-safe UTC bounds.
 *
 * Uses `Date.UTC` so boundaries are always at UTC midnight, regardless of the
 * server's local offset or any DST transition that may occur during the month.
 *
 * @example
 * const { start, end } = parsePeriodToBounds('2024-03')
 * // start → 2024-03-01T00:00:00.000Z
 * // end   → 2024-04-01T00:00:00.000Z  (exclusive)
 *
 * const { start, end } = parsePeriodToBounds('2024-12')
 * // start → 2024-12-01T00:00:00.000Z
 * // end   → 2025-01-01T00:00:00.000Z  (rolls over to next year correctly)
 *
 * @throws {PeriodParseError} if `period` does not match YYYY-MM.
 */
export const parsePeriodToBounds = (period) => {
    if (!PERIOD_REGEX.test(period)) {
        throw new PeriodParseError(period);
    }
    const [year, month] = period.split('-').map(Number);
    // Date.UTC normalises overflow: month=13 rolls to Jan of the next year.
    const start = new Date(Date.UTC(year, month - 1, 1));
    const end = new Date(Date.UTC(year, month, 1)); // first day of next month
    return { start, end };
};
/**
 * Derive the YYYY-MM period label for a given `Date` object.
 *
 * Reads `getUTCFullYear` / `getUTCMonth` instead of the local-time equivalents
 * to remain DST-neutral regardless of the server's timezone.
 *
 * @example
 * // Server running in US/Eastern (UTC-5 in winter):
 * dateToPeriod(new Date('2024-03-01T03:00:00.000Z'))
 * // → '2024-03'  (correct UTC month, not local March or February)
 *
 * dateToPeriod(new Date('2024-11-01T03:59:00.000Z'))
 * // → '2024-11'  (stays in November even during fall-back hour)
 */
export const dateToPeriod = (date) => {
    const year = date.getUTCFullYear();
    const month = String(date.getUTCMonth() + 1).padStart(2, '0');
    return `${year}-${month}`;
};
/**
 * Return the current YYYY-MM period in UTC.
 *
 * Useful for "default to current period" logic without DST exposure.
 *
 * @example
 * // On 2025-10-15, any timezone:
 * currentPeriod() // → '2025-10'
 */
export const currentPeriod = () => dateToPeriod(new Date());
/**
 * Check whether a Unix epoch timestamp (in **seconds**) falls within the
 * given YYYY-MM period.
 *
 * Comparison uses UTC-anchored boundaries to avoid DST misclassification.
 * Ownership is `[start, end)` — `end` is exclusive.
 *
 * @param timestampSeconds - Unix timestamp in seconds (as stored on-chain or
 *   in the attestation record).
 * @param period - YYYY-MM period string (e.g. `'2024-03'`).
 *
 * @example
 * // March DST spring-forward in US/Eastern (2024-03-10 02:00 → 03:00):
 * isTimestampInPeriod(1709856000, '2024-03') // 2024-03-08 00:00 UTC → true
 * isTimestampInPeriod(1711929599, '2024-03') // 2024-03-31 23:59:59 UTC → true
 * isTimestampInPeriod(1711929600, '2024-03') // 2024-04-01 00:00 UTC → false
 *
 * @throws {PeriodParseError} if `period` is not a valid YYYY-MM string.
 */
export const isTimestampInPeriod = (timestampSeconds, period) => {
    const { start, end } = parsePeriodToBounds(period);
    const tsMs = timestampSeconds * 1000;
    return tsMs >= start.getTime() && tsMs < end.getTime();
};
// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------
/**
 * Return the distinct YYYY-MM periods that have been attested for a business,
 * sorted in descending order (most recent first).
 *
 * Period strings are YYYY-MM values stored directly on attestation records;
 * they do not require further DST adjustment. The sort uses `localeCompare`
 * which, for YYYY-MM strings, is equivalent to lexicographic / chronological
 * ordering.
 *
 * @param businessId - The authenticated business identifier.
 */
export const listAttestedPeriodsForBusiness = (businessId) => {
    const attestations = attestationRepository.listByBusiness(businessId);
    return Array.from(new Set(attestations.map((a) => a.period))).sort((a, b) => b.localeCompare(a));
};
