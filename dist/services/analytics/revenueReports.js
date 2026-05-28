/**
 * @module revenueReports
 *
 * @description
 * Analytics service for generating revenue reports for a given business.
 * Supports two query modes:
 *   1. **Single period** – filter by an exact YYYY-MM billing month.
 *   2. **Date range**   – filter by an inclusive YYYY-MM from/to window.
 *
 * Security notes:
 *  - All period strings are validated with a strict YYYY-MM regex before use.
 *  - The `from`/`to` range is checked for logical ordering (from <= to).
 *  - The range is capped at MAX_RANGE_MONTHS (24) to prevent unbounded queries.
 *  - businessId is sourced exclusively from authenticated middleware and is not
 *    user-controllable.
 */
import { attestationRepository } from '../../repositories/attestation.js';
// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
/** Maximum allowed range between `from` and `to` in months. */
const MAX_RANGE_MONTHS = 24;
/** Regex used to validate any period/from/to parameter. */
const PERIOD_REGEX = /^\d{4}-\d{2}$/;
// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------
/**
 * Thrown when the supplied time-window parameters are invalid.
 * Callers (e.g. route handlers) should catch this and return HTTP 400.
 */
export class TimeWindowError extends Error {
    code = 'INVALID_TIME_WINDOW';
    constructor(message) {
        super(message);
        this.name = 'TimeWindowError';
    }
}
// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
/**
 * Parse a YYYY-MM string into a numeric year and month.
 * Throws {@link TimeWindowError} if the format is invalid.
 *
 * @param value - The period string to parse.
 * @param label - Human-readable name used in the error message.
 */
const parsePeriod = (value, label) => {
    if (!PERIOD_REGEX.test(value)) {
        throw new TimeWindowError(`Invalid format for "${label}": "${value}". Expected YYYY-MM (e.g. 2025-10).`);
    }
    const [year, month] = value.split('-').map(Number);
    return { year, month };
};
/**
 * Convert a parsed { year, month } object to a comparable integer (YYYYMM).
 */
const toOrdinal = ({ year, month }) => year * 12 + (month - 1);
// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------
/**
 * Generate a revenue report for a business within a specified time window.
 *
 * Exactly one of the following must be provided:
 *  - `period` alone → filters attestations whose `period === period`.
 *  - `from` + `to` → filters attestations where `period` falls in [from, to].
 *
 * @param businessId - The authenticated business identifier.
 * @param period     - A single YYYY-MM month (mutually exclusive with from/to).
 * @param from       - Start of an inclusive YYYY-MM range.
 * @param to         - End of an inclusive YYYY-MM range.
 *
 * @returns The revenue report, or `null` if no matching attestations exist.
 *
 * @throws {TimeWindowError} When parameters are missing, malformed, logically
 *   invalid (from > to), or exceed the 24-month range cap.
 */
export const getRevenueReport = (businessId, period, from, to) => {
    // --- Guard: at least one query mode must be present ---
    if (!period && !(from && to)) {
        throw new TimeWindowError('Provide either "period" (e.g. 2025-10) or both "from" and "to" query parameters.');
    }
    let attestations = attestationRepository.listByBusiness(businessId);
    let resolvedPeriod;
    if (period) {
        // Validate format even though Zod already does it — service is self-defending.
        parsePeriod(period, 'period');
        attestations = attestations.filter((a) => a.period === period);
        resolvedPeriod = period;
    }
    else {
        // from and to are guaranteed non-undefined here (guarded above).
        const parsedFrom = parsePeriod(from, 'from');
        const parsedTo = parsePeriod(to, 'to');
        const fromOrd = toOrdinal(parsedFrom);
        const toOrd = toOrdinal(parsedTo);
        // Guard: from must not be after to.
        if (fromOrd > toOrd) {
            throw new TimeWindowError(`"from" (${from}) must not be later than "to" (${to}).`);
        }
        // Guard: range must not exceed MAX_RANGE_MONTHS.
        const rangeMonths = toOrd - fromOrd + 1;
        if (rangeMonths > MAX_RANGE_MONTHS) {
            throw new TimeWindowError(`Date range of ${rangeMonths} months exceeds the maximum allowed window of ${MAX_RANGE_MONTHS} months.`);
        }
        attestations = attestations.filter((a) => a.period >= from && a.period <= to);
        resolvedPeriod = `${from} to ${to}`;
    }
    if (attestations.length === 0)
        return null;
    const total = attestations.length * 100; // placeholder until real revenue data lands
    const net = Math.round(total * 0.95); // placeholder 5 % fee deduction
    return {
        period: resolvedPeriod,
        total,
        net,
        currency: 'USD',
        breakdown: attestations.map((a) => ({
            attestationId: a.id,
            attestedAt: a.attestedAt,
        })),
    };
};
