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
 * Period strings are validated with a strict YYYY-MM / YYYY-Q1..Q4 regex
 * before any numeric parsing, preventing injection through malformed inputs.
 */

import { attestationRepository } from '../../repositories/attestation.js'
import { AppError, VRTErrorCodes } from '../../types/errors.js'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * Strict period regex shared by the analytics helpers and the attestation
 * route schema so both accept exactly the same formats.
 *
 * Accepts `YYYY-MM` (01-12) and `YYYY-Q1`..`YYYY-Q4`. Anchored to reject
 * partial matches, whitespace, and arbitrary separators.
 */
export const PERIOD_REGEX = /^\d{4}-(?:0[1-9]|1[0-2]|Q[1-4])$/

/** Human-readable description used in validation messages. */
export const PERIOD_FORMAT = 'YYYY-MM (e.g. 2025-10) or YYYY-Q1..Q4 (e.g. 2025-Q4)'

const MONTH_PERIOD_REGEX = /^\d{4}-(?:0[1-9]|1[0-2])$/
const QUARTER_PERIOD_REGEX = /^\d{4}-Q[1-4]$/

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/**
 * Thrown when a period string cannot be parsed.
 *
 * Extends `AppError` so callers that do not explicitly catch it still turn an
 * invalid period into an HTTP 400 rather than a 500.
 */
export class PeriodParseError extends AppError {
  public readonly code = 'INVALID_PERIOD' as const

  constructor(value: string) {
    super(
      `Invalid period string "${value}". Expected ${PERIOD_FORMAT}.`,
      400,
      VRTErrorCodes.VRT_0002,
      { period: value },
    )
    this.name = 'PeriodParseError'
  }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * Inclusive start / exclusive end boundaries for a YYYY-MM period.
 * Both dates are anchored at UTC midnight to avoid DST discontinuities.
 *
 * Treat `end` as an **exclusive** upper bound: a timestamp `t` belongs to the
 * period if and only if `start <= t < end`.
 */
export type PeriodBounds = {
  /** UTC midnight on the first day of the period month. */
  start: Date
  /** UTC midnight on the first day of the month after the period (exclusive). */
  end: Date
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Convert a YYYY-MM or YYYY-Q1..Q4 period string to DST-safe UTC bounds.
 *
 * Uses `Date.UTC` so boundaries are always at UTC midnight, regardless of the
 * server's local offset or any DST transition that may occur during the
 * period. Quarter bounds always start on the first day of the quarter's first
 * month and end on the first day of the following quarter.
 *
 * @example
 * const { start, end } = parsePeriodToBounds('2024-03')
 * // start → 2024-03-01T00:00:00.000Z
 * // end   → 2024-04-01T00:00:00.000Z  (exclusive)
 *
 * const { start, end } = parsePeriodToBounds('2024-Q4')
 * // start → 2024-10-01T00:00:00.000Z
 * // end   → 2025-01-01T00:00:00.000Z  (rolls over to next year correctly)
 *
 * @throws {PeriodParseError} if `period` is not a supported format.
 */
export const parsePeriodToBounds = (period: string): PeriodBounds => {
  if (!PERIOD_REGEX.test(period)) {
    throw new PeriodParseError(period)
  }

  const [yearPart, unit] = period.split('-')
  const year = Number(yearPart)
  const isQuarter = QUARTER_PERIOD_REGEX.test(period)
  // Date.UTC normalises overflow: month=12 rolls to Jan of the next year.
  const firstMonth = isQuarter
    ? (Number(unit.slice(1)) - 1) * 3 + 1
    : Number(unit)

  const start = new Date(Date.UTC(year, firstMonth - 1, 1))
  const end = new Date(Date.UTC(year, firstMonth - 1 + (isQuarter ? 3 : 1), 1))
  return { start, end }
}

/**
 * Inclusive ISO-8601 window for a period, derived from the same UTC bounds as
 * `parsePeriodToBounds`. Used by callers (e.g. Razorpay revenue fetching) that
 * take inclusive `startDate` / `endDate` strings instead of `Date` objects.
 *
 * The end timestamp is the final second of the period, so a month or quarter
 * never leaks into the next one, regardless of the server's timezone.
 *
 * @example
 * parsePeriodToIsoRange('2024-02')
 * // → { startDate: '2024-02-01T00:00:00Z', endDate: '2024-02-29T23:59:59Z' }
 *
 * @throws {PeriodParseError} if `period` is not a supported format.
 */
export const parsePeriodToIsoRange = (period: string): { startDate: string; endDate: string } => {
  const { start, end } = parsePeriodToBounds(period)
  const lastSecond = new Date(end.getTime() - 1000)

  return {
    startDate: `${start.toISOString().slice(0, 10)}T00:00:00Z`,
    endDate: `${lastSecond.toISOString().slice(0, 10)}T23:59:59Z`,
  }
}

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
export const dateToPeriod = (date: Date): string => {
  const year = date.getUTCFullYear()
  const month = String(date.getUTCMonth() + 1).padStart(2, '0')
  return `${year}-${month}`
}

/**
 * Return the current YYYY-MM period in UTC.
 *
 * Useful for "default to current period" logic without DST exposure.
 *
 * @example
 * // On 2025-10-15, any timezone:
 * currentPeriod() // → '2025-10'
 */
export const currentPeriod = (): string => dateToPeriod(new Date())

/**
 * Check whether a Unix epoch timestamp (in **seconds**) falls within the
 * given YYYY-MM period.
 *
 * Comparison uses UTC-anchored boundaries to avoid DST misclassification.
 * Ownership is `[start, end)` — `end` is exclusive.
 *
 * @param timestampSeconds - Unix timestamp in seconds (as stored on-chain or
 *   in the attestation record).
 * @param period - YYYY-MM or YYYY-Q1..Q4 period string (e.g. `'2024-03'`).
 *
 * @example
 * // March DST spring-forward in US/Eastern (2024-03-10 02:00 → 03:00):
 * isTimestampInPeriod(1709856000, '2024-03') // 2024-03-08 00:00 UTC → true
 * isTimestampInPeriod(1711929599, '2024-03') // 2024-03-31 23:59:59 UTC → true
 * isTimestampInPeriod(1711929600, '2024-03') // 2024-04-01 00:00 UTC → false
 *
 * @throws {PeriodParseError} if `period` is not a valid period string.
 */
export const isTimestampInPeriod = (timestampSeconds: number, period: string): boolean => {
  const { start, end } = parsePeriodToBounds(period)
  const tsMs = timestampSeconds * 1000
  return tsMs >= start.getTime() && tsMs < end.getTime()
}

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
export const listAttestedPeriodsForBusiness = (businessId: string): string[] => {
  const attestations = attestationRepository.listByBusiness(businessId)
  return Array.from(new Set(attestations.map((a) => a.period))).sort((a, b) =>
    b.localeCompare(a),
  )
}
