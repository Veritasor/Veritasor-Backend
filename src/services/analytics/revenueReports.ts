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

import { revenueSnapshotRepository } from '../../repositories/revenueSnapshotRepository.js'
import { listByBusiness } from '../../repositories/attestationRepository.js'
import { db } from '../../db/client.js'
import { revenueReportQuerySchema } from './revenueReportSchema.js'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Maximum allowed range between `from` and `to` in months. */
const MAX_RANGE_MONTHS = 24

/** Regex used to validate any period/from/to parameter. */
const PERIOD_REGEX = /^\d{4}-\d{2}$/

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/**
 * Thrown when the supplied time-window parameters are invalid.
 * Callers (e.g. route handlers) should catch this and return HTTP 400.
 */
export class TimeWindowError extends Error {
  public readonly code = 'INVALID_TIME_WINDOW'

  constructor(message: string) {
    super(message)
    this.name = 'TimeWindowError'
  }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * Shape of a revenue report returned by {@link getRevenueReport}.
 *
 * @property period    - Human-readable label for the report window.
 * @property total     - Gross revenue in cents (sum of `totalRevenue` snapshots).
 * @property net       - Net revenue after fees in cents (sum of `netRevenue` snapshots).
 * @property currency  - ISO 4217 currency code (taken from the snapshots).
 * @property breakdown - Per-snapshot line items.
 */
export type RevenueReport = {
  period: string
  total: number
  net: number
  currency: string
  breakdown: { attestationId: string; attestedAt: string }[]
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
const parsePeriod = (value: string, label: string): { year: number; month: number } => {
  if (!PERIOD_REGEX.test(value)) {
    throw new TimeWindowError(
      `Invalid format for "${label}": "${value}". Expected YYYY-MM (e.g. 2025-10).`,
    )
  }
  const [year, month] = value.split('-').map(Number)
  if (month < 1 || month > 12) {
    throw new TimeWindowError(
      `Invalid month for "${label}": "${value}". Month must be between 01 and 12.`,
    )
  }
  return { year, month }
}

/**
 * Convert a parsed { year, month } object to a comparable integer (YYYYMM).
 */
const toOrdinal = ({ year, month }: { year: number; month: number }): number =>
  year * 12 + (month - 1)

/**
 * Validate the raw query parameters against {@link revenueReportQuerySchema}.
 *
 * This keeps the schema as the single source of truth for the public query
 * contract while still surfacing a {@link TimeWindowError} to callers so the
 * HTTP layer can respond with 400.
 *
 * @param period - A single YYYY-MM month (mutually exclusive with from/to).
 * @param from   - Start of an inclusive YYYY-MM range.
 * @param to     - End of an inclusive YYYY-MM range.
 *
 * @throws {TimeWindowError} When the schema rejects the supplied parameters.
 */
const validateQuery = (period?: string, from?: string, to?: string): void => {
  const result = revenueReportQuerySchema.safeParse({ period, from, to })
  if (!result.success) {
    const message = result.error.issues
      .map((issue) => issue.message)
      .join('; ')
    throw new TimeWindowError(message || 'Invalid revenue report query parameters.')
  }
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

/**
 * Generate a revenue report for a business within a specified time window.
 *
 * The report is read from `revenue_snapshots` rows written by the
 * attestation submit path:
 *  - `period` alone → queries the window [period, period].
 *  - `from` + `to` → queries the inclusive [from, to] window.
 *
 * @param businessId - The authenticated business identifier.
 * @param period     - A single YYYY-MM month (mutually exclusive with from/to).
 * @param from       - Start of an inclusive YYYY-MM range.
 * @param to         - End of an inclusive YYYY-MM range.
 *
 * @returns The revenue report, or `null` when no snapshot rows exist for the
 *   requested window.
 *
 * @throws {TimeWindowError} When parameters are missing, malformed, logically
 *   invalid (from > to), or exceed the 24-month range cap.
 */
export const getRevenueReport = async (
  businessId: string,
  period?: string,
  from?: string,
  to?: string,
): Promise<RevenueReport | null> => {
  // --- Guard: schema-level validation of the public query contract ---
  validateQuery(period, from, to)

  // --- Guard: at least one query mode must be present ---
  if (!period && !(from && to)) {
    throw new TimeWindowError(
      'Provide either "period" (e.g. 2025-10) or both "from" and "to" query parameters.',
    )
  }

  let start: string
  let end: string
  let resolvedPeriod: string

  if (period) {
    // Validate format even though Zod already does it — service is self-defending.
    parsePeriod(period, 'period')

    // Single-period window: [period, period].
    start = period
    end = period
    resolvedPeriod = period
  } else {
    // from and to are guaranteed non-undefined here (guarded above).
    const parsedFrom = parsePeriod(from!, 'from')
    const parsedTo = parsePeriod(to!, 'to')

    const fromOrd = toOrdinal(parsedFrom)
    const toOrd = toOrdinal(parsedTo)

    // Guard: from must not be after to.
    if (fromOrd > toOrd) {
      throw new TimeWindowError(
        `"from" (${from}) must not be later than "to" (${to}).`,
      )
    }

    // Guard: range must not exceed MAX_RANGE_MONTHS.
    const rangeMonths = toOrd - fromOrd + 1
    if (rangeMonths > MAX_RANGE_MONTHS) {
      throw new TimeWindowError(
        `Date range of ${rangeMonths} months exceeds the maximum allowed window of ${MAX_RANGE_MONTHS} months.`,
      )
    }

    start = from!
    end = to!
    resolvedPeriod = `${from} to ${to}`
  }

  const snapshots = await revenueSnapshotRepository.listByBusinessAndRange(businessId, start, end)
    resolvedPeriod = `${from} to ${to}`
  }

  const records = await listByBusiness(db, businessId)
  const attestations = records.filter((a) => period
    ? a.period === period
    : a.period >= from! && a.period <= to!)

  if (attestations.length === 0) return null

  if (snapshots.length === 0) return null

  const total = snapshots.reduce((sum, snapshot) => sum + snapshot.totalRevenue, 0)
  const net = snapshots.reduce((sum, snapshot) => sum + snapshot.netRevenue, 0)

  return {
    period: resolvedPeriod,
    total,
    net,
    currency: snapshots[0].currency,
    breakdown: snapshots.map((snapshot) => ({
      attestationId: snapshot.id,
      attestedAt: snapshot.createdAt,
    currency: 'USD',
    breakdown: attestations.map((a) => ({
      attestationId: a.id,
      attestedAt: a.createdAt.toISOString(),
    })),
  }
}
