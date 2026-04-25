/**
 * @module revenueReportSchema
 *
 * @description
 * Zod schema for validating query parameters on the GET /api/analytics/revenue endpoint.
 *
 * Accepted shapes:
 *   - `period` only  → a single YYYY-MM month string
 *   - `from` + `to`  → an inclusive YYYY-MM range (logical ordering enforced in the service)
 *
 * Neither shape is required at the schema level; the route handler enforces the
 * "at least one of the two shapes must be provided" rule so that the 400 messages
 * remain human-readable.
 */

import { z } from 'zod'

/** Regex for a period string in YYYY-MM format. */
const PERIOD_REGEX = /^\d{4}-\d{2}$/

const periodString = z
  .string()
  .regex(PERIOD_REGEX, 'Must be a valid YYYY-MM month string (e.g. 2025-10)')

/**
 * Query-parameter schema for the revenue report endpoint.
 *
 * @property period - A single billing month (YYYY-MM). Mutually exclusive with from/to.
 * @property from   - Start of a date range (YYYY-MM, inclusive).
 * @property to     - End of a date range (YYYY-MM, inclusive).
 */
export const revenueReportQuerySchema = z.object({
  period: periodString.optional(),
  from: periodString.optional(),
  to: periodString.optional(),
})

export type RevenueReportQuery = z.infer<typeof revenueReportQuerySchema>
