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
 *
 * Security hardening:
 * - Strict YYYY-MM format validation with reasonable year bounds
 * - Length limits to prevent DoS via extremely long strings
 * - Explicit error messages for security monitoring
 * - Prevention of injection attempts through pattern validation
 */

import { z } from 'zod'

/** Regex for a period string in YYYY-MM format with year bounds. */
const PERIOD_REGEX = /^(20[2-9]\d|210[0-5])-(0[1-9]|1[0-2])$/

/** Maximum length for period strings to prevent DoS attacks. */
const MAX_PERIOD_LENGTH = 7

/** Minimum year to prevent unreasonable dates (year 2020). */
const MIN_YEAR = 2020

/** Maximum year to prevent unreasonable dates (year 2105). */
const MAX_YEAR = 2105

const periodString = z
  .string()
  .max(MAX_PERIOD_LENGTH, 'Period string too long (max 7 characters)')
  .min(7, 'Period string must be exactly 7 characters (YYYY-MM)')
  .regex(PERIOD_REGEX, 'Must be a valid YYYY-MM month string between 2020-01 and 2105-12 (e.g. 2025-10)')
  .refine((value) => {
    // Additional validation to prevent injection attempts
    const [year, month] = value.split('-').map(Number)
    return year >= MIN_YEAR && year <= MAX_YEAR && month >= 1 && month <= 12
  }, 'Year must be between 2020 and 2105, month must be between 01 and 12')
  .refine((value) => {
    // Prevent potential injection patterns
    const suspiciousPatterns = ['<', '>', '&', '"', "'", ';', '\\', '/', '/*', '*/', '--']
    return !suspiciousPatterns.some(pattern => value.includes(pattern))
  }, 'Period string contains invalid characters')

/**
 * Query-parameter schema for the revenue report endpoint.
 *
 * Security hardening applied:
 * - Strict format validation with year bounds (2020-2105)
 * - Length limits to prevent DoS attacks
 * - Injection prevention through character filtering
 * - Explicit error messages for security monitoring
 *
 * @property period - A single billing month (YYYY-MM). Mutually exclusive with from/to.
 * @property from   - Start of a date range (YYYY-MM, inclusive).
 * @property to     - End of a date range (YYYY-MM, inclusive).
 */
export const revenueReportQuerySchema = z.object({
  period: periodString.optional(),
  from: periodString.optional(),
  to: periodString.optional(),
}).refine((data) => {
  // Prevent conflicting parameters at schema level
  const hasPeriod = !!data.period
  const hasRange = !!data.from && !!data.to
  
  // Either period OR range should be provided (not both, not neither)
  // This is a pre-validation check; the route handler provides more user-friendly errors
  return (hasPeriod && !data.from && !data.to) || (!hasPeriod && hasRange)
}, {
  message: 'Provide either "period" alone or both "from" and "to" parameters',
  path: [], // Apply to the entire object
})

export type RevenueReportQuery = z.infer<typeof revenueReportQuerySchema>

/**
 * Error types for revenue report validation failures.
 * These can be used for structured logging and monitoring.
 */
export const RevenueReportValidationErrors = {
  INVALID_FORMAT: 'INVALID_FORMAT',
  YEAR_OUT_OF_BOUNDS: 'YEAR_OUT_OF_BOUNDS',
  MONTH_OUT_OF_BOUNDS: 'MONTH_OUT_OF_BOUNDS',
  STRING_TOO_LONG: 'STRING_TOO_LONG',
  STRING_TOO_SHORT: 'STRING_TOO_SHORT',
  INVALID_CHARACTERS: 'INVALID_CHARACTERS',
  CONFLICTING_PARAMETERS: 'CONFLICTING_PARAMETERS',
  MISSING_PARAMETERS: 'MISSING_PARAMETERS',
} as const

export type RevenueReportValidationError = typeof RevenueReportValidationErrors[keyof typeof RevenueReportValidationErrors]
