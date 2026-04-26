/**
 * @module routes/analytics
 *
 * @description
 * Express router for the /api/analytics resource group.
 *
 * Routes:
 *  GET  /api/analytics/periods  – List all attested billing periods for the
 *                                 authenticated business.
 *  GET  /api/analytics/revenue  – Generate a revenue report for a specific
 *                                 period or date range.
 *
 * Security:
 *  - All routes require business authentication via `requireBusinessAuth`.
 *  - A dedicated rate-limit bucket (`analytics`) isolates this group so
 *    burst traffic here does not consume the budget of other endpoints.
 *  - `res.locals.businessId` is set from `req.business.id` after auth so
 *    downstream handlers never read user-controlled input directly.
 *
 * Error shapes (stable contract):
 *  401  { code: 'MISSING_AUTH' | 'INVALID_TOKEN',  error: string }
 *  400  { code: 'MISSING_BUSINESS_ID',             error: string }
 *  403  { code: 'BUSINESS_NOT_FOUND',              error: string }
 *  403  { code: 'BUSINESS_SUSPENDED',              error: string }
 *  429  { error: string }
 *  400  { error: string }   – bad query params / time-window errors
 *  404  { error: string }   – no data for the given window
 */

import { Router, Request, Response } from 'express'
import { requireBusinessAuth } from '../middleware/requireBusinessAuth.js'
import { rateLimiter } from '../middleware/rateLimiter.js'
import { validateQuery } from '../middleware/validate.js'
import { listAttestedPeriodsForBusiness } from '../services/analytics/periods.js'
import { getRevenueReport, TimeWindowError } from '../services/analytics/revenueReports.js'
import { revenueReportQuerySchema } from '../services/analytics/revenueReportSchema.js'
import { logger } from '../utils/logger.js'

export const analyticsRouter = Router()

/** Shared rate-limit bucket for all analytics endpoints (30 req / 15 min). */
const analyticsRateLimiter = rateLimiter({
  windowMs: 15 * 60 * 1000,
  max: 30,
  bucket: 'analytics',
})

/**
 * Middleware that copies the authenticated business ID into res.locals so
 * route handlers never touch user-controlled input.
 */
function setBusinessLocals(req: Request, res: Response, next: () => void): void {
  // req.business is guaranteed non-null here because requireBusinessAuth ran first.
  res.locals.businessId = req.business!.id
  next()
}

// ---------------------------------------------------------------------------
// GET /periods
// ---------------------------------------------------------------------------

analyticsRouter.get(
  '/periods',
  analyticsRateLimiter,
  requireBusinessAuth,
  setBusinessLocals,
  (req: Request, res: Response) => {
    const businessId = res.locals.businessId as string

    logger.info(JSON.stringify({
      event: 'analytics.periods.request',
      businessId,
      path: req.path,
    }))

    const periods = listAttestedPeriodsForBusiness(businessId)

    logger.info(JSON.stringify({
      event: 'analytics.periods.response',
      businessId,
      count: periods.length,
    }))

    res.json({ periods })
  },
)

// ---------------------------------------------------------------------------
// GET /revenue
// ---------------------------------------------------------------------------

/**
 * GET /api/analytics/revenue
 *
 * Returns a revenue report for the authenticated business.
 * Exactly one of the following query shapes must be supplied:
 *   - `period` (YYYY-MM)         → single-month report
 *   - `from` + `to` (YYYY-MM)   → inclusive range report (max 24 months)
 *
 * @auth  requireBusinessAuth
 * @query period? string  Single billing month YYYY-MM.
 * @query from?   string  Range start YYYY-MM (inclusive).
 * @query to?     string  Range end   YYYY-MM (inclusive).
 *
 * @response 200 RevenueReport
 * @response 400 { error: string }  – Missing/invalid params or bad range.
 * @response 404 { error: string }  – No data for the given window.
 */
analyticsRouter.get(
  '/revenue',
  analyticsRateLimiter,
  requireBusinessAuth,
  setBusinessLocals,
  validateQuery(revenueReportQuerySchema),
  (req: Request, res: Response) => {
    const businessId = res.locals.businessId as string
    const { period, from, to } = req.query as Record<string, string | undefined>

    logger.info(JSON.stringify({
      event: 'analytics.revenue.request',
      businessId,
      period,
      from,
      to,
    }))

    // At least one query mode must be present (Zod allows all-optional for flexibility).
    if (!period && !(from && to)) {
      return res.status(400).json({
        error: 'Provide either "period" (e.g. 2025-10) or both "from" and "to" query params.',
      })
    }

    try {
      const report = getRevenueReport(businessId, period, from, to)

      if (!report) {
        logger.info(JSON.stringify({
          event: 'analytics.revenue.not_found',
          businessId,
          period,
          from,
          to,
        }))
        return res.status(404).json({ error: 'No revenue data found for the given period.' })
      }

      logger.info(JSON.stringify({
        event: 'analytics.revenue.response',
        businessId,
        reportPeriod: report.period,
        breakdownCount: report.breakdown.length,
      }))

      return res.json(report)
    } catch (err) {
      if (err instanceof TimeWindowError) {
        logger.warn(JSON.stringify({
          event: 'analytics.revenue.time_window_error',
          businessId,
          message: err.message,
        }))
        return res.status(400).json({ error: err.message })
      }
      throw err
    }
  },
)
