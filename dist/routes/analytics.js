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
 * Security: All routes require business authentication via `requireBusinessAuth`.
 * Input:    Query parameters are validated with `validateQuery` + Zod schema
 *           before reaching the controller logic.
 */
import { Router } from 'express';
import { requireBusinessAuth } from '../middleware/requireBusinessAuth.js';
import { validateQuery } from '../middleware/validate.js';
import { listAttestedPeriodsForBusiness } from '../services/analytics/periods.js';
import { getRevenueReport, TimeWindowError } from '../services/analytics/revenueReports.js';
import { revenueReportQuerySchema } from '../services/analytics/revenueReportSchema.js';
export const analyticsRouter = Router();
analyticsRouter.get('/periods', requireBusinessAuth, (req, res) => {
    const businessId = res.locals.businessId;
    const periods = listAttestedPeriodsForBusiness(businessId);
    res.json({ periods });
});
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
analyticsRouter.get('/revenue', requireBusinessAuth, validateQuery(revenueReportQuerySchema), (req, res) => {
    const businessId = res.locals.businessId;
    const { period, from, to } = req.query;
    // At least one query mode must be present (Zod allows all-optional for flexibility).
    if (!period && !(from && to)) {
        return res.status(400).json({
            error: 'Provide either "period" (e.g. 2025-10) or both "from" and "to" query params.',
        });
    }
    try {
        const report = getRevenueReport(businessId, period, from, to);
        if (!report) {
            return res.status(404).json({ error: 'No revenue data found for the given period.' });
        }
        return res.json(report);
    }
    catch (err) {
        if (err instanceof TimeWindowError) {
            return res.status(400).json({ error: err.message });
        }
        throw err;
    }
});
