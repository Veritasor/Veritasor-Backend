import { Router } from 'express'
import { requireBusinessAuth } from '../middleware/requireBusinessAuth.js'
import { listAttestedPeriodsForBusiness } from '../services/analytics/periods.js'
import { getRevenueReport } from '../services/analytics/revenueReports.js'

export const analyticsRouter = Router()

analyticsRouter.get('/periods', requireBusinessAuth, ( req, res ) => {
  const businessId = res.locals.businessId as string
  const periods = listAttestedPeriodsForBusiness(businessId)
  res.json({ periods })
})

analyticsRouter.get('/revenue', requireBusinessAuth, (req, res) => {
  const businessId = res.locals.businessId as string
  const { period, from, to } = req.query as Record<string, string | undefined>

  if (!period && !(from && to)) {
    return res.status(400).json({
      error: 'Provide either period (e.g. 2026-02) or both from and to query params.',
    })
  }

  const report = getRevenueReport(businessId, period, from, to)

  if (!report) {
    return res.status(404).json({ error: 'No revenue data found for the given period.' })
  }

  res.json(report)
})


