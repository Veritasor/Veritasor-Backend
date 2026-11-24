import express from 'express'
import request from 'supertest'
import { describe, it, expect, vi, beforeEach } from 'vitest'

const mocks = vi.hoisted(() => ({
  requireBusinessAuth: vi.fn(),
  getRevenueReport: vi.fn(),
  listAttestedPeriodsForBusiness: vi.fn(),
  TimeWindowError: class TimeWindowError extends Error {
    constructor(message: string) {
      super(message)
      this.name = 'TimeWindowError'
    }
  },
}))

vi.mock('../../../src/middleware/requireBusinessAuth', () => ({
  requireBusinessAuth: (req: any, res: any, next: any) => mocks.requireBusinessAuth(req, res, next),
}))

vi.mock('../../../src/services/analytics', () => ({
  getRevenueReport: (...args: any[]) => mocks.getRevenueReport(...args),
  listAttestedPeriodsForBusiness: (...args: any[]) => mocks.listAttestedPeriodsForBusiness(...args),
  TimeWindowError: mocks.TimeWindowError,
}))

import { analyticsRouter } from '../../../src/routes/analytics'

function buildApp() {
  const app = express()
  app.use(express.json())
  app.use('/api/analytics', analyticsRouter)
  app.use((err: any, _req: any, res: any, _next: any) => {
    res.status(err.status ?? 500).json({ error: err.message ?? 'Internal error' })
  })
  return app
}

describe('analyticsRouter', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mocks.requireBusinessAuth.mockImplementation((req: any, _res: any, next: any) => {
      req.businessId = 'biz-1'
      next()
    })
  })

  describe('GET /revenue', () => {
    it('returns 400 when neither period nor from/to is provided', async () => {
      const res = await request(buildApp()).get('/api/analytics/revenue')
      expect(res.status).toBe(400)
      expect(res.body.error).toMatch(/Provide either period or both from and to/)
      expect(mocks.getRevenueReport).not.toHaveBeenCalled()
    })

    it('returns 400 when TimeWindowError is thrown by the service', async () => {
      mocks.getRevenueReport.mockRejectedValue(new mocks.TimeWindowError('from must be before to'))
      const res = await request(buildApp()).get('/api/analytics/revenue?from=2025-05&to=2025-01')
      expect(res.status).toBe(400)
      expect(res.body.error).toBe('from must be before to')
    })

    it('returns 404 when the report is null', async () => {
      mocks.getRevenueReport.mockResolvedValue(null)
      const res = await request(buildApp()).get('/api/analytics/revenue?period=2025-10')
      expect(res.status).toBe(404)
    })

    it('returns 200 with the report shape on success', async () => {
      const report = { businessId: 'biz-1', period: '2025-10', total: 1234 }
      mocks.getRevenueReport.mockResolvedValue(report)
      const res = await request(buildApp()).get('/api/analytics/revenue?period=2025-10')
      expect(res.status).toBe(200)
      expect(res.body).toEqual(report)
      expect(mocks.getRevenueReport).toHaveBeenCalledWith(
        expect.objectContaining({ businessId: 'biz-1', period: '2025-10' }),
      )
    })

    it('accepts from/to range and returns 200', async () => {
      const report = { businessId: 'biz-1', from: '2025-01', to: '2025-03', total: 99 }
      mocks.getRevenueReport.mockResolvedValue(report)
      const res = await request(buildApp()).get('/api/analytics/revenue?from=2025-01&to=2025-03')
      expect(res.status).toBe(200)
      expect(res.body).toEqual(report)
    })

    it('propagates unexpected errors to the error handler', async () => {
      mocks.getRevenueReport.mockRejectedValue(Object.assign(new Error('boom'), { status: 500 }))
      const res = await request(buildApp()).get('/api/analytics/revenue?period=2025-10')
      expect(res.status).toBe(500)
      expect(res.body.error).toBe('boom')
    })

    it('runs auth before the handler', async () => {
      mocks.requireBusinessAuth.mockImplementation((_req: any, res: any, _next: any) => {
        res.status(401).json({ error: 'unauthorized' })
      })
      const res = await request(buildApp()).get('/api/analytics/revenue?period=2025-10')
      expect(res.status).toBe(401)
      expect(mocks.getRevenueReport).not.toHaveBeenCalled()
    })
  })

  describe('GET /periods', () => {
    it('returns 200 with attested periods', async () => {
      mocks.listAttestedPeriodsForBusiness.mockResolvedValue(['2025-09', '2025-10'])
      const res = await request(buildApp()).get('/api/analytics/periods')
      expect(res.status).toBe(200)
      expect(res.body).toEqual(expect.objectContaining({ periods: ['2025-09', '2025-10'] }))
      expect(mocks.listAttestedPeriodsForBusiness).toHaveBeenCalledWith('biz-1')
    })

    it('propagates unexpected errors to the error handler', async () => {
      mocks.listAttestedPeriodsForBusiness.mockRejectedValue(Object.assign(new Error('db down'), { status: 500 }))
      const res = await request(buildApp()).get('/api/analytics/periods')
      expect(res.status).toBe(500)
      expect(res.body.error).toBe('db down')
    })
  })
})
