import express from 'express'
import request from 'supertest'
import { describe, it, expect, vi, beforeEach } from 'vitest'

const mocks = vi.hoisted(() => ({
  requireBusinessAuth: vi.fn(),
  getRevenueReport: vi.fn(),
  listAttestedPeriodsForBusiness: vi.fn(),
  rateLimitCounts: new Map<string, number>(),
  authContext: { userId: 'user-1', businessId: 'biz-1' },
  TimeWindowError: class TimeWindowError extends Error {
    constructor(message: string) {
      super(message)
      this.name = 'TimeWindowError'
    }
  },
}))

vi.mock('../../../src/middleware/rateLimiter.js', () => ({
  rateLimiter: (options: { bucket: string | ((req: any) => string); max: number; windowMs: number }) =>
    (req: any, res: any, next: any) => {
      const bucket = typeof options.bucket === 'function' ? options.bucket(req) : options.bucket
      const identifier = req.user?.userId ? `user:${req.user.userId}` : `ip:${req.ip}`
      const key = `${bucket}:${identifier}`
      const count = (mocks.rateLimitCounts.get(key) ?? 0) + 1
      mocks.rateLimitCounts.set(key, count)

      res.setHeader('X-RateLimit-Bucket', bucket)
      res.setHeader('X-RateLimit-Limit', String(options.max))
      res.setHeader('X-RateLimit-Remaining', String(Math.max(0, options.max - count)))
      res.setHeader('X-RateLimit-Reset', String(Date.now() + options.windowMs))
      res.setHeader('Retry-After', String(Math.ceil(options.windowMs / 1000)))

      if (count > options.max) {
        res.status(429).json({ error: 'Too many requests, please try again later.' })
        return
      }
      next()
    },
}))

vi.mock('../../../src/middleware/requireBusinessAuth.js', () => ({
  requireBusinessAuth: (req: any, res: any, next: any) => mocks.requireBusinessAuth(req, res, next),
}))

vi.mock('../../../src/services/analytics/periods.js', () => ({
  listAttestedPeriodsForBusiness: (...args: any[]) => mocks.listAttestedPeriodsForBusiness(...args),
}))

vi.mock('../../../src/services/analytics/revenueReports.js', () => ({
  getRevenueReport: (...args: any[]) => mocks.getRevenueReport(...args),
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

function allowAuthenticatedRequest() {
  mocks.requireBusinessAuth.mockImplementation((req: any, _res: any, next: any) => {
    const { userId, businessId } = mocks.authContext
    req.user = { id: userId, userId }
    req.business = { id: businessId, userId }
    next()
  })
}

describe('analyticsRouter', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    mocks.rateLimitCounts.clear()
    mocks.authContext.userId = 'user-1'
    mocks.authContext.businessId = 'biz-1'
    mocks.listAttestedPeriodsForBusiness.mockReturnValue([])
    allowAuthenticatedRequest()
  })

  describe('GET /revenue', () => {
    it('returns 400 when neither period nor from/to is provided', async () => {
      const res = await request(buildApp()).get('/api/analytics/revenue')
      expect(res.status).toBe(400)
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
      const report = { businessId: 'biz-1', period: '2025-10', total: 1234, breakdown: [] }
      mocks.getRevenueReport.mockResolvedValue(report)
      const res = await request(buildApp()).get('/api/analytics/revenue?period=2025-10')
      expect(res.status).toBe(200)
      expect(res.body).toEqual(report)
      expect(mocks.getRevenueReport).toHaveBeenCalledWith('biz-1', '2025-10', undefined, undefined)
    })

    it('accepts from/to range and returns 200', async () => {
      const report = { businessId: 'biz-1', from: '2025-01', to: '2025-03', total: 99, breakdown: [] }
      mocks.getRevenueReport.mockResolvedValue(report)
      const res = await request(buildApp()).get('/api/analytics/revenue?from=2025-01&to=2025-03')
      expect(res.status).toBe(200)
      expect(res.body).toEqual(report)
      expect(mocks.getRevenueReport).toHaveBeenCalledWith('biz-1', undefined, '2025-01', '2025-03')
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
      mocks.listAttestedPeriodsForBusiness.mockReturnValue(['2025-09', '2025-10'])
      const res = await request(buildApp()).get('/api/analytics/periods')
      expect(res.status).toBe(200)
      expect(res.body).toEqual(expect.objectContaining({ periods: ['2025-09', '2025-10'] }))
      expect(mocks.listAttestedPeriodsForBusiness).toHaveBeenCalledWith('biz-1')
    })

    it('propagates unexpected errors to the error handler', async () => {
      mocks.listAttestedPeriodsForBusiness.mockImplementation(() => {
        throw Object.assign(new Error('db down'), { status: 500 })
      })
      const res = await request(buildApp()).get('/api/analytics/periods')
      expect(res.status).toBe(500)
      expect(res.body.error).toBe('db down')
    })
  })

  describe('per-business rate limiting', () => {
    it('emits X-RateLimit-* headers on successful responses', async () => {
      const res = await request(buildApp()).get('/api/analytics/periods')
      expect(res.status).toBe(200)
      expect(res.headers['x-ratelimit-bucket']).toBe('analytics:biz-1')
      expect(res.headers['x-ratelimit-limit']).toBe('30')
      expect(res.headers['x-ratelimit-remaining']).toBe('29')
      expect(res.headers['x-ratelimit-reset']).toBeDefined()
      expect(res.headers['retry-after']).toBeDefined()
    })

    it('gives two businesses from the same IP independent quotas', async () => {
      const app = buildApp()
      mocks.authContext.userId = 'shared-user'
      mocks.authContext.businessId = 'biz-a'

      for (let i = 0; i < 30; i++) {
        expect((await request(app).get('/api/analytics/periods')).status).toBe(200)
      }

      const exhausted = await request(app).get('/api/analytics/periods')
      expect(exhausted.status).toBe(429)
      expect(exhausted.body.error).toMatch(/too many requests/i)
      expect(mocks.listAttestedPeriodsForBusiness).toHaveBeenCalledTimes(30)

      mocks.authContext.businessId = 'biz-b'
      const otherFirst = await request(app).get('/api/analytics/periods')
      expect(otherFirst.status).toBe(200)
      expect(otherFirst.headers['x-ratelimit-bucket']).toBe('analytics:biz-b')
      expect(otherFirst.headers['x-ratelimit-remaining']).toBe('29')

      for (let i = 0; i < 29; i++) {
        expect((await request(app).get('/api/analytics/periods')).status).toBe(200)
      }
      expect((await request(app).get('/api/analytics/periods')).status).toBe(429)
      expect(mocks.listAttestedPeriodsForBusiness).toHaveBeenCalledTimes(60)
    })

    it('returns 429 with rate-limit headers once the business quota is exhausted', async () => {
      const app = buildApp()
      for (let i = 0; i < 30; i++) {
        await request(app).get('/api/analytics/revenue?period=2025-10')
      }

      const res = await request(app).get('/api/analytics/revenue?period=2025-10')
      expect(res.status).toBe(429)
      expect(res.body.error).toMatch(/too many requests/i)
      expect(res.headers['x-ratelimit-bucket']).toBe('analytics:biz-1')
      expect(res.headers['x-ratelimit-limit']).toBe('30')
      expect(res.headers['x-ratelimit-remaining']).toBe('0')
      expect(res.headers['x-ratelimit-reset']).toBeDefined()
      expect(res.headers['retry-after']).toBeDefined()
      expect(mocks.getRevenueReport).toHaveBeenCalledTimes(30)
    })

    it('returns 401 before applying the per-business quota when auth fails', async () => {
      mocks.requireBusinessAuth.mockImplementation((_req: any, res: any, _next: any) => {
        res.status(401).json({ code: 'MISSING_AUTH', error: 'Business authentication required' })
      })

      const res = await request(buildApp()).get('/api/analytics/periods')
      expect(res.status).toBe(401)
      expect(res.body.code).toBe('MISSING_AUTH')
      expect(res.headers['x-ratelimit-bucket']).toBe('analytics:auth')
      expect(res.headers['x-ratelimit-limit']).toBe('100')
      expect(mocks.listAttestedPeriodsForBusiness).not.toHaveBeenCalled()
    })

    it('does not consume a business quota on failed auth', async () => {
      const app = buildApp()
      mocks.requireBusinessAuth.mockImplementation((_req: any, res: any, _next: any) => {
        res.status(401).json({ code: 'INVALID_TOKEN', error: 'Invalid authentication' })
      })
      for (let i = 0; i < 5; i++) {
        expect((await request(app).get('/api/analytics/periods')).status).toBe(401)
      }

      allowAuthenticatedRequest()
      const res = await request(app).get('/api/analytics/periods')
      expect(res.status).toBe(200)
      expect(res.headers['x-ratelimit-remaining']).toBe('29')
    })
  })
})
