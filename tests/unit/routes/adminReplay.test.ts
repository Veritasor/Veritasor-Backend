import { describe, it, expect, vi, beforeEach } from 'vitest'
import request from 'supertest'
import express from 'express'
import adminRouter from '../../../src/routes/admin.js'

// Mock dependencies
vi.mock('../../../src/services/webhooks/deadLetterQueue.js', () => ({
  getDeadLetter: vi.fn(),
  deleteDeadLetter: vi.fn(),
  computePayloadHash: vi.fn(),
  isQuarantined: vi.fn(),
  listQuarantinedLetters: vi.fn(),
  releaseQuarantinedLetter: vi.fn(),
  purgeQuarantinedLetter: vi.fn(),
}))

vi.mock('../../../src/services/webhooks/razorpayHandler.js', () => ({
  handleRazorpayEvent: vi.fn(),
}))

vi.mock('../../../src/repositories/auditLogRepository.js', () => ({
  createAuditLog: vi.fn().mockResolvedValue(true),
  queryAuditLogs: vi.fn().mockResolvedValue({ data: [], hasMore: false }),
}))

import {
  getDeadLetter,
  deleteDeadLetter,
  computePayloadHash,
  isQuarantined,
  listQuarantinedLetters,
  releaseQuarantinedLetter,
  purgeQuarantinedLetter,
} from '../../../src/services/webhooks/deadLetterQueue.js'
import { handleRazorpayEvent } from '../../../src/services/webhooks/razorpayHandler.js'

// Mock auth and permission middleware
vi.mock('../../../src/middleware/requireAuth.js', () => ({
  requireAuth: (req: any, res: any, next: any) => {
    const role = (req.headers['x-user-role'] as string) || 'admin'
    req.user = { id: 'admin_123', userId: 'admin_123', email: 'admin@test.com', role }
    next()
  },
}))

vi.mock('../../../src/middleware/permissions.js', () => ({
  requirePermissions: (permissions: any) => (req: any, res: any, next: any) => {
    if (req.user.role === 'admin') {
      return next()
    }
    res.status(403).json({ error: 'Forbidden' })
  },
}))

const app = express()
app.use(express.json())
app.use('/api/v1/admin', adminRouter)

describe('Admin Webhook Replay and Quarantine Routes', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(isQuarantined).mockResolvedValue(false)
  })

  describe('POST /api/v1/admin/webhooks/replay', () => {
    it('replays a failed webhook successfully', async () => {
      const mockPayload = { id: 'evt_123', event: 'payment.captured' }
      vi.mocked(getDeadLetter).mockResolvedValueOnce({ payload_hash: 'matched_hash' })
      vi.mocked(computePayloadHash).mockReturnValueOnce('matched_hash')
      vi.mocked(handleRazorpayEvent).mockResolvedValueOnce({ status: 'ok', message: 'Success' })
      vi.mocked(deleteDeadLetter).mockResolvedValueOnce(undefined)

      const response = await request(app)
        .post('/api/v1/admin/webhooks/replay')
        .send({
          provider: 'razorpay',
          eventId: 'evt_123',
          payload: mockPayload,
        })

      expect(response.status).toBe(200)
      expect(response.body).toEqual({
        status: 'ok',
        message: 'Replay successful, entry cleared',
      })

      expect(getDeadLetter).toHaveBeenCalledWith('razorpay', 'evt_123')
      expect(computePayloadHash).toHaveBeenCalledWith(mockPayload)
      expect(handleRazorpayEvent).toHaveBeenCalledWith(mockPayload)
      expect(deleteDeadLetter).toHaveBeenCalledWith('razorpay', 'evt_123')
    })

    it('blocks replay if webhook payload is quarantined as a poison pill', async () => {
      vi.mocked(isQuarantined).mockResolvedValueOnce(true)

      const response = await request(app)
        .post('/api/v1/admin/webhooks/replay')
        .send({
          provider: 'razorpay',
          eventId: 'evt_poison',
          payload: { foo: 'bar' },
        })

      expect(response.status).toBe(400)
      expect(response.body.error).toContain('quarantined as a poison pill')
      expect(getDeadLetter).not.toHaveBeenCalled()
      expect(handleRazorpayEvent).not.toHaveBeenCalled()
    })

    it('returns 400 for missing fields', async () => {
      const response = await request(app)
        .post('/api/v1/admin/webhooks/replay')
        .send({
          provider: 'razorpay',
        })

      expect(response.status).toBe(400)
      expect(response.body.error).toContain('Missing required fields')
    })

    it('returns 400 for unsupported provider', async () => {
      const response = await request(app)
        .post('/api/v1/admin/webhooks/replay')
        .send({
          provider: 'stripe',
          eventId: 'evt_123',
          payload: {},
        })

      expect(response.status).toBe(400)
      expect(response.body.error).toContain('Unsupported provider')
    })

    it('returns 404 if dead-letter entry does not exist', async () => {
      vi.mocked(getDeadLetter).mockResolvedValueOnce(null)

      const response = await request(app)
        .post('/api/v1/admin/webhooks/replay')
        .send({
          provider: 'razorpay',
          eventId: 'evt_nonexistent',
          payload: {},
        })

      expect(response.status).toBe(404)
      expect(response.body.error).toContain('Dead letter entry not found')
    })

    it('returns 400 if payload is too large', async () => {
      vi.mocked(getDeadLetter).mockResolvedValueOnce({ payload_hash: 'some_hash' })
      vi.mocked(computePayloadHash).mockImplementationOnce(() => {
        throw new Error('Payload too large')
      })

      const response = await request(app)
        .post('/api/v1/admin/webhooks/replay')
        .send({
          provider: 'razorpay',
          eventId: 'evt_123',
          payload: { too: 'large' },
        })

      expect(response.status).toBe(400)
      expect(response.body.error).toBe('Payload too large')
    })

    it('returns 400 if payload hash mismatches', async () => {
      vi.mocked(getDeadLetter).mockResolvedValueOnce({ payload_hash: 'correct_hash' })
      vi.mocked(computePayloadHash).mockReturnValueOnce('mismatched_hash')

      const response = await request(app)
        .post('/api/v1/admin/webhooks/replay')
        .send({
          provider: 'razorpay',
          eventId: 'evt_123',
          payload: { invalid: 'payload' },
        })

      expect(response.status).toBe(400)
      expect(response.body.error).toBe('Payload hash mismatch')
      expect(handleRazorpayEvent).not.toHaveBeenCalled()
      expect(deleteDeadLetter).not.toHaveBeenCalled()
    })

    it('does not delete dead-letter if handler throws, and returns 500', async () => {
      vi.mocked(getDeadLetter).mockResolvedValueOnce({ payload_hash: 'correct_hash' })
      vi.mocked(computePayloadHash).mockReturnValueOnce('correct_hash')
      vi.mocked(handleRazorpayEvent).mockRejectedValueOnce(new Error('Processing failed'))

      const response = await request(app)
        .post('/api/v1/admin/webhooks/replay')
        .send({
          provider: 'razorpay',
          eventId: 'evt_123',
          payload: { event: 'fail' },
        })

      expect(response.status).toBe(500)
      expect(response.body.error).toBe('Replay failed')
      expect(response.body.message).toBe('Processing failed')
      expect(deleteDeadLetter).not.toHaveBeenCalled()
    })

    it('returns 403 Forbidden for non-admin requests', async () => {
      const response = await request(app)
        .post('/api/v1/admin/webhooks/replay')
        .set('x-user-role', 'user')
        .send({
          provider: 'razorpay',
          eventId: 'evt_123',
          payload: {},
        })

      expect(response.status).toBe(403)
      expect(response.body.error).toBe('Forbidden')
    })
  })

  describe('Quarantine Admin Endpoints', () => {
    it('GET /api/v1/admin/webhooks/quarantine returns list of quarantined entries', async () => {
      const mockList = [{ provider: 'razorpay', event_id: 'evt_q1', fingerprint: 'fp1' }]
      vi.mocked(listQuarantinedLetters).mockResolvedValueOnce(mockList as any)

      const response = await request(app).get('/api/v1/admin/webhooks/quarantine?provider=razorpay')

      expect(response.status).toBe(200)
      expect(response.body).toEqual({ data: mockList })
      expect(listQuarantinedLetters).toHaveBeenCalledWith('razorpay')
    })

    it('POST /api/v1/admin/webhooks/quarantine/release releases quarantined entry', async () => {
      vi.mocked(releaseQuarantinedLetter).mockResolvedValueOnce(true)

      const response = await request(app)
        .post('/api/v1/admin/webhooks/quarantine/release')
        .send({ provider: 'razorpay', eventId: 'evt_q1' })

      expect(response.status).toBe(200)
      expect(response.body.message).toContain('released successfully')
      expect(releaseQuarantinedLetter).toHaveBeenCalledWith('razorpay', 'evt_q1', 'admin_123')
    })

    it('POST /api/v1/admin/webhooks/quarantine/release returns 404 if not found', async () => {
      vi.mocked(releaseQuarantinedLetter).mockResolvedValueOnce(false)

      const response = await request(app)
        .post('/api/v1/admin/webhooks/quarantine/release')
        .send({ provider: 'razorpay', eventId: 'evt_nonexistent' })

      expect(response.status).toBe(404)
    })

    it('DELETE /api/v1/admin/webhooks/quarantine purges quarantined entry', async () => {
      vi.mocked(purgeQuarantinedLetter).mockResolvedValueOnce(true)

      const response = await request(app)
        .delete('/api/v1/admin/webhooks/quarantine')
        .send({ provider: 'razorpay', eventId: 'evt_q1' })

      expect(response.status).toBe(200)
      expect(response.body.message).toContain('purged successfully')
      expect(purgeQuarantinedLetter).toHaveBeenCalledWith('razorpay', 'evt_q1')
    })
  })
})
