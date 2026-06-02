import { describe, it, expect, vi, beforeEach } from 'vitest'
import request from 'supertest'
import express from 'express'
import adminRouter from '../../../src/routes/admin.js'
import { IntegrationPermission } from '../../../src/types/permissions.js'

// Mock dependencies
vi.mock('../../../src/services/webhooks/deadLetterQueue.js', () => ({
  getDeadLetter: vi.fn(),
  deleteDeadLetter: vi.fn(),
  computePayloadHash: vi.fn(),
}))

vi.mock('../../../src/services/webhooks/razorpayHandler.js', () => ({
  handleRazorpayEvent: vi.fn(),
}))

import { getDeadLetter, deleteDeadLetter, computePayloadHash } from '../../../src/services/webhooks/deadLetterQueue.js'
import { handleRazorpayEvent } from '../../../src/services/webhooks/razorpayHandler.js'

// Mock auth and permission middleware
vi.mock('../../../src/middleware/requireAuth.js', () => ({
  requireAuth: (req: any, res: any, next: any) => {
    const role = (req.headers['x-user-role'] as string) || 'admin'
    req.user = { id: 'admin_123', userId: 'admin_123', email: 'admin@test.com', role }
    next()
  }
}))

vi.mock('../../../src/middleware/permissions.js', () => ({
  requirePermissions: (permissions: any) => (req: any, res: any, next: any) => {
    if (req.user.role === 'admin') {
      return next()
    }
    res.status(403).json({ error: 'Forbidden' })
  }
}))

const app = express()
app.use(express.json())
app.use('/api/v1/admin', adminRouter)

describe('Admin Webhook Replay Route', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

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
