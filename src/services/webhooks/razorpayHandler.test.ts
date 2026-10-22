import { describe, it, expect, vi, beforeEach } from 'vitest'
import crypto from 'node:crypto'
import {
  verifyRazorpaySignature,
  RazorpayWebhookError,
  parseRazorpayEvent,
  handleRazorpayEvent,
  resetProcessedRazorpayEvents,
} from './razorpayHandler.js'
import * as idempotency from './idempotency.js'
import * as deadLetterQueue from './deadLetterQueue.js'
import { logger } from '../../utils/logger.js'

vi.mock('../../utils/logger.js', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}))

vi.mock('./idempotency.js', () => ({
  isEventProcessed: vi.fn().mockReturnValue(false),
  markEventProcessed: vi.fn(),
  checkTimestampTolerance: vi.fn().mockReturnValue({ valid: true }),
}))

vi.mock('./deadLetterQueue.js', () => ({
  saveDeadLetter: vi.fn().mockResolvedValue(undefined),
}))

describe('Razorpay Webhook Handler', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    resetProcessedRazorpayEvents()
    vi.mocked(idempotency.checkTimestampTolerance).mockReturnValue({ valid: true })
    vi.mocked(idempotency.isEventProcessed).mockReturnValue(false)
  })

  describe('verifyRazorpaySignature', () => {
    const secret = 'test_secret'
    const payload = JSON.stringify({ event: 'payment.captured' })

    it('returns true for a valid signature', () => {
      const signature = crypto
        .createHmac('sha256', secret)
        .update(payload)
        .digest('hex')
      expect(verifyRazorpaySignature(payload, signature, secret)).toBe(true)
    })

    it('returns false for an invalid signature', () => {
      const invalidSignature = crypto
        .createHmac('sha256', secret)
        .update('wrong_payload')
        .digest('hex')
      expect(verifyRazorpaySignature(payload, invalidSignature, secret)).toBe(false)
    })

    it('returns false when signature length is incorrect', () => {
      expect(verifyRazorpaySignature(payload, 'short_signature', secret)).toBe(false)
    })

    it('returns false when secret is empty', () => {
      const signature = crypto
        .createHmac('sha256', 'test_secret')
        .update(payload)
        .digest('hex')
      expect(verifyRazorpaySignature(payload, signature, '')).toBe(false)
    })
  })

  describe('RazorpayWebhookError', () => {
    it('correctly instantiates with code, status, and message', () => {
      const error = new RazorpayWebhookError('invalid_payload', 400, 'Invalid payload')
      expect(error).toBeInstanceOf(Error)
      expect(error.name).toBe('RazorpayWebhookError')
      expect(error.code).toBe('invalid_payload')
      expect(error.httpStatus).toBe(400)
      expect(error.message).toBe('Invalid payload')
    })
  })

  describe('parseRazorpayEvent (RazorpayEvent schema)', () => {
    it('successfully parses a valid handled event', () => {
      const validPayload = JSON.stringify({
        id: 'evt_123',
        event: 'payment.captured',
        created_at: 1616161616,
        payload: {
          payment: {
            entity: {
              id: 'pay_123',
              order_id: 'order_123',
              status: 'captured',
              amount: 1000,
              currency: 'INR'
            }
          }
        }
      })
      const event = parseRazorpayEvent(validPayload, { nowMs: 1616161616000 })
      expect(event.id).toBe('evt_123')
      expect(event.event).toBe('payment.captured')
    })

    it('throws invalid_payload if JSON is malformed', () => {
      expect(() => parseRazorpayEvent('invalid json'))
        .toThrowError(new RazorpayWebhookError('invalid_payload', 400, 'Invalid webhook payload'))
    })

    it('throws invalid_event if required fields are missing', () => {
      const invalidEvent = JSON.stringify({
        event: 'payment.captured' // missing id
      })
      expect(() => parseRazorpayEvent(invalidEvent))
        .toThrowError(new RazorpayWebhookError('invalid_event', 400, 'Invalid event structure'))
    })

    it('throws invalid_event if handled event is missing payment entity', () => {
      const invalidEvent = JSON.stringify({
        id: 'evt_123',
        event: 'payment.captured',
        payload: {} // missing payment.entity
      })
      expect(() => parseRazorpayEvent(invalidEvent))
        .toThrowError(new RazorpayWebhookError('invalid_event', 400, 'Invalid event structure'))
    })

    it('throws invalid_timestamp if event is too far in the future', () => {
      const futureEvent = JSON.stringify({
        id: 'evt_123',
        event: 'payment.captured',
        created_at: Math.floor(Date.now() / 1000) + 10000,
        payload: {
          payment: {
            entity: { id: 'pay_123', order_id: 'order_123', status: 'captured', amount: 1000, currency: 'INR' }
          }
        }
      })
      expect(() => parseRazorpayEvent(futureEvent, { nowMs: Date.now(), maxFutureSkewMs: 5000 }))
        .toThrowError(new RazorpayWebhookError('invalid_timestamp', 400, 'Invalid webhook timestamp'))
    })
  })

  describe('Primary State Transitions (handleRazorpayEvent)', () => {
    it('processes a payment.captured event successfully', async () => {
      const event = {
        id: 'evt_captured',
        event: 'payment.captured',
        payload: { payment: { entity: { id: 'pay_1', order_id: 'order_1', status: 'captured', amount: 1000, currency: 'INR' } } }
      }
      
      const result = await handleRazorpayEvent(event as any, { maxAttempts: 1 })
      expect(result.status).toBe('ok')
      expect(result.message).toContain('captured successfully')
      expect(idempotency.markEventProcessed).toHaveBeenCalledWith('evt_captured')
    })

    it('processes a payment.failed event successfully', async () => {
      const event = {
        id: 'evt_failed',
        event: 'payment.failed',
        payload: { payment: { entity: { id: 'pay_2', order_id: 'order_2', status: 'failed', amount: 1000, currency: 'INR' } } }
      }
      
      const result = await handleRazorpayEvent(event as any, { maxAttempts: 1 })
      expect(result.status).toBe('ok')
      expect(result.message).toContain('failed')
    })

    it('ignores duplicate events using in-memory store', async () => {
      const event = {
        id: 'evt_dup',
        event: 'payment.captured',
        payload: { payment: { entity: { id: 'pay_3', order_id: 'order_3', status: 'captured', amount: 1000, currency: 'INR' } } }
      }
      
      await handleRazorpayEvent(event as any, { maxAttempts: 1 })
      const result2 = await handleRazorpayEvent(event as any, { maxAttempts: 1 })
      
      expect(result2.status).toBe('ok')
      expect(result2.message).toContain('already processed')
      // markEventProcessed should only be called once
      expect(idempotency.markEventProcessed).toHaveBeenCalledTimes(1)
    })
    
    it('ignores duplicate events via idempotency module', async () => {
      vi.mocked(idempotency.isEventProcessed).mockReturnValue(true)
      const event = {
        id: 'evt_dup_2',
        event: 'payment.captured',
        payload: { payment: { entity: { id: 'pay_4', order_id: 'order_4', status: 'captured', amount: 1000, currency: 'INR' } } }
      }
      
      const result = await handleRazorpayEvent(event as any, { maxAttempts: 1 })
      expect(result.status).toBe('duplicate')
    })

    it('handles unhandled event types gracefully', async () => {
      const event = {
        id: 'evt_unhandled',
        event: 'subscription.created',
        payload: {}
      }
      
      const result = await handleRazorpayEvent(event as any, { maxAttempts: 1 })
      expect(result.status).toBe('ignored')
      expect(result.message).toContain('Unhandled event type')
    })
  })
})
