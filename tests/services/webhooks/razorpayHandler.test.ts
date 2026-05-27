import { describe, it, expect } from 'vitest'
import { handleRazorpayEvent, RazorpayWebhookError } from '../../../src/services/webhooks/razorpayHandler.js'

const makeEvent = (overrides: any = {}) => ({
  id: 'evt_test_123',
  event: 'payment.captured',
  created_at: Math.floor(Date.now() / 1000),
  payload: {
    payment: {
      entity: {
        id: 'pay_123',
        order_id: 'order_123',
        status: 'captured',
        amount: 1000,
        currency: 'INR',
      },
    },
  },
  ...overrides,
})

describe('handleRazorpayEvent', () => {
  it('processes a valid event on first delivery', async () => {
    const event = makeEvent({ id: 'evt_valid_' + Date.now() })
    const result = await handleRazorpayEvent(event)
    expect(result.status).toBe('ok')
  })

  it('returns duplicate status on second delivery of same event', async () => {
    const id = 'evt_dup_' + Date.now()
    const event = makeEvent({ id })
    await handleRazorpayEvent(event)
    const result = await handleRazorpayEvent(event)
    expect(result.status).toBe('duplicate')
    expect(result.message).toContain(id)
  })

  it('rejects a replayed old event outside tolerance window', async () => {
    const staleEvent = makeEvent({
      id: 'evt_stale_' + Date.now(),
      created_at: Math.floor(Date.now() / 1000) - 600,
    })
    let error: any
    try {
      await handleRazorpayEvent(staleEvent)
    } catch (e) {
      error = e
    }
    expect(error).toBeDefined()
    expect(error).toBeInstanceOf(RazorpayWebhookError)
    expect(error.code).toBe('invalid_timestamp')
  })

  it('handles missing event id by throwing', async () => {
    const badEvent = makeEvent({ id: 'evt_noid_' + Date.now(), event: 'unknown.event' })
    const result = await handleRazorpayEvent(badEvent)
    expect(result.status).toBe('ignored')
  })

  it('ignores unhandled event types', async () => {
    const event = makeEvent({ id: 'evt_ignored_' + Date.now(), event: 'refund.created' })
    const result = await handleRazorpayEvent(event)
    expect(result.status).toBe('ignored')
  })
})
