import { describe, it, expect, vi } from 'vitest'

vi.mock('../../../src/services/webhooks/deadLetterQueue.js', () => ({
  saveDeadLetter: vi.fn(),
}))

import { handleRazorpayEvent, RazorpayWebhookError } from '../../../src/services/webhooks/razorpayHandler.js'
import { saveDeadLetter } from '../../../src/services/webhooks/deadLetterQueue.js'

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

  it('rejects a replayed old event outside tolerance window and saves to DLQ', async () => {
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
    expect(saveDeadLetter).toHaveBeenCalledWith('razorpay', staleEvent.id, staleEvent, error)
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

// ─── verifyRazorpaySignatureWithRotation unit tests ───────────────────────────

import crypto from 'node:crypto'
import {
  verifyRazorpaySignature,
  verifyRazorpaySignatureWithRotation,
} from '../../../src/services/webhooks/razorpayHandler.js'

function hmacHex(body: Buffer, secret: string): string {
  return crypto.createHmac('sha256', secret).update(body).digest('hex')
}

const BODY = Buffer.from('{"id":"evt_unit","event":"payment.captured"}')
const PRIMARY = 'unit_primary_secret'
const SECONDARY = 'unit_secondary_secret'
const WRONG = 'unit_wrong_secret'

describe('verifyRazorpaySignature', () => {
  it('returns true for a correct HMAC-SHA256 signature', () => {
    expect(verifyRazorpaySignature(BODY, hmacHex(BODY, PRIMARY), PRIMARY)).toBe(true)
  })

  it('returns false for a wrong secret', () => {
    expect(verifyRazorpaySignature(BODY, hmacHex(BODY, PRIMARY), WRONG)).toBe(false)
  })

  it('returns false for a tampered body', () => {
    const tampered = Buffer.from('{"id":"evt_unit","event":"payment.failed"}')
    expect(verifyRazorpaySignature(tampered, hmacHex(BODY, PRIMARY), PRIMARY)).toBe(false)
  })

  it('returns false for a non-hex signature', () => {
    expect(verifyRazorpaySignature(BODY, 'not-hex-at-all', PRIMARY)).toBe(false)
  })

  it('returns false for an empty secret', () => {
    expect(verifyRazorpaySignature(BODY, hmacHex(BODY, PRIMARY), '')).toBe(false)
  })
})

describe('verifyRazorpaySignatureWithRotation', () => {
  it('matches primary when only primary is set', () => {
    const sig = hmacHex(BODY, PRIMARY)
    const result = verifyRazorpaySignatureWithRotation(BODY, sig, PRIMARY)
    expect(result).toEqual({ valid: true, keyLabel: 'primary' })
  })

  it('returns invalid when only primary is set and signature is wrong', () => {
    const sig = hmacHex(BODY, WRONG)
    const result = verifyRazorpaySignatureWithRotation(BODY, sig, PRIMARY)
    expect(result).toEqual({ valid: false, keyLabel: null })
  })

  it('matches primary when both secrets are set and signature is for primary', () => {
    const sig = hmacHex(BODY, PRIMARY)
    const result = verifyRazorpaySignatureWithRotation(BODY, sig, PRIMARY, SECONDARY)
    expect(result).toEqual({ valid: true, keyLabel: 'primary' })
  })

  it('matches secondary when both secrets are set and signature is for secondary', () => {
    const sig = hmacHex(BODY, SECONDARY)
    const result = verifyRazorpaySignatureWithRotation(BODY, sig, PRIMARY, SECONDARY)
    expect(result).toEqual({ valid: true, keyLabel: 'secondary' })
  })

  it('returns invalid when neither primary nor secondary matches', () => {
    const sig = hmacHex(BODY, WRONG)
    const result = verifyRazorpaySignatureWithRotation(BODY, sig, PRIMARY, SECONDARY)
    expect(result).toEqual({ valid: false, keyLabel: null })
  })

  it('does not fall through to secondary when primary matches (short-circuit)', () => {
    // Both secrets produce different HMACs; only primary sig is provided.
    // If secondary were tried first or both tried, the result would differ.
    const primarySig = hmacHex(BODY, PRIMARY)
    const result = verifyRazorpaySignatureWithRotation(BODY, primarySig, PRIMARY, SECONDARY)
    expect(result.keyLabel).toBe('primary')
  })

  it('treats undefined secondary as absent (no secondary attempt)', () => {
    const sig = hmacHex(BODY, SECONDARY)
    // Secondary sig against primary-only config must fail
    const result = verifyRazorpaySignatureWithRotation(BODY, sig, PRIMARY, undefined)
    expect(result).toEqual({ valid: false, keyLabel: null })
  })

  it('treats empty-string secondary as absent', () => {
    const sig = hmacHex(BODY, SECONDARY)
    const result = verifyRazorpaySignatureWithRotation(BODY, sig, PRIMARY, '')
    expect(result).toEqual({ valid: false, keyLabel: null })
  })
})
