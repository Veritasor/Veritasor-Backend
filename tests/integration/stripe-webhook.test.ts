/**
 * Integration tests for POST /api/integrations/stripe/webhook
 *
 * Covers replay resistance, duplicate event handling, signature verification,
 * timestamp tolerance, and HTTP response codes end-to-end through the Express
 * route layer  no mocks of the service functions themselves.
 */
import { describe, it, expect, beforeAll, beforeEach, afterEach } from 'vitest'
import request from 'supertest'
import express, { type Express } from 'express'
import crypto from 'crypto'
import { integrationsStripeRouter } from '../../src/routes/integrations-stripe.js'
import { computeStripeSignature, seenEventStore, STRIPE_WEBHOOK_TOLERANCE_SECONDS } from '../../src/services/integrations/stripe/callback.js'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const WEBHOOK_SECRET = 'whsec_integration_test_secret_abc123'
const NOW_SECS = Math.floor(Date.now() / 1000)

function buildSigHeader(rawBody: string, secret: string, ts: number, extra: string[] = []): string {
  const sig = computeStripeSignature(ts, rawBody, secret)
  return ['t=' + ts, 'v1=' + sig, ...extra.map(s => 'v1=' + s)].join(',')
}

function makeEvent(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    id: 'evt_integ_' + crypto.randomBytes(8).toString('hex'),
    type: 'account.updated',
    created: NOW_SECS,
    data: { object: {} },
    ...overrides,
  })
}

// ---------------------------------------------------------------------------
// App setup
// ---------------------------------------------------------------------------

let app: Express

beforeAll(() => {
  app = express()
  // Mount WITHOUT express.json() before the webhook route so the route
  // receives the raw body and can verify the HMAC signature.
  app.use('/api/integrations/stripe', integrationsStripeRouter)
  process.env.STRIPE_WEBHOOK_SECRET = WEBHOOK_SECRET
})

beforeEach(() => {
  seenEventStore.clear()
})

afterEach(() => {
  seenEventStore.clear()
})

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('POST /api/integrations/stripe/webhook', () => {

  //  Happy path 
  it('returns 200 for a valid signed event', async () => {
    const body = makeEvent()
    const sig = buildSigHeader(body, WEBHOOK_SECRET, NOW_SECS)
    const res = await request(app)
      .post('/api/integrations/stripe/webhook')
      .set('stripe-signature', sig)
      .set('content-type', 'application/json')
      .send(body)
    expect(res.status).toBe(200)
    expect(res.body.received).toBe(true)
  })

  it('returns 200 and acknowledges an unknown event type without error', async () => {
    const body = makeEvent({ type: 'some.unknown.event' })
    const sig = buildSigHeader(body, WEBHOOK_SECRET, NOW_SECS)
    const res = await request(app)
      .post('/api/integrations/stripe/webhook')
      .set('stripe-signature', sig)
      .set('content-type', 'application/json')
      .send(body)
    expect(res.status).toBe(200)
    expect(res.body.received).toBe(true)
  })

  //  Missing / wrong secret 
  it('returns 401 when stripe-signature header is absent', async () => {
    const body = makeEvent()
    const res = await request(app)
      .post('/api/integrations/stripe/webhook')
      .set('content-type', 'application/json')
      .send(body)
    expect(res.status).toBe(401)
  })

  it('returns 401 when signed with the wrong secret', async () => {
    const body = makeEvent()
    const sig = buildSigHeader(body, 'wrong_secret', NOW_SECS)
    const res = await request(app)
      .post('/api/integrations/stripe/webhook')
      .set('stripe-signature', sig)
      .set('content-type', 'application/json')
      .send(body)
    expect(res.status).toBe(401)
  })

  it('returns 401 when the body is tampered after signing', async () => {
    const body = makeEvent()
    const sig = buildSigHeader(body, WEBHOOK_SECRET, NOW_SECS)
    const res = await request(app)
      .post('/api/integrations/stripe/webhook')
      .set('stripe-signature', sig)
      .set('content-type', 'application/json')
      .send(body + ' ')
    expect(res.status).toBe(401)
  })

  //  Replay resistance  timestamp tolerance 
  it('returns 401 for an event older than the tolerance window (replay attack)', async () => {
    const body = makeEvent()
    const staleTs = NOW_SECS - STRIPE_WEBHOOK_TOLERANCE_SECONDS - 1
    const sig = buildSigHeader(body, WEBHOOK_SECRET, staleTs)
    const res = await request(app)
      .post('/api/integrations/stripe/webhook')
      .set('stripe-signature', sig)
      .set('content-type', 'application/json')
      .send(body)
    expect(res.status).toBe(401)
  })

  it('returns 401 for an event with a timestamp far in the future', async () => {
    const body = makeEvent()
    const futureTs = NOW_SECS + STRIPE_WEBHOOK_TOLERANCE_SECONDS + 1
    const sig = buildSigHeader(body, WEBHOOK_SECRET, futureTs)
    const res = await request(app)
      .post('/api/integrations/stripe/webhook')
      .set('stripe-signature', sig)
      .set('content-type', 'application/json')
      .send(body)
    expect(res.status).toBe(401)
  })

  it('returns 200 for an event at the exact tolerance boundary', async () => {
    const body = makeEvent()
    const boundaryTs = NOW_SECS - STRIPE_WEBHOOK_TOLERANCE_SECONDS
    const sig = buildSigHeader(body, WEBHOOK_SECRET, boundaryTs)
    const res = await request(app)
      .post('/api/integrations/stripe/webhook')
      .set('stripe-signature', sig)
      .set('content-type', 'application/json')
      .send(body)
    expect(res.status).toBe(200)
  })

  //  Duplicate event deduplication 
  it('returns 200 on first delivery and 200 with duplicate note on second delivery', async () => {
    const body = makeEvent({ id: 'evt_dedup_integ_001' })
    const sig = buildSigHeader(body, WEBHOOK_SECRET, NOW_SECS)

    const first = await request(app)
      .post('/api/integrations/stripe/webhook')
      .set('stripe-signature', sig)
      .set('content-type', 'application/json')
      .send(body)
    expect(first.status).toBe(200)
    expect(first.body.received).toBe(true)
    expect(first.body.note).toBeUndefined()

    const second = await request(app)
      .post('/api/integrations/stripe/webhook')
      .set('stripe-signature', sig)
      .set('content-type', 'application/json')
      .send(body)
    // 200 so Stripe stops retrying, but flagged as duplicate
    expect(second.status).toBe(200)
    expect(second.body.note).toBe('duplicate')
  })

  it('accepts the same event type with a different ID (not a duplicate)', async () => {
    const body1 = makeEvent({ id: 'evt_unique_integ_a' })
    const body2 = makeEvent({ id: 'evt_unique_integ_b' })
    const sig1 = buildSigHeader(body1, WEBHOOK_SECRET, NOW_SECS)
    const sig2 = buildSigHeader(body2, WEBHOOK_SECRET, NOW_SECS)

    const r1 = await request(app)
      .post('/api/integrations/stripe/webhook')
      .set('stripe-signature', sig1)
      .set('content-type', 'application/json')
      .send(body1)
    const r2 = await request(app)
      .post('/api/integrations/stripe/webhook')
      .set('stripe-signature', sig2)
      .set('content-type', 'application/json')
      .send(body2)

    expect(r1.status).toBe(200)
    expect(r2.status).toBe(200)
    expect(r2.body.note).toBeUndefined()
  })

  it('rejects a replayed event re-signed with a fresh timestamp (same event ID)', async () => {
    const body = makeEvent({ id: 'evt_replay_resign_001' })
    const sig1 = buildSigHeader(body, WEBHOOK_SECRET, NOW_SECS)
    await request(app)
      .post('/api/integrations/stripe/webhook')
      .set('stripe-signature', sig1)
      .set('content-type', 'application/json')
      .send(body)

    // Attacker re-signs with a fresh timestamp but same event ID
    const sig2 = buildSigHeader(body, WEBHOOK_SECRET, NOW_SECS + 5)
    const res = await request(app)
      .post('/api/integrations/stripe/webhook')
      .set('stripe-signature', sig2)
      .set('content-type', 'application/json')
      .send(body)
    expect(res.status).toBe(200)
    expect(res.body.note).toBe('duplicate')
  })

  //  Invalid payload 
  it('returns 400 for a validly-signed but non-JSON payload', async () => {
    const body = 'not-json-at-all'
    const sig = buildSigHeader(body, WEBHOOK_SECRET, NOW_SECS)
    const res = await request(app)
      .post('/api/integrations/stripe/webhook')
      .set('stripe-signature', sig)
      .set('content-type', 'text/plain')
      .send(body)
    expect(res.status).toBe(400)
  })

  it('returns 400 for a validly-signed payload missing the event id', async () => {
    const body = JSON.stringify({ type: 'account.updated', created: NOW_SECS, data: { object: {} } })
    const sig = buildSigHeader(body, WEBHOOK_SECRET, NOW_SECS)
    const res = await request(app)
      .post('/api/integrations/stripe/webhook')
      .set('stripe-signature', sig)
      .set('content-type', 'application/json')
      .send(body)
    expect(res.status).toBe(400)
  })

  //  Missing server config 
  it('returns 500 when STRIPE_WEBHOOK_SECRET env var is not set', async () => {
    const saved = process.env.STRIPE_WEBHOOK_SECRET
    delete process.env.STRIPE_WEBHOOK_SECRET
    const body = makeEvent()
    const res = await request(app)
      .post('/api/integrations/stripe/webhook')
      .set('content-type', 'application/json')
      .send(body)
    expect(res.status).toBe(500)
    process.env.STRIPE_WEBHOOK_SECRET = saved
  })

  //  Security: no secret leakage in responses 
  it('does not leak the webhook secret in any error response', async () => {
    const body = makeEvent()
    const sig = buildSigHeader(body, 'wrong_secret', NOW_SECS)
    const res = await request(app)
      .post('/api/integrations/stripe/webhook')
      .set('stripe-signature', sig)
      .set('content-type', 'application/json')
      .send(body)
    expect(JSON.stringify(res.body)).not.toContain(WEBHOOK_SECRET)
    expect(JSON.stringify(res.body)).not.toContain('wrong_secret')
  })

})