/**
 * Integration tests for attestations API.
 * Uses requireAuth; expects 401 when unauthenticated.
 */
import { test } from 'node:test'
import assert from 'node:assert'
import request from 'supertest'
import { app } from '../../src/app.js'

const authHeader = { Authorization: 'Bearer test-token' }

test('GET /api/attestations returns 401 when unauthenticated', async () => {
  const res = await request(app).get('/api/attestations')
  assert.strictEqual(res.status, 401)
  assert.ok(res.body?.error === 'Unauthorized' || res.body?.message)
})

test('GET /api/attestations list returns empty when no data', async () => {
  const res = await request(app).get('/api/attestations').set(authHeader)
  assert.strictEqual(res.status, 200)
  assert.ok(Array.isArray(res.body?.attestations))
  assert.strictEqual(res.body.attestations.length, 0)
  assert.ok(res.body?.message)
})

test('GET /api/attestations list response has expected shape (with data case)', async () => {
  const res = await request(app).get('/api/attestations').set(authHeader)
  assert.strictEqual(res.status, 200)
  assert.ok('attestations' in res.body)
  assert.ok(Array.isArray(res.body.attestations))
  // When backend returns data, items can be validated here
})

test('GET /api/attestations/:id returns 401 when unauthenticated', async () => {
  const res = await request(app).get('/api/attestations/abc-123')
  assert.strictEqual(res.status, 401)
})

test('GET /api/attestations/:id returns attestation by id when authenticated', async () => {
  const res = await request(app).get('/api/attestations/abc-123').set(authHeader)
  assert.strictEqual(res.status, 200)
  assert.strictEqual(res.body?.id, 'abc-123')
  assert.ok(res.body?.message)
})

test('POST /api/attestations returns 401 when unauthenticated', async () => {
  const res = await request(app)
    .post('/api/attestations')
    .set('Idempotency-Key', 'test-key')
    .send({ business_id: 'b1', period: '2024-01' })
  assert.strictEqual(res.status, 401)
})

test('POST /api/attestations submit succeeds with auth and Idempotency-Key', async () => {
  const res = await request(app)
    .post('/api/attestations')
    .set(authHeader)
    .set('Idempotency-Key', 'integration-test-submit-1')
    .send({ business_id: 'b1', period: '2024-01' })
  assert.strictEqual(res.status, 201)
  assert.ok(res.body?.message)
  assert.strictEqual(res.body?.business_id, 'b1')
  assert.strictEqual(res.body?.period, '2024-01')
})

test('POST /api/attestations duplicate request returns same response (idempotent)', async () => {
  const key = 'integration-test-idempotent-' + Date.now()
  const first = await request(app)
    .post('/api/attestations')
    .set(authHeader)
    .set('Idempotency-Key', key)
    .send({ business_id: 'b2', period: '2024-02' })
  assert.strictEqual(first.status, 201)
  const second = await request(app)
    .post('/api/attestations')
    .set(authHeader)
    .set('Idempotency-Key', key)
    .send({ business_id: 'b2', period: '2024-02' })
  assert.strictEqual(second.status, 201)
  assert.deepStrictEqual(second.body, first.body)
})

test('DELETE /api/attestations/:id revoke returns 401 when unauthenticated', async () => {
  const res = await request(app).delete('/api/attestations/xyz-456')
  assert.strictEqual(res.status, 401)
})

test('DELETE /api/attestations/:id revoke succeeds when authenticated', async () => {
  const res = await request(app).delete('/api/attestations/xyz-456').set(authHeader)
  assert.strictEqual(res.status, 200)
  assert.strictEqual(res.body?.id, 'xyz-456')
  assert.ok(res.body?.message)
})
