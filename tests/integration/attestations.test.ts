/**
 * Integration tests for attestations API.
 * Uses requireAuth; expects 401 when unauthenticated.
 */
import { describe, it, expect, vi } from 'vitest'
import request from 'supertest'
import { app } from '../../src/app.js'
import {
  validateSendTransactionResponse,
  waitForConfirmation,
  validateConfirmedResult,
  SorobanSubmissionError,
} from '../../src/services/soroban/submitAttestation.js'

const authHeader = { Authorization: 'Bearer test-token' }

// ---------------------------------------------------------------------------
// Existing API integration tests
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Soroban submit attestation response validation tests
// ---------------------------------------------------------------------------

const VALID_TX_HASH = 'a'.repeat(64)

test('validateSendTransactionResponse accepts valid PENDING response', () => {
  const response = { hash: VALID_TX_HASH, status: 'PENDING' }
  assert.doesNotThrow(() =>
    validateSendTransactionResponse(response as any)
  )
})

test('validateSendTransactionResponse accepts valid DUPLICATE response', () => {
  const response = { hash: VALID_TX_HASH, status: 'DUPLICATE' }
  assert.doesNotThrow(() =>
    validateSendTransactionResponse(response as any)
  )
})

test('validateSendTransactionResponse accepts ERROR status (validated before error mapping)', () => {
  const response = { hash: VALID_TX_HASH, status: 'ERROR' }
  assert.doesNotThrow(() =>
    validateSendTransactionResponse(response as any)
  )
})

test('validateSendTransactionResponse rejects null response', () => {
  assert.throws(
    () => validateSendTransactionResponse(null as any),
    (err: any) => {
      assert.ok(err instanceof SorobanSubmissionError)
      assert.strictEqual(err.code, 'INVALID_RESPONSE')
      return true
    }
  )
})

test('validateSendTransactionResponse rejects missing hash', () => {
  assert.throws(
    () => validateSendTransactionResponse({ status: 'PENDING' } as any),
    (err: any) => {
      assert.ok(err instanceof SorobanSubmissionError)
      assert.strictEqual(err.code, 'INVALID_RESPONSE')
      assert.ok(err.message.includes('invalid transaction hash'))
      return true
    }
  )
})

test('validateSendTransactionResponse rejects malformed hash', () => {
  const response = { hash: 'not-a-hex-hash', status: 'PENDING' }
  assert.throws(
    () => validateSendTransactionResponse(response as any),
    (err: any) => {
      assert.ok(err instanceof SorobanSubmissionError)
      assert.strictEqual(err.code, 'INVALID_RESPONSE')
      return true
    }
  )
})

test('validateSendTransactionResponse rejects short hash', () => {
  const response = { hash: 'abcdef1234', status: 'PENDING' }
  assert.throws(
    () => validateSendTransactionResponse(response as any),
    (err: any) => {
      assert.ok(err instanceof SorobanSubmissionError)
      assert.strictEqual(err.code, 'INVALID_RESPONSE')
      return true
    }
  )
})

test('validateSendTransactionResponse rejects uppercase hash', () => {
  const response = { hash: 'A'.repeat(64), status: 'PENDING' }
  assert.throws(
    () => validateSendTransactionResponse(response as any),
    (err: any) => {
      assert.ok(err instanceof SorobanSubmissionError)
      assert.strictEqual(err.code, 'INVALID_RESPONSE')
      return true
    }
  )
})

test('validateSendTransactionResponse rejects unknown status', () => {
  const response = { hash: VALID_TX_HASH, status: 'UNKNOWN_STATUS' }
  assert.throws(
    () => validateSendTransactionResponse(response as any),
    (err: any) => {
      assert.ok(err instanceof SorobanSubmissionError)
      assert.strictEqual(err.code, 'INVALID_RESPONSE')
      assert.ok(err.message.includes('unexpected status'))
      return true
    }
  )
})

test('waitForConfirmation resolves on immediate SUCCESS', async () => {
  const mockServer = {
    getTransaction: async () => ({
      status: 'SUCCESS',
      ledger: 12345,
      returnValue: null,
    }),
  }

  const result = await waitForConfirmation(mockServer as any, VALID_TX_HASH, 10, 3)
  assert.strictEqual(result.status, 'SUCCESS')
})

test('waitForConfirmation resolves after NOT_FOUND then SUCCESS', async () => {
  let callCount = 0
  const mockServer = {
    getTransaction: async () => {
      callCount++
      if (callCount < 3) {
        return { status: 'NOT_FOUND' }
      }
      return { status: 'SUCCESS', ledger: 99999, returnValue: null }
    },
  }

  const result = await waitForConfirmation(mockServer as any, VALID_TX_HASH, 10, 5)
  assert.strictEqual(result.status, 'SUCCESS')
  assert.strictEqual(callCount, 3)
})

test('waitForConfirmation throws CONFIRMATION_FAILED on FAILED status', async () => {
  const mockServer = {
    getTransaction: async () => ({ status: 'FAILED' }),
  }

  await assert.rejects(
    () => waitForConfirmation(mockServer as any, VALID_TX_HASH, 10, 3),
    (err: any) => {
      assert.ok(err instanceof SorobanSubmissionError)
      assert.strictEqual(err.code, 'CONFIRMATION_FAILED')
      return true
    }
  )
})

test('waitForConfirmation throws CONFIRMATION_TIMEOUT after max attempts', async () => {
  const mockServer = {
    getTransaction: async () => ({ status: 'NOT_FOUND' }),
  }

  await assert.rejects(
    () => waitForConfirmation(mockServer as any, VALID_TX_HASH, 10, 3),
    (err: any) => {
      assert.ok(err instanceof SorobanSubmissionError)
      assert.strictEqual(err.code, 'CONFIRMATION_TIMEOUT')
      assert.ok(err.message.includes('3 polling attempts'))
      return true
    }
  )
})

test('validateConfirmedResult throws when returnValue is undefined', () => {
  const merkleRoot = '0xdeadbeef1234567890abcdef'

  assert.throws(
    () => validateConfirmedResult({ returnValue: undefined } as any, merkleRoot),
    (err: any) => {
      assert.ok(err instanceof SorobanSubmissionError)
      assert.strictEqual(err.code, 'RESULT_VALIDATION_FAILED')
      assert.ok(err.message.includes('no return value'))
      return true
    }
  )
})

test('validateConfirmedResult throws on null returnValue', () => {
  assert.throws(
    () => validateConfirmedResult({ returnValue: null } as any, 'root'),
    (err: any) => {
      assert.ok(err instanceof SorobanSubmissionError)
      assert.strictEqual(err.code, 'RESULT_VALIDATION_FAILED')
      return true
    }
  )
})

test('SorobanSubmissionError has correct name and code', () => {
  const err = new SorobanSubmissionError('test message', 'TEST_CODE')
  assert.strictEqual(err.name, 'SorobanSubmissionError')
  assert.strictEqual(err.code, 'TEST_CODE')
  assert.strictEqual(err.message, 'test message')
  assert.ok(err instanceof Error)
})

test('SorobanSubmissionError preserves cause', () => {
  const cause = new Error('original')
  const err = new SorobanSubmissionError('wrapped', 'WRAP', cause)
  assert.strictEqual(err.cause, cause)
})
