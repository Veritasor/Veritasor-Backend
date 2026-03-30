/**
 * Integration tests for attestations API.
 * Uses requireAuth; expects 401 when unauthenticated.
 */
import { describe, it, expect, vi } from 'vitest'
import request from 'supertest'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { businessRepository } from '../../src/repositories/business.js'

const { submitAttestationMock } = vi.hoisted(() => ({
  submitAttestationMock: vi.fn(),
}))

vi.mock('../../src/services/soroban/submitAttestation.js', () => ({
  submitAttestation: submitAttestationMock,
}))

import { app } from '../../src/app.js'
import {
  validateSendTransactionResponse,
  waitForConfirmation,
  validateConfirmedResult,
  SorobanSubmissionError,
} from '../../src/services/soroban/submitAttestation.js'

const authHeader = { 'x-user-id': 'user_1' }
const business = {
  id: 'biz_1',
  userId: 'user_1',
  name: 'Acme Inc',
  industry: null,
  description: null,
  website: null,
  createdAt: '2026-01-01T00:00:00.000Z',
  updatedAt: '2026-01-01T00:00:00.000Z',
}

// ---------------------------------------------------------------------------
// Existing API integration tests
// ---------------------------------------------------------------------------

test('GET /api/attestations returns 401 when unauthenticated', async () => {
  const res = await request(app).get('/api/attestations')
  assert.strictEqual(res.status, 401)
  assert.ok(res.body?.error === 'Unauthorized' || res.body?.message)
})

  it('returns 401 when listing attestations without authentication', async () => {
    const res = await request(app).get('/api/attestations')

    expect(res.status).toBe(401)
    expect(res.body).toEqual({ error: 'Unauthorized' })
  })

  it('lists attestations for the authenticated business with pagination metadata', async () => {
    const res = await request(app).get('/api/attestations').set(authHeader)

    expect(res.status).toBe(200)
    expect(res.body.status).toBe('success')
    expect(Array.isArray(res.body.data)).toBe(true)
    expect(res.body.data.length).toBeGreaterThan(0)
    expect(res.body.data[0].businessId).toBe('biz_1')
    expect(res.body.pagination).toMatchObject({
      page: 1,
      limit: 20,
      totalPages: 1,
    })
  })

  it('returns an attestation by id for the authenticated business', async () => {
    const res = await request(app).get('/api/attestations/att_1').set(authHeader)

    expect(res.status).toBe(200)
    expect(res.body.status).toBe('success')
    expect(res.body.data).toMatchObject({
      id: 'att_1',
      businessId: 'biz_1',
    })
  })

  it('submits an attestation and persists the Soroban transaction hash', async () => {
    submitAttestationMock.mockResolvedValue({
      txHash: 'tx_success_123',
    })

    const res = await request(app)
      .post('/api/attestations')
      .set(authHeader)
      .set('Idempotency-Key', 'integration-submit-success')
      .send({
        period: '2026-02',
        merkleRoot: 'abc123',
        timestamp: 1700000000,
        version: '1.2.0',
      })

    expect(res.status).toBe(201)
    expect(res.body.status).toBe('success')
    expect(res.body.txHash).toBe('tx_success_123')
    expect(res.body.data).toMatchObject({
      businessId: 'biz_1',
      period: '2026-02',
      merkleRoot: 'abc123',
      timestamp: 1700000000,
      version: '1.2.0',
      txHash: 'tx_success_123',
      status: 'submitted',
    })
    expect(submitAttestationMock).toHaveBeenCalledTimes(1)
    expect(submitAttestationMock).toHaveBeenCalledWith({
      business: 'biz_1',
      period: '2026-02',
      merkleRoot: 'abc123',
      timestamp: 1700000000,
      version: '1.2.0',
    })
  })

  it('returns the cached response for duplicate idempotent submissions', async () => {
    submitAttestationMock.mockResolvedValue({
      txHash: 'tx_cached_123',
    })

    const key = `integration-idempotent-${Date.now()}`
    const payload = {
      period: '2026-03',
      merkleRoot: 'root-123',
      timestamp: 1700000100,
      version: '1.0.0',
    }

    const first = await request(app)
      .post('/api/attestations')
      .set(authHeader)
      .set('Idempotency-Key', key)
      .send(payload)

    const second = await request(app)
      .post('/api/attestations')
      .set(authHeader)
      .set('Idempotency-Key', key)
      .send(payload)

    expect(first.status).toBe(201)
    expect(second.status).toBe(201)
    expect(second.body).toEqual(first.body)
    expect(submitAttestationMock).toHaveBeenCalledTimes(1)
  })

  it('returns 400 when the idempotency key is missing', async () => {
    const res = await request(app)
      .post('/api/attestations')
      .set(authHeader)
      .send({
        period: '2026-04',
        merkleRoot: 'root-456',
      })

    expect(res.status).toBe(400)
    expect(res.body).toEqual({ error: 'Missing Idempotency-Key header' })
  })

  it('maps Soroban RPC failures to a 502 response', async () => {
    submitAttestationMock.mockRejectedValue(
      Object.assign(new Error('retry budget exhausted'), {
        code: 'SUBMIT_FAILED',
      }),
    )

    const res = await request(app)
      .post('/api/attestations')
      .set(authHeader)
      .set('Idempotency-Key', `integration-submit-failure-${Date.now()}`)
      .send({
        period: '2026-05',
        merkleRoot: 'root-789',
      })

    expect(res.status).toBe(502)
    expect(res.body).toMatchObject({
      status: 'error',
      code: 'SUBMIT_FAILED',
      message: 'Soroban RPC request failed after applying the retry policy.',
    })
  })

  it('maps signer configuration failures to a 503 response without leaking secrets', async () => {
    submitAttestationMock.mockRejectedValue(
      Object.assign(new Error('signerSecret does not match sourcePublicKey.'), {
        code: 'SIGNER_MISMATCH',
      }),
    )

    const res = await request(app)
      .post('/api/attestations')
      .set(authHeader)
      .set('Idempotency-Key', `integration-signer-failure-${Date.now()}`)
      .send({
        period: '2026-06',
        merkleRoot: 'root-999',
      })

    expect(res.status).toBe(503)
    expect(res.body).toMatchObject({
      status: 'error',
      code: 'SIGNER_MISMATCH',
      message: 'Soroban submission is not available right now.',
    })
    expect(res.body.message).not.toContain('signerSecret')
  })
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
