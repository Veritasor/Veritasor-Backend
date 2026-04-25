/**
 * Integration tests for attestations API.
 * Uses requireAuth (checks x-user-id header); expects 401 when unauthenticated.
 *
 * Note: Routes that call resolveBusinessIdForUser() without a businessId query
 * param will hit the real DB client (not configured in tests) and return 500.
 * Tests that require an actual database are omitted here; they belong in e2e tests.
 */
import assert from 'node:assert'
import { beforeEach, describe, expect, it, test, vi } from 'vitest'
import request from 'supertest'
import { businessRepository } from '../../src/repositories/business.js'

const { submitAttestationMock } = vi.hoisted(() => ({
  submitAttestationMock: vi.fn(),
}))

vi.mock('../../src/services/soroban/submitAttestation.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/services/soroban/submitAttestation.js')>()
  return {
    ...actual,
    submitAttestation: submitAttestationMock,
  }
})

import { app } from '../../src/app.js'
import {
  validateSendTransactionResponse,
  waitForConfirmation,
  validateConfirmedResult,
  SorobanSubmissionError,
} from '../../src/services/soroban/submitAttestation.js'
import {
  parsePeriodToBounds,
  dateToPeriod,
  currentPeriod,
  isTimestampInPeriod,
  listAttestedPeriodsForBusiness,
  PeriodParseError,
} from '../../src/services/analytics/periods.js'

const authHeader = { 'x-user-id': 'user_1' }
const business = {
  id: 'biz_1',
  userId: 'user_1',
  name: 'Acme Inc',
  email: 'owner@acme.example',
  industry: null,
  description: null,
  website: null,
  createdAt: '2026-01-01T00:00:00.000Z',
  updatedAt: '2026-01-01T00:00:00.000Z',
}

// ---------------------------------------------------------------------------
// Existing API integration tests
// ---------------------------------------------------------------------------

describe('Attestations HTTP integration', () => {
  beforeEach(() => {
    submitAttestationMock.mockClear()
    vi.spyOn(businessRepository, 'getByUserId').mockResolvedValue(business)
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

describe("GET /api/attestations", () => {
  it("should return 401 when unauthenticated", async () => {
    const res = await request(app).get("/api/attestations");
    expect(res.status).toBe(401);
    expect(res.body.error).toMatch(/unauthorized/i);
  });

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
    expect(res.body).toMatchObject({
      code: 'IDEMPOTENCY_KEY_REQUIRED',
      error: 'Bad Request',
    })
    expect(String(res.body.message).toLowerCase()).toContain('idempotency')
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
    })
    expect(res.body.message).toBeDefined()
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
    })
    expect(String(res.body.message)).not.toContain('signerSecret')
  })
})

describe('API version negotiation (attestations integration)', () => {
  it('responds with API-Version v1 for unversioned routes (default negotiation)', async () => {
    const res = await request(app).get('/api/attestations').set(authHeader)
    expect(res.status).toBe(200)
    expect(res.headers['api-version']).toBe('v1')
    expect(res.headers['api-version-fallback']).toBeUndefined()
  })

  it('honors X-API-Version: 1 without fallback', async () => {
    const res = await request(app)
      .get('/api/attestations')
      .set(authHeader)
      .set('X-API-Version', '1')
    expect(res.status).toBe(200)
    expect(res.headers['api-version']).toBe('v1')
    expect(res.headers['api-version-fallback']).toBeUndefined()
  })

  it('falls back to v1 with API-Version-Fallback when an unsupported major is requested', async () => {
    const res = await request(app)
      .get('/api/attestations')
      .set(authHeader)
      .set('X-API-Version', '99')
    expect(res.status).toBe(200)
    expect(res.headers['api-version']).toBe('v1')
    expect(res.headers['api-version-fallback']).toBe('true')
  })

  it('includes Vary for cache correctness when version may depend on headers', async () => {
    const res = await request(app).get('/api/attestations').set(authHeader)
    const vary = (res.headers.vary ?? '').toLowerCase()
    expect(vary).toContain('accept')
    expect(vary).toContain('x-api-version')
  })
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

// ---------------------------------------------------------------------------
// DST-safe analytics period calculation tests
// ---------------------------------------------------------------------------

describe('parsePeriodToBounds — DST-safe UTC boundaries', () => {
  it('returns UTC midnight start and exclusive end for a standard month', () => {
    const { start, end } = parsePeriodToBounds('2024-06')
    expect(start.toISOString()).toBe('2024-06-01T00:00:00.000Z')
    expect(end.toISOString()).toBe('2024-07-01T00:00:00.000Z')
  })

  it('start boundary is exactly UTC midnight, not local midnight', () => {
    // This assertion holds regardless of the server TZ because Date.UTC is used.
    const { start } = parsePeriodToBounds('2024-06')
    expect(start.getUTCHours()).toBe(0)
    expect(start.getUTCMinutes()).toBe(0)
    expect(start.getUTCSeconds()).toBe(0)
    expect(start.getUTCMilliseconds()).toBe(0)
  })

  it('handles December → January year rollover correctly', () => {
    const { start, end } = parsePeriodToBounds('2024-12')
    expect(start.toISOString()).toBe('2024-12-01T00:00:00.000Z')
    expect(end.toISOString()).toBe('2025-01-01T00:00:00.000Z')
  })

  it('handles January correctly', () => {
    const { start, end } = parsePeriodToBounds('2025-01')
    expect(start.toISOString()).toBe('2025-01-01T00:00:00.000Z')
    expect(end.toISOString()).toBe('2025-02-01T00:00:00.000Z')
  })

  it('US/Eastern spring-forward month: March 2024 boundaries are unaffected by DST', () => {
    // Clocks spring forward on 2024-03-10 02:00 US/Eastern → 03:00 local.
    // UTC boundaries must still be exactly March 1 and April 1 midnight UTC.
    const { start, end } = parsePeriodToBounds('2024-03')
    expect(start.toISOString()).toBe('2024-03-01T00:00:00.000Z')
    expect(end.toISOString()).toBe('2024-04-01T00:00:00.000Z')
  })

  it('US/Eastern fall-back month: November 2024 boundaries are unaffected by DST', () => {
    // Clocks fall back on 2024-11-03 02:00 US/Eastern → 01:00 local.
    const { start, end } = parsePeriodToBounds('2024-11')
    expect(start.toISOString()).toBe('2024-11-01T00:00:00.000Z')
    expect(end.toISOString()).toBe('2024-12-01T00:00:00.000Z')
  })

  it('throws PeriodParseError for a malformed period string', () => {
    expect(() => parsePeriodToBounds('2024/03')).toThrow(PeriodParseError)
    expect(() => parsePeriodToBounds('24-03')).toThrow(PeriodParseError)
    expect(() => parsePeriodToBounds('2024-3')).toThrow(PeriodParseError)
    expect(() => parsePeriodToBounds('')).toThrow(PeriodParseError)
    expect(() => parsePeriodToBounds('not-a-date')).toThrow(PeriodParseError)
  })

  it('PeriodParseError has the correct code and name', () => {
    try {
      parsePeriodToBounds('bad')
    } catch (e: any) {
      expect(e).toBeInstanceOf(PeriodParseError)
      expect(e.code).toBe('INVALID_PERIOD')
      expect(e.name).toBe('PeriodParseError')
      expect(e.message).toContain('"bad"')
    }
  })
})

describe('dateToPeriod — UTC-based period label derivation', () => {
  it('maps a UTC timestamp to the correct YYYY-MM label', () => {
    expect(dateToPeriod(new Date('2024-03-15T12:00:00.000Z'))).toBe('2024-03')
  })

  it('handles a UTC timestamp at the very start of a month', () => {
    expect(dateToPeriod(new Date('2024-04-01T00:00:00.000Z'))).toBe('2024-04')
  })

  it('handles a UTC timestamp one millisecond before the end of a month', () => {
    expect(dateToPeriod(new Date('2024-03-31T23:59:59.999Z'))).toBe('2024-03')
  })

  it('does NOT misclassify a timestamp that is still in the previous month in UTC even if local time shows the next month', () => {
    // 2024-04-01T00:30:00.000Z is April in UTC.
    // But a server in UTC+2 would see this as 02:30 on April 1st, still April.
    // A server in UTC-5 would see this as 23:30 on March 31st — but dateToPeriod
    // must always return '2024-04' because it reads UTC.
    expect(dateToPeriod(new Date('2024-04-01T00:30:00.000Z'))).toBe('2024-04')
  })

  it('during US/Eastern spring-forward: a timestamp in the skipped hour is in March in UTC', () => {
    // 2024-03-10T07:00:00Z = 2024-03-10 02:00 US/Eastern (the skipped hour)
    // UTC month is still March → '2024-03'
    expect(dateToPeriod(new Date('2024-03-10T07:00:00.000Z'))).toBe('2024-03')
  })

  it('during US/Eastern fall-back: the ambiguous hour is resolved by UTC', () => {
    // 2024-11-03T06:00:00Z = one of the two 01:00 US/Eastern hours (ambiguous locally)
    // UTC month is November → '2024-11'
    expect(dateToPeriod(new Date('2024-11-03T06:00:00.000Z'))).toBe('2024-11')
  })

  it('handles December correctly', () => {
    expect(dateToPeriod(new Date('2024-12-31T23:59:59.999Z'))).toBe('2024-12')
  })
})

describe('currentPeriod', () => {
  it('returns a string matching YYYY-MM format', () => {
    expect(currentPeriod()).toMatch(/^\d{4}-\d{2}$/)
  })

  it('returns the same period as dateToPeriod(new Date())', () => {
    // Freeze time to avoid a race between the two calls.
    const before = dateToPeriod(new Date())
    const result = currentPeriod()
    const after = dateToPeriod(new Date())
    // result must be within [before, after] — all equal unless month rolls over mid-test.
    expect([before, after]).toContain(result)
  })
})

describe('isTimestampInPeriod — DST-safe range check', () => {
  // 2024-03-01T00:00:00Z in seconds
  const marchStartSec = Date.UTC(2024, 2, 1) / 1000
  // 2024-03-31T23:59:59Z in seconds
  const marchLastSec = Date.UTC(2024, 2, 31, 23, 59, 59) / 1000
  // 2024-04-01T00:00:00Z in seconds (exclusive end of March)
  const aprilStartSec = Date.UTC(2024, 3, 1) / 1000

  it('returns true for the first second of the period', () => {
    expect(isTimestampInPeriod(marchStartSec, '2024-03')).toBe(true)
  })

  it('returns true for the last second of the period', () => {
    expect(isTimestampInPeriod(marchLastSec, '2024-03')).toBe(true)
  })

  it('returns false for the first second of the next period (exclusive end)', () => {
    expect(isTimestampInPeriod(aprilStartSec, '2024-03')).toBe(false)
  })

  it('returns false for a timestamp one second before the period starts', () => {
    expect(isTimestampInPeriod(marchStartSec - 1, '2024-03')).toBe(false)
  })

  it('US spring-forward: timestamp during the skipped hour is still in March', () => {
    // 2024-03-10T07:00:00Z = 02:00 US/Eastern (the hour that does not exist locally)
    const skippedHourSec = Date.UTC(2024, 2, 10, 7, 0, 0) / 1000
    expect(isTimestampInPeriod(skippedHourSec, '2024-03')).toBe(true)
  })

  it('US fall-back: timestamp during the ambiguous hour is correctly classified', () => {
    // 2024-11-03T06:30:00Z falls during the US/Eastern "fall-back" ambiguous hour.
    // UTC says it is still November → belongs to '2024-11', not '2024-10'.
    const ambiguousHourSec = Date.UTC(2024, 10, 3, 6, 30, 0) / 1000
    expect(isTimestampInPeriod(ambiguousHourSec, '2024-11')).toBe(true)
    expect(isTimestampInPeriod(ambiguousHourSec, '2024-10')).toBe(false)
  })

  it('handles December → January year boundary correctly', () => {
    const dec31LastSec = Date.UTC(2024, 11, 31, 23, 59, 59) / 1000
    const jan1FirstSec = Date.UTC(2025, 0, 1, 0, 0, 0) / 1000
    expect(isTimestampInPeriod(dec31LastSec, '2024-12')).toBe(true)
    expect(isTimestampInPeriod(jan1FirstSec, '2024-12')).toBe(false)
    expect(isTimestampInPeriod(jan1FirstSec, '2025-01')).toBe(true)
  })

  it('throws PeriodParseError for an invalid period string', () => {
    expect(() => isTimestampInPeriod(0, 'bad')).toThrow(PeriodParseError)
  })
})
