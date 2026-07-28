import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

vi.mock('../../../../src/db/client.js', () => ({
  db: {
    query: vi.fn(),
  },
}))

import { db } from '../../../../src/db/client.js'
import {
  computePayloadHash,
  computeFailureFingerprint,
  resolveFingerprintCollision,
  saveDeadLetter,
  getDeadLetter,
  deleteDeadLetter,
  scanOldestDlqEntryAge,
  startDlqAgeScanner,
  MAX_PAYLOAD_SIZE,
  getBackpressureState,
  updateRateLimitFromHeaders,
  acquireReplayPermit,
} from '../../../../src/services/webhooks/deadLetterQueue.js'
import { webhookDlqOldestEntryAge } from '../../../../src/metrics.js'

describe('deadLetterQueue', () => {
  const mockQuery = vi.mocked(db.query)

  beforeEach(() => {
    mockQuery.mockReset()
  })

  describe('computePayloadHash', () => {
    it('computes a sha256 hash for a valid payload object', () => {
      const payload = { some: 'value', foo: 123 }
      const hash = computePayloadHash(payload)
      expect(hash).toMatch(/^[a-f0-9]{64}$/)
    })

    it('computes a sha256 hash for a valid payload string', () => {
      const payload = 'hello world'
      const hash = computePayloadHash(payload)
      expect(hash).toMatch(/^[a-f0-9]{64}$/)
    })

    it('throws error when payload is too large', () => {
      const largePayload = 'a'.repeat(MAX_PAYLOAD_SIZE + 1)
      expect(() => computePayloadHash(largePayload)).toThrowError('Payload too large')
    })
  })

  describe('computeFailureFingerprint', () => {
    it('generates consistent sha256 hash from provider, payloadHash, and errorCode', () => {
      const fp1 = computeFailureFingerprint('razorpay', 'hash123', 'ERR_INVALID')
      const fp2 = computeFailureFingerprint('razorpay', 'hash123', 'ERR_INVALID')
      expect(fp1).toBe(fp2)
      expect(fp1).toMatch(/^[a-f0-9]{64}$/)
    })
  })

  describe('resolveFingerprintCollision', () => {
    it('returns original fingerprint when stored payload hash matches current', () => {
      const fp = 'base_fp'
      const resolved = resolveFingerprintCollision(fp, 'hash_abc', 'hash_abc')
      expect(resolved).toBe(fp)
    })

    it('returns original fingerprint when stored payload hash is null', () => {
      const fp = 'base_fp'
      const resolved = resolveFingerprintCollision(fp, null, 'hash_abc')
      expect(resolved).toBe(fp)
    })

    it('returns salted fingerprint when stored payload hash differs (collision guard)', () => {
      const fp = 'base_fp'
      const resolved = resolveFingerprintCollision(fp, 'hash_abc', 'hash_xyz')
      expect(resolved).not.toBe(fp)
      expect(resolved).toMatch(/^[a-f0-9]{64}$/)
    })
  })

  describe('saveDeadLetter', () => {
    it('saves entry to webhook_dead_letters when under threshold', async () => {
      mockQuery.mockResolvedValue({ rowCount: 0, rows: [] } as any)
      const payload = { event: 'test' }
      const error = new Error('Some database failure')

      const result = await saveDeadLetter('razorpay', 'evt_123', payload, error)

      expect(result.status).toBe('saved')
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO webhook_dead_letters'),
        [
          'razorpay',
          'evt_123',
          computePayloadHash(payload),
          'Some database failure',
        ]
      )
    })

    it('handles non-Error throwables gracefully', async () => {
      mockQuery.mockResolvedValue({ rowCount: 0, rows: [] } as any)
      const result = await saveDeadLetter('razorpay', 'evt_123', { event: 'test' }, 'string error')

      expect(result.status).toBe('saved')
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO webhook_dead_letters'),
        [
          'razorpay',
          'evt_123',
          expect.any(String),
          'string error',
        ]
      )
    })

    it('quarantines malformed payload when threshold is reached', async () => {
      // Return 2 existing attempts so current + 1 = 3 >= threshold (3)
      mockQuery.mockImplementation(async (query: string) => {
        if (query.includes('webhook_dead_letters')) {
          if (query.startsWith('SELECT')) {
            return { rowCount: 1, rows: [{ attempt_count: 2 }] } as any
          }
        }
        return { rowCount: 0, rows: [] } as any
      })

      const payload = { event: 'test' }
      const error = new Error('Repeated poison pill')

      const result = await saveDeadLetter('razorpay', 'evt_123', payload, error, 3)

      expect(result.status).toBe('quarantined')
      expect(result.attemptCount).toBe(3)
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO webhook_quarantine'),
        expect.arrayContaining(['razorpay', 'evt_123'])
      )
    })

    it('handles fingerprint collision properly during save', async () => {
      mockQuery.mockImplementation(async (query: string) => {
        if (query.includes('webhook_failure_fingerprints')) {
          if (query.startsWith('SELECT') && !query.includes('WHERE fingerprint = $1 AND')) {
            // Simulate existing collision with a different payload_hash
            return { rowCount: 1, rows: [{ payload_hash: 'different_hash', failure_count: 5 }] } as any
          }
        }
        return { rowCount: 0, rows: [] } as any
      })

      const payload = { event: 'colliding_payload' }
      const result = await saveDeadLetter('razorpay', 'evt_456', payload, 'err_code', 10)

      expect(result.fingerprint).toBeDefined()
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO webhook_failure_fingerprints'),
        expect.any(Array)
      )
    })
  })

  describe('getDeadLetter', () => {
    it('returns null if entry is not found', async () => {
      mockQuery.mockResolvedValueOnce({ rowCount: 0, rows: [] } as any)
      const result = await getDeadLetter('razorpay', 'evt_123')
      expect(result).toBeNull()
    })

    it('returns entry details if found', async () => {
      const mockRow = { payload_hash: 'hash123', attempt_count: 1 }
      mockQuery.mockResolvedValueOnce({ rowCount: 1, rows: [mockRow] } as any)
      const result = await getDeadLetter('razorpay', 'evt_123')
      expect(result).toEqual(mockRow)
    })
  })

  describe('deleteDeadLetter', () => {
    it('executes DELETE query with correct parameters', async () => {
      mockQuery.mockResolvedValueOnce({ rowCount: 1, rows: [] } as any)
      await deleteDeadLetter('razorpay', 'evt_123')
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('DELETE FROM webhook_dead_letters'),
        ['razorpay', 'evt_123']
      )
    })
  })

  describe('scanOldestDlqEntryAge', () => {
    it('queries db using NOW() to handle clock skew and sets metric', async () => {
      mockQuery.mockResolvedValueOnce({
        rowCount: 2,
        rows: [
          { provider: 'razorpay', age_seconds: '120.5' },
          { provider: 'stripe', age_seconds: '30' }
        ]
      } as any)

      await scanOldestDlqEntryAge()

      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('EXTRACT(EPOCH FROM (NOW() - MIN(updated_at)))')
      )
      
      const values = await webhookDlqOldestEntryAge.get()
      const razorpayMetric = values.values.find((v) => v.labels.provider === 'razorpay')
      const stripeMetric = values.values.find((v) => v.labels.provider === 'stripe')
      
      expect(razorpayMetric?.value).toBe(120.5)
      expect(stripeMetric?.value).toBe(30)
    })

    it('handles empty results gracefully', async () => {
      mockQuery.mockResolvedValueOnce({ rowCount: 0, rows: [] } as any)
      await scanOldestDlqEntryAge()
      
      const values = await webhookDlqOldestEntryAge.get()
      expect(values.values).toHaveLength(0) // since it was reset
    })
  })

  describe('startDlqAgeScanner', () => {
    beforeEach(() => {
      vi.useFakeTimers()
    })
    afterEach(() => {
      vi.useRealTimers()
    })

    it('runs periodically and can be stopped', async () => {
      mockQuery.mockResolvedValue({ rowCount: 0, rows: [] } as any)
      const handle = startDlqAgeScanner(1000)
      
      // wait for initial run
      await Promise.resolve()
      
      expect(mockQuery).toHaveBeenCalledTimes(1) // initial run
      
      await vi.advanceTimersByTimeAsync(1000)
      expect(mockQuery).toHaveBeenCalledTimes(2) // interval run
      
      handle.stop()
      
      await vi.advanceTimersByTimeAsync(1000)
      expect(mockQuery).toHaveBeenCalledTimes(2) // stopped
    })
  })
  describe('Backpressure Manager', () => {
    beforeEach(() => {
      vi.useFakeTimers()
      // reset backpressure map for tests (hack by getting state and setting to default)
      const state = getBackpressureState('razorpay')
      state.tokens = 100
      state.pauseUntil = 0
    })
    
    afterEach(() => {
      vi.useRealTimers()
    })

    it('respects Retry-After seconds on 429', () => {
      updateRateLimitFromHeaders('razorpay', { 'Retry-After': '30' }, 429)
      const state = getBackpressureState('razorpay')
      expect(state.tokens).toBe(0)
      expect(state.pauseUntil).toBeGreaterThan(Date.now() + 29000)
    })

    it('respects Retry-After date on 429', () => {
      const futureDate = new Date(Date.now() + 50000).toUTCString()
      updateRateLimitFromHeaders('razorpay', { 'retry-after': futureDate }, 429)
      const state = getBackpressureState('razorpay')
      expect(state.tokens).toBe(0)
      expect(state.pauseUntil).toBeGreaterThan(Date.now() + 49000)
    })

    it('falls back to 60s pause on 429 without Retry-After', () => {
      updateRateLimitFromHeaders('razorpay', {}, 429)
      const state = getBackpressureState('razorpay')
      expect(state.tokens).toBe(0)
      expect(state.pauseUntil).toBeGreaterThan(Date.now() + 59000)
    })

    it('updates token count from rate-limit-remaining', () => {
      updateRateLimitFromHeaders('razorpay', { 'x-ratelimit-remaining': '50' }, 200)
      const state = getBackpressureState('razorpay')
      expect(state.tokens).toBe(50)
    })

    it('updates pauseUntil from x-ratelimit-reset when remaining is 0', () => {
      const resetTime = Math.floor(Date.now() / 1000) + 120
      updateRateLimitFromHeaders('razorpay', { 
        'x-ratelimit-remaining': '0',
        'x-ratelimit-reset': resetTime.toString()
      }, 200)
      const state = getBackpressureState('razorpay')
      expect(state.tokens).toBe(0)
      expect(state.pauseUntil).toBe(resetTime * 1000)
    })

    it('acquireReplayPermit consumes tokens', async () => {
      const state = getBackpressureState('razorpay')
      state.tokens = 5
      state.pauseUntil = 0
      
      let resolved = false
      acquireReplayPermit('razorpay').then(() => resolved = true)
      
      await Promise.resolve() // flush microtasks
      expect(resolved).toBe(true)
      expect(state.tokens).toBe(4)
    })

    it('acquireReplayPermit pauses when paused', async () => {
      const state = getBackpressureState('razorpay')
      state.tokens = 0
      state.pauseUntil = Date.now() + 5000
      
      let resolved = false
      const promise = acquireReplayPermit('razorpay').then(() => resolved = true)
      
      await Promise.resolve()
      expect(resolved).toBe(false)
      
      await vi.advanceTimersByTimeAsync(5000)
      expect(resolved).toBe(true)
      expect(state.tokens).toBe(0) // It replenished to 1 then consumed 1
    })
  })
})
