import { describe, it, expect, vi, beforeEach } from 'vitest'

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
  isQuarantined,
  getQuarantinedLetter,
  listQuarantinedLetters,
  releaseQuarantinedLetter,
  purgeQuarantinedLetter,
  getFingerprintCount,
  MAX_PAYLOAD_SIZE,
  DEFAULT_QUARANTINE_THRESHOLD,
} from '../../../../src/services/webhooks/deadLetterQueue.js'

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

  describe('quarantine helper functions', () => {
    it('isQuarantined returns true when entry exists in quarantine', async () => {
      mockQuery.mockResolvedValueOnce({ rowCount: 1, rows: [{ 1: 1 }] } as any)
      const res = await isQuarantined('razorpay', 'evt_123')
      expect(res).toBe(true)
    })

    it('isQuarantined returns false when entry is not in quarantine', async () => {
      mockQuery.mockResolvedValueOnce({ rowCount: 0, rows: [] } as any)
      const res = await isQuarantined('razorpay', 'evt_123')
      expect(res).toBe(false)
    })

    it('getQuarantinedLetter returns item if found', async () => {
      const mockQuarantineItem = { provider: 'razorpay', event_id: 'evt_123', fingerprint: 'fp123' }
      mockQuery.mockResolvedValueOnce({ rowCount: 1, rows: [mockQuarantineItem] } as any)
      const res = await getQuarantinedLetter('razorpay', 'evt_123')
      expect(res).toEqual(mockQuarantineItem)
    })

    it('listQuarantinedLetters queries with or without provider filter', async () => {
      mockQuery.mockResolvedValue({ rowCount: 1, rows: [{ id: 1 }] } as any)
      
      const all = await listQuarantinedLetters()
      expect(all).toHaveLength(1)

      const filtered = await listQuarantinedLetters('razorpay')
      expect(filtered).toHaveLength(1)
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('WHERE provider = $1'),
        ['razorpay']
      )
    })

    it('releaseQuarantinedLetter releases and deletes fingerprint entry', async () => {
      const mockQuarantineItem = { provider: 'razorpay', event_id: 'evt_123', fingerprint: 'fp123' }
      mockQuery.mockImplementation(async (query: string) => {
        if (query.includes('webhook_quarantine') && query.startsWith('SELECT')) {
          return { rowCount: 1, rows: [mockQuarantineItem] } as any
        }
        return { rowCount: 1, rows: [] } as any
      })

      const success = await releaseQuarantinedLetter('razorpay', 'evt_123', 'admin_1')
      expect(success).toBe(true)
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('DELETE FROM webhook_quarantine'),
        ['razorpay', 'evt_123']
      )
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('DELETE FROM webhook_failure_fingerprints'),
        ['fp123']
      )
    })

    it('releaseQuarantinedLetter returns false if entry not found', async () => {
      mockQuery.mockResolvedValueOnce({ rowCount: 0, rows: [] } as any)
      const success = await releaseQuarantinedLetter('razorpay', 'evt_999')
      expect(success).toBe(false)
    })

    it('purgeQuarantinedLetter removes entry permanently', async () => {
      mockQuery.mockResolvedValueOnce({ rowCount: 1, rows: [] } as any)
      const purged = await purgeQuarantinedLetter('razorpay', 'evt_123')
      expect(purged).toBe(true)
    })

    it('getFingerprintCount returns failure count', async () => {
      mockQuery.mockResolvedValueOnce({ rowCount: 1, rows: [{ failure_count: 5 }] } as any)
      const count = await getFingerprintCount('fp123')
      expect(count).toBe(5)
    })
  })
})
