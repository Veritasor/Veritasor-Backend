import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

vi.mock('../../../../src/db/client.js', () => ({
  db: {
    query: vi.fn(),
  },
}))

import { db } from '../../../../src/db/client.js'
import {
  computePayloadHash,
  saveDeadLetter,
  getDeadLetter,
  deleteDeadLetter,
  scanOldestDlqEntryAge,
  startDlqAgeScanner,
  MAX_PAYLOAD_SIZE,
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

  describe('saveDeadLetter', () => {
    it('executes INSERT ... ON CONFLICT DO UPDATE with correct parameters', async () => {
      mockQuery.mockResolvedValueOnce({ rowCount: 1, rows: [] } as any)
      const payload = { event: 'test' }
      const error = new Error('Some database failure')
      
      await saveDeadLetter('razorpay', 'evt_123', payload, error)
      
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
      mockQuery.mockResolvedValueOnce({ rowCount: 1, rows: [] } as any)
      await saveDeadLetter('razorpay', 'evt_123', { event: 'test' }, 'string error')
      
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
  })

  describe('getDeadLetter', () => {
    it('returns null if entry is not found', async () => {
      mockQuery.mockResolvedValueOnce({ rowCount: 0, rows: [] } as any)
      const result = await getDeadLetter('razorpay', 'evt_123')
      expect(result).toBeNull()
    })

    it('returns entry details if found', async () => {
      const mockRow = { payload_hash: 'hash123' }
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
})
