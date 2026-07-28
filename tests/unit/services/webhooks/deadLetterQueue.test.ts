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
  resolveIntegrationShard,
  saveDeadLetter,
  getDeadLetter,
  deleteDeadLetter,
  getDeadLettersByShard,
  listDeadLetterShards,
  DLQShardWorker,
  createDLQShardWorker,
  isQuarantined,
  getQuarantinedLetter,
  listQuarantinedLetters,
  releaseQuarantinedLetter,
  purgeQuarantinedLetter,
  getFingerprintCount,
  MAX_PAYLOAD_SIZE,
  DEFAULT_QUARANTINE_THRESHOLD,
  UNKNOWN_INTEGRATION_SHARD,
} from '../../../../src/services/webhooks/deadLetterQueue.js'

describe('deadLetterQueue', () => {
  const mockQuery = vi.mocked(db.query)

  beforeEach(() => {
    mockQuery.mockReset()
  })

  describe('resolveIntegrationShard', () => {
    it('returns normalized integration when integration string is provided', () => {
      expect(resolveIntegrationShard('razorpay', 'Shopify-Store')).toBe('shopify-store')
    })

    it('falls back to provider when integration is not provided', () => {
      expect(resolveIntegrationShard('RazorPay')).toBe('razorpay')
    })

    it('falls back to unknown integration shard when provider and integration are missing or empty', () => {
      expect(resolveIntegrationShard('', '')).toBe(UNKNOWN_INTEGRATION_SHARD)
      expect(resolveIntegrationShard(undefined, undefined)).toBe(UNKNOWN_INTEGRATION_SHARD)
    })
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
    it('saves entry to webhook_dead_letters with integration shard when under threshold', async () => {
      mockQuery.mockResolvedValue({ rowCount: 0, rows: [] } as any)
      const payload = { event: 'test' }
      const error = new Error('Some database failure')

      const result = await saveDeadLetter('razorpay', 'evt_123', payload, error, DEFAULT_QUARANTINE_THRESHOLD, 'custom_integration')

      expect(result.status).toBe('saved')
      expect(result.integration).toBe('custom_integration')
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO webhook_dead_letters'),
        [
          'razorpay',
          'custom_integration',
          'evt_123',
          computePayloadHash(payload),
          'Some database failure',
        ]
      )
    })

    it('falls back to provider as shard when integration is omitted', async () => {
      mockQuery.mockResolvedValue({ rowCount: 0, rows: [] } as any)
      const payload = { event: 'test' }
      const error = new Error('Some database failure')

      const result = await saveDeadLetter('razorpay', 'evt_123', payload, error)

      expect(result.status).toBe('saved')
      expect(result.integration).toBe('razorpay')
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO webhook_dead_letters'),
        [
          'razorpay',
          'razorpay',
          'evt_123',
          computePayloadHash(payload),
          'Some database failure',
        ]
      )
    })

    it('falls back to unknown integration shard when provider is empty', async () => {
      mockQuery.mockResolvedValue({ rowCount: 0, rows: [] } as any)
      const payload = { event: 'test' }
      const error = new Error('Some database failure')

      const result = await saveDeadLetter('', 'evt_123', payload, error)

      expect(result.status).toBe('saved')
      expect(result.integration).toBe(UNKNOWN_INTEGRATION_SHARD)
    })

    it('handles non-Error throwables gracefully', async () => {
      mockQuery.mockResolvedValue({ rowCount: 0, rows: [] } as any)
      const result = await saveDeadLetter('razorpay', 'evt_123', { event: 'test' }, 'string error')

      expect(result.status).toBe('saved')
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO webhook_dead_letters'),
        [
          'razorpay',
          'razorpay',
          'evt_123',
          expect.any(String),
          'string error',
        ]
      )
    })

    it('quarantines malformed payload with shard when threshold is reached', async () => {
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

      const result = await saveDeadLetter('razorpay', 'evt_123', payload, error, 3, 'razorpay_shard')

      expect(result.status).toBe('quarantined')
      expect(result.attemptCount).toBe(3)
      expect(result.integration).toBe('razorpay_shard')
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO webhook_quarantine'),
        expect.arrayContaining(['razorpay', 'razorpay_shard', 'evt_123'])
      )
    })

    it('handles fingerprint collision properly during save', async () => {
      mockQuery.mockImplementation(async (query: string) => {
        if (query.includes('webhook_failure_fingerprints')) {
          if (query.startsWith('SELECT') && !query.includes('WHERE fingerprint = $1 AND')) {
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
      const mockRow = { provider: 'razorpay', integration: 'razorpay', event_id: 'evt_123', payload_hash: 'hash123', attempt_count: 1 }
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

  describe('Sharding & Worker functions', () => {
    it('getDeadLettersByShard queries dead letters by integration shard', async () => {
      const mockRows = [{ provider: 'razorpay', integration: 'razorpay', event_id: 'evt_1' }]
      mockQuery.mockResolvedValueOnce({ rowCount: 1, rows: mockRows } as any)

      const entries = await getDeadLettersByShard('razorpay', 10)
      expect(entries).toEqual(mockRows)
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('WHERE integration = $1'),
        ['razorpay', 10]
      )
    })

    it('listDeadLetterShards returns aggregated shard stats', async () => {
      const mockShards = [{ integration: 'razorpay', count: 5 }, { integration: 'unknown', count: 2 }]
      mockQuery.mockResolvedValueOnce({ rowCount: 2, rows: mockShards } as any)

      const shards = await listDeadLetterShards()
      expect(shards).toEqual(mockShards)
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('GROUP BY integration')
      )
    })

    it('DLQShardWorker processes shard entries independently and deletes succeeded entries', async () => {
      const mockEntries = [
        { provider: 'razorpay', integration: 'razorpay', event_id: 'evt_success', payload_hash: 'h1', error_code: 'e1', attempt_count: 1 },
        { provider: 'razorpay', integration: 'razorpay', event_id: 'evt_fail', payload_hash: 'h2', error_code: 'e2', attempt_count: 1 },
      ]

      mockQuery.mockImplementation(async (query: string, params?: any[]) => {
        if (query.includes('WHERE integration = $1')) {
          return { rowCount: 2, rows: mockEntries } as any
        }
        return { rowCount: 1, rows: [] } as any
      })

      const handler = vi.fn().mockImplementation(async (entry) => {
        return entry.event_id === 'evt_success'
      })

      const worker = createDLQShardWorker('razorpay', handler)
      expect(worker.integration).toBe('razorpay')

      const res = await worker.processBatch()

      expect(res.processed).toBe(2)
      expect(res.succeeded).toBe(1)
      expect(res.failed).toBe(1)
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('DELETE FROM webhook_dead_letters WHERE provider = $1 AND event_id = $2'),
        ['razorpay', 'evt_success']
      )
    })

    it('DLQShardWorker handles unknown integration fallback shard', async () => {
      const mockEntries = [
        { provider: 'unknown', integration: 'unknown', event_id: 'evt_unk', payload_hash: 'h1', error_code: 'e1', attempt_count: 1 },
      ]
      mockQuery.mockImplementation(async (query: string) => {
        if (query.includes('WHERE integration = $1')) {
          return { rowCount: 1, rows: mockEntries } as any
        }
        return { rowCount: 1, rows: [] } as any
      })

      const handler = vi.fn().mockResolvedValue(true)
      const worker = new DLQShardWorker('', handler)
      expect(worker.integration).toBe(UNKNOWN_INTEGRATION_SHARD)

      const res = await worker.processBatch()
      expect(res.processed).toBe(1)
      expect(res.succeeded).toBe(1)
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
      const mockQuarantineItem = { provider: 'razorpay', integration: 'razorpay', event_id: 'evt_123', fingerprint: 'fp123' }
      mockQuery.mockResolvedValueOnce({ rowCount: 1, rows: [mockQuarantineItem] } as any)
      const res = await getQuarantinedLetter('razorpay', 'evt_123')
      expect(res).toEqual(mockQuarantineItem)
    })

    it('listQuarantinedLetters queries with or without provider or integration filter', async () => {
      mockQuery.mockResolvedValue({ rowCount: 1, rows: [{ id: 1 }] } as any)
      
      const all = await listQuarantinedLetters()
      expect(all).toHaveLength(1)

      const filteredProvider = await listQuarantinedLetters('razorpay')
      expect(filteredProvider).toHaveLength(1)

      const filteredIntegration = await listQuarantinedLetters(undefined, 'razorpay_integration')
      expect(filteredIntegration).toHaveLength(1)
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('WHERE integration = $1'),
        ['razorpay_integration']
      )
    })

    it('releaseQuarantinedLetter releases and deletes fingerprint entry', async () => {
      const mockQuarantineItem = { provider: 'razorpay', integration: 'razorpay', event_id: 'evt_123', fingerprint: 'fp123' }
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
