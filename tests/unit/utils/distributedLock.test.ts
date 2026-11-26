/**
 * Distributed lock utility tests.
 *
 * Tests the Redis-based distributed lock implementation with mocked Redis client.
 * Verifies lock acquisition, release, and fallback behavior when Redis is unavailable.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'

describe('Distributed lock utility', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    // Set Redis as configured
    process.env.REDIS_URL = 'redis://localhost:6379'
  })

  afterEach(() => {
    delete process.env.REDIS_URL
    delete process.env.REDIS_CLUSTER_NODES
    delete process.env.REDIS_MODE
    vi.restoreAllMocks()
  })

  describe('acquireLock', () => {
    it('acquires lock when key does not exist', async () => {
      const { acquireLock } = await import('../../../../src/utils/distributedLock.js')
      const { getRedisClient } = await import('../../../../src/redis.js')

      const mockRedisClient = {
        set: vi.fn().mockResolvedValue('OK'),
      }
      vi.mocked(getRedisClient).mockReturnValue(mockRedisClient)

      const result = await acquireLock({ key: 'test-lock' })

      expect(result.acquired).toBe(true)
      expect(result.token).toBeDefined()
      expect(mockRedisClient.set).toHaveBeenCalledWith(
        'test-lock',
        result.token,
        'NX',
        'PX',
        30000 // default TTL
      )
    })

    it('fails to acquire lock when key already exists', async () => {
      const { acquireLock } = await import('../../../../src/utils/distributedLock.js')
      const { getRedisClient } = await import('../../../../src/redis.js')

      const mockRedisClient = {
        set: vi.fn().mockResolvedValue(null),
      }
      vi.mocked(getRedisClient).mockReturnValue(mockRedisClient)

      const result = await acquireLock({ key: 'test-lock' })

      expect(result.acquired).toBe(false)
      expect(mockRedisClient.set).toHaveBeenCalledWith(
        'test-lock',
        expect.any(String),
        'NX',
        'PX',
        30000
      )
    })

    it('uses custom TTL when provided', async () => {
      const { acquireLock } = await import('../../../../src/utils/distributedLock.js')
      const { getRedisClient } = await import('../../../../src/redis.js')

      const mockRedisClient = {
        set: vi.fn().mockResolvedValue('OK'),
      }
      vi.mocked(getRedisClient).mockReturnValue(mockRedisClient)

      const result = await acquireLock({ key: 'test-lock', ttlMs: 60000 })

      expect(result.acquired).toBe(true)
      expect(mockRedisClient.set).toHaveBeenCalledWith(
        'test-lock',
        result.token,
        'NX',
        'PX',
        60000
      )
    })

    it('uses custom token when provided', async () => {
      const { acquireLock } = await import('../../../../src/utils/distributedLock.js')
      const { getRedisClient } = await import('../../../../src/redis.js')

      const mockRedisClient = {
        set: vi.fn().mockResolvedValue('OK'),
      }
      vi.mocked(getRedisClient).mockReturnValue(mockRedisClient)
      const customToken = 'my-custom-token'

      const result = await acquireLock({ key: 'test-lock', token: customToken })

      expect(result.acquired).toBe(true)
      expect(result.token).toBe(customToken)
      expect(mockRedisClient.set).toHaveBeenCalledWith(
        'test-lock',
        customToken,
        'NX',
        'PX',
        30000
      )
    })

    it('generates unique token when not provided', async () => {
      const { acquireLock } = await import('../../../../src/utils/distributedLock.js')
      const { getRedisClient } = await import('../../../../src/redis.js')

      const mockRedisClient = {
        set: vi.fn().mockResolvedValue('OK'),
      }
      vi.mocked(getRedisClient).mockReturnValue(mockRedisClient)

      const result1 = await acquireLock({ key: 'test-lock' })
      const result2 = await acquireLock({ key: 'test-lock' })

      expect(result1.token).not.toBe(result2.token)
    })

    it('falls back to acquired=true when Redis is unavailable', async () => {
      delete process.env.REDIS_URL
      const { acquireLock } = await import('../../../../src/utils/distributedLock.js')

      const result = await acquireLock({ key: 'test-lock' })

      expect(result.acquired).toBe(true)
    })

    it('falls back to acquired=true when Redis throws error', async () => {
      const { acquireLock } = await import('../../../../src/utils/distributedLock.js')
      const { getRedisClient } = await import('../../../../src/redis.js')

      const mockRedisClient = {
        set: vi.fn().mockRejectedValue(new Error('Redis connection failed')),
      }
      vi.mocked(getRedisClient).mockReturnValue(mockRedisClient)

      const result = await acquireLock({ key: 'test-lock' })

      expect(result.acquired).toBe(true)
    })
  })

  describe('releaseLock', () => {
    it('releases lock when token matches', async () => {
      const { releaseLock } = await import('../../../../src/utils/distributedLock.js')
      const { getRedisClient } = await import('../../../../src/redis.js')

      const mockRedisClient = {
        eval: vi.fn().mockResolvedValue(1),
      }
      vi.mocked(getRedisClient).mockReturnValue(mockRedisClient)

      const result = await releaseLock('test-lock', 'my-token')

      expect(result).toBe(true)
      expect(mockRedisClient.eval).toHaveBeenCalledWith(
        expect.stringContaining('GET'),
        1,
        'test-lock',
        'my-token'
      )
    })

    it('fails to release lock when token does not match', async () => {
      const { releaseLock } = await import('../../../../src/utils/distributedLock.js')
      const { getRedisClient } = await import('../../../../src/redis.js')

      const mockRedisClient = {
        eval: vi.fn().mockResolvedValue(0),
      }
      vi.mocked(getRedisClient).mockReturnValue(mockRedisClient)

      const result = await releaseLock('test-lock', 'wrong-token')

      expect(result).toBe(false)
    })

    it('fails to release lock when key does not exist', async () => {
      const { releaseLock } = await import('../../../../src/utils/distributedLock.js')
      const { getRedisClient } = await import('../../../../src/redis.js')

      const mockRedisClient = {
        eval: vi.fn().mockResolvedValue(0),
      }
      vi.mocked(getRedisClient).mockReturnValue(mockRedisClient)

      const result = await releaseLock('test-lock', 'my-token')

      expect(result).toBe(false)
    })

    it('returns false when Redis throws error', async () => {
      const { releaseLock } = await import('../../../../src/utils/distributedLock.js')
      const { getRedisClient } = await import('../../../../src/redis.js')

      const mockRedisClient = {
        eval: vi.fn().mockRejectedValue(new Error('Redis error')),
      }
      vi.mocked(getRedisClient).mockReturnValue(mockRedisClient)

      const result = await releaseLock('test-lock', 'my-token')

      expect(result).toBe(false)
    })

    it('is no-op when Redis is not configured', async () => {
      delete process.env.REDIS_URL
      const { releaseLock } = await import('../../../../src/utils/distributedLock.js')

      const result = await releaseLock('test-lock', 'my-token')

      expect(result).toBe(true)
    })
  })

  describe('withLock', () => {
    it('executes function when lock is acquired', async () => {
      const { withLock } = await import('../../../../src/utils/distributedLock.js')
      const { getRedisClient } = await import('../../../../src/redis.js')

      const mockRedisClient = {
        set: vi.fn().mockResolvedValue('OK'),
        eval: vi.fn().mockResolvedValue(1),
      }
      vi.mocked(getRedisClient).mockReturnValue(mockRedisClient)

      const fn = vi.fn().mockResolvedValue('result')
      const result = await withLock({ key: 'test-lock' }, fn)

      expect(result).toBe('result')
      expect(fn).toHaveBeenCalledTimes(1)
      expect(mockRedisClient.set).toHaveBeenCalled()
      expect(mockRedisClient.eval).toHaveBeenCalled()
    })

    it('does not execute function when lock is not acquired', async () => {
      const { withLock } = await import('../../../../src/utils/distributedLock.js')
      const { getRedisClient } = await import('../../../../src/redis.js')

      const mockRedisClient = {
        set: vi.fn().mockResolvedValue(null),
      }
      vi.mocked(getRedisClient).mockReturnValue(mockRedisClient)

      const fn = vi.fn().mockResolvedValue('result')
      const result = await withLock({ key: 'test-lock' }, fn)

      expect(result).toBeUndefined()
      expect(fn).not.toHaveBeenCalled()
    })

    it('releases lock even when function throws', async () => {
      const { withLock } = await import('../../../../src/utils/distributedLock.js')
      const { getRedisClient } = await import('../../../../src/redis.js')

      const mockRedisClient = {
        set: vi.fn().mockResolvedValue('OK'),
        eval: vi.fn().mockResolvedValue(1),
      }
      vi.mocked(getRedisClient).mockReturnValue(mockRedisClient)

      const fn = vi.fn().mockRejectedValue(new Error('Function error'))
      await expect(withLock({ key: 'test-lock' }, fn)).rejects.toThrow('Function error')

      expect(fn).toHaveBeenCalledTimes(1)
      expect(mockRedisClient.eval).toHaveBeenCalled()
    })

    it('continues to release lock even if release fails', async () => {
      const { withLock } = await import('../../../../src/utils/distributedLock.js')
      const { getRedisClient } = await import('../../../../src/redis.js')

      const mockRedisClient = {
        set: vi.fn().mockResolvedValue('OK'),
        eval: vi.fn().mockRejectedValue(new Error('Release failed')),
      }
      vi.mocked(getRedisClient).mockReturnValue(mockRedisClient)

      const fn = vi.fn().mockResolvedValue('result')
      const result = await withLock({ key: 'test-lock' }, fn)

      expect(result).toBe('result')
      expect(fn).toHaveBeenCalledTimes(1)
      expect(mockRedisClient.eval).toHaveBeenCalled()
    })

    it('executes function without lock when Redis is not configured', async () => {
      delete process.env.REDIS_URL
      const { withLock } = await import('../../../../src/utils/distributedLock.js')

      const fn = vi.fn().mockResolvedValue('result')
      const result = await withLock({ key: 'test-lock' }, fn)

      expect(result).toBe('result')
      expect(fn).toHaveBeenCalledTimes(1)
    })
  })

  describe('Multi-pod scenario simulation', () => {
    it('only one instance acquires lock', async () => {
      const { acquireLock } = await import('../../../../src/utils/distributedLock.js')
      const { getRedisClient } = await import('../../../../src/redis.js')

      const mockRedisClient = {
        set: vi.fn(),
      }
      vi.mocked(getRedisClient).mockReturnValue(mockRedisClient)

      // First instance acquires lock
      mockRedisClient.set.mockResolvedValueOnce('OK')
      const result1 = await acquireLock({ key: 'test-lock' })
      expect(result1.acquired).toBe(true)

      // Second instance fails to acquire
      mockRedisClient.set.mockResolvedValueOnce(null)
      const result2 = await acquireLock({ key: 'test-lock' })
      expect(result2.acquired).toBe(false)
    })

    it('lock is released on completion', async () => {
      const { withLock } = await import('../../../../src/utils/distributedLock.js')
      const { getRedisClient } = await import('../../../../src/redis.js')

      const mockRedisClient = {
        set: vi.fn().mockResolvedValue('OK'),
        eval: vi.fn().mockResolvedValue(1),
      }
      vi.mocked(getRedisClient).mockReturnValue(mockRedisClient)

      const fn = vi.fn().mockResolvedValue('result')
      await withLock({ key: 'test-lock' }, fn)

      expect(mockRedisClient.eval).toHaveBeenCalledWith(
        expect.stringContaining('DEL'),
        1,
        'test-lock',
        expect.any(String)
      )
    })

    it('lock expires on crash (TTL set on acquisition)', async () => {
      const { acquireLock } = await import('../../../../src/utils/distributedLock.js')
      const { getRedisClient } = await import('../../../../src/redis.js')

      const mockRedisClient = {
        set: vi.fn().mockResolvedValue('OK'),
      }
      vi.mocked(getRedisClient).mockReturnValue(mockRedisClient)

      const result = await acquireLock({ key: 'test-lock', ttlMs: 60000 })

      expect(result.acquired).toBe(true)
      expect(mockRedisClient.set).toHaveBeenCalledWith(
        'test-lock',
        result.token,
        'NX',
        'PX',
        60000
      )
    })
  })
})
