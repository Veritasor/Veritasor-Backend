/**
 * Redis-backed OAuth state storage tests.
 *
 * Tests the Redis implementation of OAuth state storage with mocked Redis client.
 * Verifies that state issued on one instance is consumable on another,
 * states expire correctly, and states are single-use.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import {
  setOAuthState,
  consumeOAuthState,
  resetStoresForTesting
} from '../../../../../src/services/integrations/stripe/store.js'

// Mock Redis client
const mockRedisClient = {
  set: vi.fn(),
  getdel: vi.fn(),
  eval: vi.fn(),
}

// Mock getRedisClient to return our mock
vi.mock('../../../../../src/redis.js', () => ({
  getRedisClient: () => mockRedisClient,
  resetRedisClient: vi.fn(),
}))

describe('Stripe OAuth state store (Redis)', () => {
  beforeEach(() => {
    resetStoresForTesting()
    vi.clearAllMocks()
    // Set Redis as configured
    process.env.REDIS_URL = 'redis://localhost:6379'
  })

  afterEach(() => {
    delete process.env.REDIS_URL
    delete process.env.REDIS_CLUSTER_NODES
    delete process.env.REDIS_MODE
  })

  describe('Redis setOAuthState', () => {
    it('stores state with TTL using SET PX', async () => {
      const state = 'a'.repeat(64)
      const expiresAt = Date.now() + 60000
      const ttlMs = expiresAt - Date.now()

      mockRedisClient.set.mockResolvedValue('OK')

      await setOAuthState(state, expiresAt)

      expect(mockRedisClient.set).toHaveBeenCalledWith(
        `oauth:state:${state}`,
        JSON.stringify({ expiresAt }),
        'PX',
        ttlMs
      )
    })

    it('throws error when expiresAt is in the past', async () => {
      const state = 'a'.repeat(64)
      const expiresAt = Date.now() - 1000

      await expect(setOAuthState(state, expiresAt)).rejects.toThrow('expiresAt must be in the future')
    })

    it('throws error when expiresAt is now', async () => {
      const state = 'a'.repeat(64)
      const expiresAt = Date.now()

      await expect(setOAuthState(state, expiresAt)).rejects.toThrow('expiresAt must be in the future')
    })
  })

  describe('Redis consumeOAuthState with GETDEL', () => {
    it('consumes state using GETDEL when available', async () => {
      const state = 'a'.repeat(64)
      const expiresAt = Date.now() + 60000
      const key = `oauth:state:${state}`

      mockRedisClient.getdel.mockResolvedValue(JSON.stringify({ expiresAt }))

      const result = await consumeOAuthState(state)

      expect(mockRedisClient.getdel).toHaveBeenCalledWith(key)
      expect(mockRedisClient.eval).not.toHaveBeenCalled()
      expect(result).toBe(true)
    })

    it('returns false when state does not exist', async () => {
      const state = 'a'.repeat(64)
      mockRedisClient.getdel.mockResolvedValue(null)

      const result = await consumeOAuthState(state)

      expect(result).toBe(false)
    })

    it('returns false when state has expired', async () => {
      const state = 'a'.repeat(64)
      const expiresAt = Date.now() - 1000
      mockRedisClient.getdel.mockResolvedValue(JSON.stringify({ expiresAt }))

      const result = await consumeOAuthState(state)

      expect(result).toBe(false)
    })

    it('falls back to Lua script when GETDEL fails', async () => {
      const state = 'a'.repeat(64)
      const expiresAt = Date.now() + 60000
      const key = `oauth:state:${state}`

      mockRedisClient.getdel.mockRejectedValue(new Error('GETDEL not supported'))
      mockRedisClient.eval.mockResolvedValue(JSON.stringify({ expiresAt }))

      const result = await consumeOAuthState(state)

      expect(mockRedisClient.eval).toHaveBeenCalledWith(
        expect.stringContaining('redis.call'),
        1,
        key
      )
      expect(result).toBe(true)
    })
  })

  describe('Redis Lua script fallback', () => {
    it('uses Lua script for atomic GET + DEL', async () => {
      const state = 'a'.repeat(64)
      const expiresAt = Date.now() + 60000
      const key = `oauth:state:${state}`

      mockRedisClient.getdel.mockRejectedValue(new Error('GETDEL not supported'))
      mockRedisClient.eval.mockResolvedValue(JSON.stringify({ expiresAt }))

      await consumeOAuthState(state)

      expect(mockRedisClient.eval).toHaveBeenCalledWith(
        expect.stringContaining('GET'),
        1,
        key
      )
      expect(mockRedisClient.eval).toHaveBeenCalledWith(
        expect.stringContaining('DEL'),
        1,
        key
      )
    })

    it('returns false when Lua script returns null', async () => {
      const state = 'a'.repeat(64)
      mockRedisClient.getdel.mockRejectedValue(new Error('GETDEL not supported'))
      mockRedisClient.eval.mockResolvedValue(null)

      const result = await consumeOAuthState(state)

      expect(result).toBe(false)
    })
  })

  describe('Multi-pod scenario simulation', () => {
    it('state issued on one instance is consumable on another', async () => {
      const state = 'a'.repeat(64)
      const expiresAt = Date.now() + 60000

      // Simulate setting state on "pod 1"
      mockRedisClient.set.mockResolvedValue('OK')
      await setOAuthState(state, expiresAt)

      // Clear mock to simulate consumption on "pod 2"
      mockRedisClient.set.mockClear()
      mockRedisClient.getdel.mockResolvedValue(JSON.stringify({ expiresAt }))

      // Consume on "pod 2"
      const result = await consumeOAuthState(state)

      expect(result).toBe(true)
    })

    it('consumed state cannot be consumed again', async () => {
      const state = 'a'.repeat(64)
      const expiresAt = Date.now() + 60000

      mockRedisClient.set.mockResolvedValue('OK')
      await setOAuthState(state, expiresAt)

      mockRedisClient.set.mockClear()
      mockRedisClient.getdel.mockResolvedValueOnce(JSON.stringify({ expiresAt }))
      mockRedisClient.getdel.mockResolvedValueOnce(null)

      const firstConsume = await consumeOAuthState(state)
      const secondConsume = await consumeOAuthState(state)

      expect(firstConsume).toBe(true)
      expect(secondConsume).toBe(false)
    })
  })

  describe('Fallback to in-memory when Redis not configured', () => {
    beforeEach(() => {
      delete process.env.REDIS_URL
      delete process.env.REDIS_CLUSTER_NODES
      delete process.env.REDIS_MODE
    })

    it('uses in-memory storage when Redis is not configured', async () => {
      const state = 'a'.repeat(64)
      const expiresAt = Date.now() + 60000

      await setOAuthState(state, expiresAt)

      // Redis should not be called
      expect(mockRedisClient.set).not.toHaveBeenCalled()

      // Should work with in-memory storage
      const result = await consumeOAuthState(state)
      expect(result).toBe(true)
    })
  })
})
