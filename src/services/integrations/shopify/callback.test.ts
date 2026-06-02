/**
 * Tests for Shopify OAuth callback with TTL and single-use state validation.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { handleCallback, type CallbackParams } from './callback.js'
import * as store from './store.js'
import * as integrationRepository from '../../../repositories/integration.js'
import * as utils from './utils.js'

// Mock dependencies
vi.mock('../../../repositories/integration.js')
vi.mock('../../../utils/logger.js', () => ({
  logger: {
    warn: vi.fn(),
    error: vi.fn(),
    info: vi.fn(),
  },
}))
vi.mock('./utils.js', () => ({
  computeShopifyHmac: vi.fn(),
}))

describe('Shopify OAuth Callback', () => {
  const originalEnv = process.env
  const mockFetch = vi.fn()

  beforeEach(() => {
    vi.resetModules()
    process.env = { ...originalEnv }
    process.env.SHOPIFY_CLIENT_ID = 'test-client-id'
    process.env.SHOPIFY_CLIENT_SECRET = 'test-client-secret'
    store.clearAll()
    vi.useFakeTimers()
    global.fetch = mockFetch
    vi.clearAllMocks()
    
    // Mock HMAC validation to always return the provided hmac
    vi.mocked(utils.computeShopifyHmac).mockImplementation((secret, params) => params.hmac || 'valid-hmac')
  })

  afterEach(() => {
    process.env = originalEnv
    vi.useRealTimers()
  })

  const createValidParams = (state: string, shop: string): CallbackParams => ({
    code: 'test-code-123',
    shop,
    state,
    hmac: 'valid-hmac',
  })

  describe('State validation', () => {
    it('should reject unknown state', async () => {
      const params = createValidParams('unknown-state', 'test-shop.myshopify.com')

      const result = await handleCallback(params)

      expect(result.success).toBe(false)
      expect(result.error).toBe('Invalid or expired state')
    })

    it('should reject expired state', async () => {
      const now = Date.now()
      vi.setSystemTime(now)

      const state = 'test-state-123'
      const expiresAt = now + 10 * 60 * 1000
      store.setOAuthState(state, 'test-shop', 'user-1', 'business-1', expiresAt)

      // Advance time past expiry
      vi.advanceTimersByTime(11 * 60 * 1000)

      const params = createValidParams(state, 'test-shop.myshopify.com')
      const result = await handleCallback(params)

      expect(result.success).toBe(false)
      expect(result.error).toBe('Invalid or expired state')
    })

    it('should reject replayed state (second use)', async () => {
      const now = Date.now()
      vi.setSystemTime(now)

      const state = 'test-state-123'
      const expiresAt = now + 10 * 60 * 1000
      store.setOAuthState(state, 'test-shop', 'user-1', 'business-1', expiresAt)

      // Mock successful token exchange
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ access_token: 'test-token' }),
      })

      // Mock integration repository
      vi.mocked(integrationRepository.listByUserId).mockResolvedValue([])
      vi.mocked(integrationRepository.create).mockResolvedValue({
        id: 'integration-1',
        userId: 'user-1',
        businessId: 'business-1',
        provider: 'shopify',
        externalId: 'test-shop.myshopify.com',
        token: { accessToken: 'test-token' },
        metadata: { shop: 'test-shop.myshopify.com' },
        createdAt: new Date(),
        updatedAt: new Date(),
      })

      const params = createValidParams(state, 'test-shop.myshopify.com')

      // First callback should succeed
      const result1 = await handleCallback(params)
      expect(result1.success).toBe(true)

      // Second callback with same state should fail (state consumed)
      const result2 = await handleCallback(params)
      expect(result2.success).toBe(false)
      expect(result2.error).toBe('Invalid or expired state')
    })

    it('should reject state with mismatched shop', async () => {
      const now = Date.now()
      vi.setSystemTime(now)

      const state = 'test-state-123'
      const expiresAt = now + 10 * 60 * 1000
      store.setOAuthState(state, 'shop-a', 'user-1', 'business-1', expiresAt)

      const params = createValidParams(state, 'shop-b.myshopify.com')
      const result = await handleCallback(params)

      expect(result.success).toBe(false)
      expect(result.error).toBe('Invalid or expired state')
    })

    it('should accept valid state within TTL', async () => {
      const now = Date.now()
      vi.setSystemTime(now)

      const state = 'test-state-123'
      const expiresAt = now + 10 * 60 * 1000
      store.setOAuthState(state, 'test-shop', 'user-1', 'business-1', expiresAt)

      // Advance time but stay within TTL
      vi.advanceTimersByTime(5 * 60 * 1000)

      // Mock successful token exchange
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ access_token: 'test-token' }),
      })

      vi.mocked(integrationRepository.listByUserId).mockResolvedValue([])
      vi.mocked(integrationRepository.create).mockResolvedValue({
        id: 'integration-1',
        userId: 'user-1',
        businessId: 'business-1',
        provider: 'shopify',
        externalId: 'test-shop.myshopify.com',
        token: { accessToken: 'test-token' },
        metadata: { shop: 'test-shop.myshopify.com' },
        createdAt: new Date(),
        updatedAt: new Date(),
      })

      const params = createValidParams(state, 'test-shop.myshopify.com')
      const result = await handleCallback(params)

      expect(result.success).toBe(true)
    })

    it('should accept state consumed exactly at expiry time', async () => {
      const now = Date.now()
      vi.setSystemTime(now)

      const state = 'test-state-123'
      const expiresAt = now + 10 * 60 * 1000
      store.setOAuthState(state, 'test-shop', 'user-1', 'business-1', expiresAt)

      // Advance time to exactly expiry time
      vi.advanceTimersByTime(10 * 60 * 1000)

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ access_token: 'test-token' }),
      })

      vi.mocked(integrationRepository.listByUserId).mockResolvedValue([])
      vi.mocked(integrationRepository.create).mockResolvedValue({
        id: 'integration-1',
        userId: 'user-1',
        businessId: 'business-1',
        provider: 'shopify',
        externalId: 'test-shop.myshopify.com',
        token: { accessToken: 'test-token' },
        metadata: { shop: 'test-shop.myshopify.com' },
        createdAt: new Date(),
        updatedAt: new Date(),
      })

      const params = createValidParams(state, 'test-shop.myshopify.com')
      const result = await handleCallback(params)

      expect(result.success).toBe(true)
    })

    it('should reject state consumed 1ms after expiry', async () => {
      const now = Date.now()
      vi.setSystemTime(now)

      const state = 'test-state-123'
      const expiresAt = now + 10 * 60 * 1000
      store.setOAuthState(state, 'test-shop', 'user-1', 'business-1', expiresAt)

      // Advance time 1ms past expiry
      vi.advanceTimersByTime(10 * 60 * 1000 + 1)

      const params = createValidParams(state, 'test-shop.myshopify.com')
      const result = await handleCallback(params)

      expect(result.success).toBe(false)
      expect(result.error).toBe('Invalid or expired state')
    })
  })

  describe('Parameter validation', () => {
    it('should reject missing code', async () => {
      const params = { shop: 'test-shop.myshopify.com', state: 'test-state', hmac: 'test-hmac' } as CallbackParams

      const result = await handleCallback(params)

      expect(result.success).toBe(false)
      expect(result.error).toBe('Missing required callback parameters')
    })

    it('should reject missing shop', async () => {
      const params = { code: 'test-code', state: 'test-state', hmac: 'test-hmac' } as CallbackParams

      const result = await handleCallback(params)

      expect(result.success).toBe(false)
      expect(result.error).toBe('Missing required callback parameters')
    })

    it('should reject missing state', async () => {
      const params = { code: 'test-code', shop: 'test-shop.myshopify.com', hmac: 'test-hmac' } as CallbackParams

      const result = await handleCallback(params)

      expect(result.success).toBe(false)
      expect(result.error).toBe('Missing required callback parameters')
    })

    it('should reject missing hmac', async () => {
      const params = { code: 'test-code', shop: 'test-shop.myshopify.com', state: 'test-state' } as CallbackParams

      const result = await handleCallback(params)

      expect(result.success).toBe(false)
      expect(result.error).toBe('Missing HMAC signature')
    })

    it('should reject invalid shop hostname', async () => {
      const now = Date.now()
      vi.setSystemTime(now)

      const state = 'test-state-123'
      const expiresAt = now + 10 * 60 * 1000
      // Store state with a valid shop, but callback will receive invalid shop
      store.setOAuthState(state, 'valid-shop', 'user-1', 'business-1', expiresAt)

      // Use a shop that will fail validation: starts with hyphen after normalization
      const params = createValidParams(state, '-invalid.myshopify.com')

      const result = await handleCallback(params)

      expect(result.success).toBe(false)
      expect(result.error).toBe('Invalid shop hostname')
    })
  })

  describe('Concurrent callback attempts', () => {
    it('should handle concurrent callbacks with same state (only first succeeds)', async () => {
      const now = Date.now()
      vi.setSystemTime(now)

      const state = 'test-state-123'
      const expiresAt = now + 10 * 60 * 1000
      store.setOAuthState(state, 'test-shop', 'user-1', 'business-1', expiresAt)

      // Mock successful token exchange
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({ access_token: 'test-token' }),
      })

      vi.mocked(integrationRepository.listByUserId).mockResolvedValue([])
      vi.mocked(integrationRepository.create).mockResolvedValue({
        id: 'integration-1',
        userId: 'user-1',
        businessId: 'business-1',
        provider: 'shopify',
        externalId: 'test-shop.myshopify.com',
        token: { accessToken: 'test-token' },
        metadata: { shop: 'test-shop.myshopify.com' },
        createdAt: new Date(),
        updatedAt: new Date(),
      })

      const params = createValidParams(state, 'test-shop.myshopify.com')

      // Simulate concurrent callbacks
      const results = await Promise.all([
        handleCallback(params),
        handleCallback(params),
        handleCallback(params),
      ])

      // Only one should succeed
      const successful = results.filter((r) => r.success)
      const failed = results.filter((r) => !r.success)

      expect(successful).toHaveLength(1)
      expect(failed).toHaveLength(2)
      expect(failed.every((r) => r.error === 'Invalid or expired state')).toBe(true)
    })
  })

  describe('Edge cases', () => {
    it('should handle state that expires during callback processing', async () => {
      const now = Date.now()
      vi.setSystemTime(now)

      const state = 'test-state-123'
      const expiresAt = now + 100 // Very short TTL
      store.setOAuthState(state, 'test-shop', 'user-1', 'business-1', expiresAt)

      // Advance time to expire state before callback completes
      vi.advanceTimersByTime(101)

      const params = createValidParams(state, 'test-shop.myshopify.com')
      const result = await handleCallback(params)

      expect(result.success).toBe(false)
      expect(result.error).toBe('Invalid or expired state')
    })

    it('should normalize shop hostname when validating state', async () => {
      const now = Date.now()
      vi.setSystemTime(now)

      const state = 'test-state-123'
      const expiresAt = now + 10 * 60 * 1000
      store.setOAuthState(state, 'TEST-SHOP', 'user-1', 'business-1', expiresAt)

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ access_token: 'test-token' }),
      })

      vi.mocked(integrationRepository.listByUserId).mockResolvedValue([])
      vi.mocked(integrationRepository.create).mockResolvedValue({
        id: 'integration-1',
        userId: 'user-1',
        businessId: 'business-1',
        provider: 'shopify',
        externalId: 'test-shop.myshopify.com',
        token: { accessToken: 'test-token' },
        metadata: { shop: 'test-shop.myshopify.com' },
        createdAt: new Date(),
        updatedAt: new Date(),
      })

      const params = createValidParams(state, 'test-shop.myshopify.com')
      const result = await handleCallback(params)

      expect(result.success).toBe(true)
    })
  })
})
