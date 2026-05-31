/**
 * Tests for Shopify OAuth state store with TTL and single-use semantics.
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import * as store from './store.js'

describe('Shopify OAuth Store', () => {
  beforeEach(() => {
    store.clearAll()
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  describe('normalizeShop', () => {
    it('should normalize shop without .myshopify.com suffix', () => {
      expect(store.normalizeShop('test-shop')).toBe('test-shop.myshopify.com')
    })

    it('should normalize shop with .myshopify.com suffix', () => {
      expect(store.normalizeShop('test-shop.myshopify.com')).toBe('test-shop.myshopify.com')
    })

    it('should trim and lowercase shop names', () => {
      expect(store.normalizeShop('  TEST-SHOP  ')).toBe('test-shop.myshopify.com')
    })

    it('should return empty string for empty input', () => {
      expect(store.normalizeShop('')).toBe('')
      expect(store.normalizeShop('   ')).toBe('')
    })
  })

  describe('isValidShopHost', () => {
    it('should accept valid shop hostnames', () => {
      expect(store.isValidShopHost('test-shop.myshopify.com')).toBe(true)
      expect(store.isValidShopHost('my-store.myshopify.com')).toBe(true)
      expect(store.isValidShopHost('a.myshopify.com')).toBe(true)
    })

    it('should reject invalid shop hostnames', () => {
      expect(store.isValidShopHost('test-shop')).toBe(false)
      expect(store.isValidShopHost('.myshopify.com')).toBe(false)
      expect(store.isValidShopHost('-test.myshopify.com')).toBe(false)
      expect(store.isValidShopHost('test.example.com')).toBe(false)
    })
  })

  describe('OAuth State Management', () => {
    describe('setOAuthState and consumeOAuthState', () => {
      it('should store and retrieve valid state', () => {
        const state = 'test-state-123'
        const shop = 'test-shop'
        const userId = 'user-1'
        const businessId = 'business-1'
        const expiresAt = Date.now() + 10 * 60 * 1000

        store.setOAuthState(state, shop, userId, businessId, expiresAt)
        const result = store.consumeOAuthState(state)

        expect(result).toEqual({
          shop: 'test-shop.myshopify.com',
          userId,
          businessId,
          expiresAt,
        })
      })

      it('should normalize shop when storing state', () => {
        const state = 'test-state-123'
        const expiresAt = Date.now() + 10 * 60 * 1000

        store.setOAuthState(state, 'TEST-SHOP', 'user-1', 'business-1', expiresAt)
        const result = store.consumeOAuthState(state)

        expect(result?.shop).toBe('test-shop.myshopify.com')
      })

      it('should return undefined for unknown state', () => {
        const result = store.consumeOAuthState('unknown-state')
        expect(result).toBeUndefined()
      })

      it('should enforce single-use: second consume returns undefined', () => {
        const state = 'test-state-123'
        const expiresAt = Date.now() + 10 * 60 * 1000

        store.setOAuthState(state, 'test-shop', 'user-1', 'business-1', expiresAt)
        
        // First consume succeeds
        const first = store.consumeOAuthState(state)
        expect(first).toBeDefined()

        // Second consume fails (state already deleted)
        const second = store.consumeOAuthState(state)
        expect(second).toBeUndefined()
      })

      it('should reject expired state', () => {
        const state = 'test-state-123'
        const expiresAt = Date.now() + 10 * 60 * 1000

        store.setOAuthState(state, 'test-shop', 'user-1', 'business-1', expiresAt)

        // Advance time past expiry
        vi.advanceTimersByTime(11 * 60 * 1000)

        const result = store.consumeOAuthState(state)
        expect(result).toBeUndefined()
      })

      it('should delete expired state even if not consumed', () => {
        const state = 'test-state-123'
        const expiresAt = Date.now() + 10 * 60 * 1000

        store.setOAuthState(state, 'test-shop', 'user-1', 'business-1', expiresAt)

        // Advance time past expiry
        vi.advanceTimersByTime(11 * 60 * 1000)

        // First consume deletes the state
        const first = store.consumeOAuthState(state)
        expect(first).toBeUndefined()

        // Second consume also returns undefined
        const second = store.consumeOAuthState(state)
        expect(second).toBeUndefined()
      })

      it('should accept state consumed exactly at expiry time', () => {
        const state = 'test-state-123'
        const expiresAt = Date.now() + 10 * 60 * 1000

        store.setOAuthState(state, 'test-shop', 'user-1', 'business-1', expiresAt)

        // Advance time to exactly expiry time
        vi.advanceTimersByTime(10 * 60 * 1000)

        const result = store.consumeOAuthState(state)
        expect(result).toBeDefined()
      })

      it('should reject state consumed 1ms after expiry', () => {
        const state = 'test-state-123'
        const expiresAt = Date.now() + 10 * 60 * 1000

        store.setOAuthState(state, 'test-shop', 'user-1', 'business-1', expiresAt)

        // Advance time 1ms past expiry
        vi.advanceTimersByTime(10 * 60 * 1000 + 1)

        const result = store.consumeOAuthState(state)
        expect(result).toBeUndefined()
      })
    })

    describe('Concurrent consume race conditions', () => {
      it('should handle concurrent consume attempts (only first succeeds)', async () => {
        const state = 'test-state-123'
        const expiresAt = Date.now() + 10 * 60 * 1000

        store.setOAuthState(state, 'test-shop', 'user-1', 'business-1', expiresAt)

        // Simulate concurrent consume attempts
        const results = await Promise.all([
          Promise.resolve(store.consumeOAuthState(state)),
          Promise.resolve(store.consumeOAuthState(state)),
          Promise.resolve(store.consumeOAuthState(state)),
        ])

        // Only one should succeed
        const successful = results.filter((r) => r !== undefined)
        expect(successful).toHaveLength(1)
        expect(successful[0]).toEqual({
          shop: 'test-shop.myshopify.com',
          userId: 'user-1',
          businessId: 'business-1',
          expiresAt,
        })
      })
    })

    describe('Multiple states', () => {
      it('should handle multiple independent states', () => {
        const expiresAt = Date.now() + 10 * 60 * 1000

        store.setOAuthState('state-1', 'shop-1', 'user-1', 'business-1', expiresAt)
        store.setOAuthState('state-2', 'shop-2', 'user-2', 'business-2', expiresAt)

        const result1 = store.consumeOAuthState('state-1')
        const result2 = store.consumeOAuthState('state-2')

        expect(result1?.shop).toBe('shop-1.myshopify.com')
        expect(result2?.shop).toBe('shop-2.myshopify.com')
      })

      it('should not affect other states when one is consumed', () => {
        const expiresAt = Date.now() + 10 * 60 * 1000

        store.setOAuthState('state-1', 'shop-1', 'user-1', 'business-1', expiresAt)
        store.setOAuthState('state-2', 'shop-2', 'user-2', 'business-2', expiresAt)

        // Consume first state
        store.consumeOAuthState('state-1')

        // Second state should still be valid
        const result2 = store.consumeOAuthState('state-2')
        expect(result2).toBeDefined()
        expect(result2?.shop).toBe('shop-2.myshopify.com')
      })
    })
  })

  describe('Token Management', () => {
    describe('saveToken and getToken', () => {
      it('should store and retrieve tokens', () => {
        const shop = 'test-shop'
        const token = 'test-access-token'

        store.saveToken(shop, token)
        const retrieved = store.getToken(shop)

        expect(retrieved).toBe(token)
      })

      it('should normalize shop when storing tokens', () => {
        store.saveToken('TEST-SHOP', 'token-1')
        
        expect(store.getToken('test-shop')).toBe('token-1')
        expect(store.getToken('test-shop.myshopify.com')).toBe('token-1')
      })

      it('should return undefined for unknown shop', () => {
        const result = store.getToken('unknown-shop')
        expect(result).toBeUndefined()
      })

      it('should overwrite existing token for same shop', () => {
        const shop = 'test-shop'

        store.saveToken(shop, 'token-1')
        store.saveToken(shop, 'token-2')

        expect(store.getToken(shop)).toBe('token-2')
      })
    })

    describe('deleteToken', () => {
      it('should delete existing token', () => {
        const shop = 'test-shop'
        store.saveToken(shop, 'test-token')

        const deleted = store.deleteToken(shop)
        expect(deleted).toBe(true)
        expect(store.getToken(shop)).toBeUndefined()
      })

      it('should return false for non-existent token', () => {
        const deleted = store.deleteToken('unknown-shop')
        expect(deleted).toBe(false)
      })

      it('should normalize shop when deleting', () => {
        store.saveToken('test-shop', 'test-token')

        const deleted = store.deleteToken('TEST-SHOP.myshopify.com')
        expect(deleted).toBe(true)
        expect(store.getToken('test-shop')).toBeUndefined()
      })
    })
  })

  describe('clearAll', () => {
    it('should clear all states and tokens', () => {
      const expiresAt = Date.now() + 10 * 60 * 1000

      store.setOAuthState('state-1', 'shop-1', 'user-1', 'business-1', expiresAt)
      store.saveToken('shop-1', 'token-1')

      store.clearAll()

      expect(store.consumeOAuthState('state-1')).toBeUndefined()
      expect(store.getToken('shop-1')).toBeUndefined()
    })
  })
})
