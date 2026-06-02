/**
 * Tests for Shopify OAuth connect flow with TTL configuration.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { startConnect } from './connect.js'
import * as store from './store.js'

describe('Shopify OAuth Connect', () => {
  const originalEnv = process.env

  beforeEach(() => {
    vi.resetModules()
    process.env = { ...originalEnv }
    process.env.SHOPIFY_CLIENT_ID = 'test-client-id'
    process.env.SHOPIFY_REDIRECT_URI = 'https://api.example.com/callback'
    process.env.SHOPIFY_SCOPES = 'read_orders,write_orders'
    store.clearAll()
    vi.useFakeTimers()
  })

  afterEach(() => {
    process.env = originalEnv
    vi.useRealTimers()
  })

  describe('startConnect', () => {
    it('should generate redirect URL with correct parameters', () => {
      const result = startConnect('test-shop', 'user-1', 'business-1')

      expect(result.redirectUrl).toContain('https://test-shop.myshopify.com/admin/oauth/authorize')
      expect(result.redirectUrl).toContain('client_id=test-client-id')
      expect(result.redirectUrl).toContain('scope=read_orders%2Cwrite_orders')
      expect(result.redirectUrl).toContain('redirect_uri=https%3A%2F%2Fapi.example.com%2Fcallback')
      expect(result.redirectUrl).toContain('state=')
      expect(result.state).toHaveLength(32) // 16 bytes hex = 32 chars
    })

    it('should store state with default TTL of 10 minutes', () => {
      const now = Date.now()
      vi.setSystemTime(now)

      const result = startConnect('test-shop', 'user-1', 'business-1')

      const stateRecord = store.consumeOAuthState(result.state)
      expect(stateRecord).toBeDefined()
      expect(stateRecord?.expiresAt).toBe(now + 10 * 60 * 1000)
    })

    it('should use custom TTL from SHOPIFY_OAUTH_STATE_TTL_MS', () => {
      const now = Date.now()
      vi.setSystemTime(now)
      process.env.SHOPIFY_OAUTH_STATE_TTL_MS = '300000' // 5 minutes

      const result = startConnect('test-shop', 'user-1', 'business-1')

      const stateRecord = store.consumeOAuthState(result.state)
      expect(stateRecord).toBeDefined()
      expect(stateRecord?.expiresAt).toBe(now + 300000)
    })

    it('should normalize shop hostname', () => {
      const result = startConnect('TEST-SHOP', 'user-1', 'business-1')

      expect(result.redirectUrl).toContain('https://test-shop.myshopify.com')
      
      const stateRecord = store.consumeOAuthState(result.state)
      expect(stateRecord?.shop).toBe('test-shop.myshopify.com')
    })

    it('should generate unique state for each call', () => {
      const result1 = startConnect('test-shop', 'user-1', 'business-1')
      const result2 = startConnect('test-shop', 'user-1', 'business-1')

      expect(result1.state).not.toBe(result2.state)
    })

    it('should throw error if SHOPIFY_CLIENT_ID is missing', () => {
      delete process.env.SHOPIFY_CLIENT_ID

      expect(() => startConnect('test-shop', 'user-1', 'business-1')).toThrow(
        'Missing SHOPIFY_CLIENT_ID, SHOPIFY_REDIRECT_URI, or invalid shop'
      )
    })

    it('should throw error if SHOPIFY_REDIRECT_URI is missing', () => {
      delete process.env.SHOPIFY_REDIRECT_URI

      expect(() => startConnect('test-shop', 'user-1', 'business-1')).toThrow(
        'Missing SHOPIFY_CLIENT_ID, SHOPIFY_REDIRECT_URI, or invalid shop'
      )
    })

    it('should throw error for invalid shop hostname', () => {
      expect(() => startConnect('-invalid.myshopify.com', 'user-1', 'business-1')).toThrow(
        'Missing SHOPIFY_CLIENT_ID, SHOPIFY_REDIRECT_URI, or invalid shop'
      )
    })

    it('should use default scopes if SHOPIFY_SCOPES is not set', () => {
      delete process.env.SHOPIFY_SCOPES

      const result = startConnect('test-shop', 'user-1', 'business-1')

      expect(result.redirectUrl).toContain('scope=read_orders')
    })

    it('should store userId and businessId correctly', () => {
      const result = startConnect('test-shop', 'user-123', 'business-456')

      const stateRecord = store.consumeOAuthState(result.state)
      expect(stateRecord?.userId).toBe('user-123')
      expect(stateRecord?.businessId).toBe('business-456')
    })

    it('should handle very short TTL', () => {
      const now = Date.now()
      vi.setSystemTime(now)
      process.env.SHOPIFY_OAUTH_STATE_TTL_MS = '1000' // 1 second

      const result = startConnect('test-shop', 'user-1', 'business-1')

      const stateRecord = store.consumeOAuthState(result.state)
      expect(stateRecord?.expiresAt).toBe(now + 1000)
    })

    it('should handle very long TTL', () => {
      const now = Date.now()
      vi.setSystemTime(now)
      process.env.SHOPIFY_OAUTH_STATE_TTL_MS = '3600000' // 1 hour

      const result = startConnect('test-shop', 'user-1', 'business-1')

      const stateRecord = store.consumeOAuthState(result.state)
      expect(stateRecord?.expiresAt).toBe(now + 3600000)
    })
  })
})
