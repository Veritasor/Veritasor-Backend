/**
 * Regression coverage for the Shopify OAuth state/token store.
 *
 * Focuses on the failure and empty-result branches (`return undefined;` /
 * early `return;`) so their behaviour stays observable and deterministic:
 * - `setOAuthState` rejects empty state, empty/invalid shop hosts, non-finite
 *   expiry, and already-past expiry, and must clear any prior entry for the
 *   same state key when the new write is rejected.
 * - `consumeOAuthState` returns `undefined` for unknown, replayed, and expired
 *   state, while still returning a valid record at the inclusive expiry boundary.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import {
  normalizeShop,
  isValidShopHost,
  setOAuthState,
  consumeOAuthState,
  saveToken,
  getToken,
  deleteToken,
  clearAll,
} from '../../../../../src/services/integrations/shopify/store.js'

const FIXED_NOW = new Date('2026-01-01T00:00:00.000Z')
const TEN_MINUTES_MS = 10 * 60 * 1000

describe('Shopify OAuth store', () => {
  beforeEach(() => {
    clearAll()
    vi.useFakeTimers()
    vi.setSystemTime(FIXED_NOW)
  })

  afterEach(() => {
    clearAll()
    vi.useRealTimers()
  })

  describe('normalizeShop', () => {
    it('appends the myshopify suffix when it is missing', () => {
      expect(normalizeShop('test-shop')).toBe('test-shop.myshopify.com')
    })

    it('keeps an existing suffix and does not duplicate it', () => {
      expect(normalizeShop('test-shop.myshopify.com')).toBe(
        'test-shop.myshopify.com',
      )
    })

    it('trims surrounding whitespace and lowercases the value', () => {
      expect(normalizeShop('  TEST-Shop  ')).toBe('test-shop.myshopify.com')
      expect(normalizeShop('  TEST-Shop.MyShopify.COM  ')).toBe(
        'test-shop.myshopify.com',
      )
    })

    it('returns an empty string for empty or whitespace-only input', () => {
      expect(normalizeShop('')).toBe('')
      expect(normalizeShop('   ')).toBe('')
    })
  })

  describe('isValidShopHost', () => {
    it('accepts well-formed myshopify hostnames', () => {
      expect(isValidShopHost('test-shop.myshopify.com')).toBe(true)
      expect(isValidShopHost('a.myshopify.com')).toBe(true)
      expect(isValidShopHost('my.store-name.myshopify.com')).toBe(true)
    })

    it('rejects hosts that are not a bare myshopify hostname', () => {
      expect(isValidShopHost('test-shop')).toBe(false)
      expect(isValidShopHost('.myshopify.com')).toBe(false)
      expect(isValidShopHost('-test.myshopify.com')).toBe(false)
      expect(isValidShopHost('test_shop.myshopify.com')).toBe(false)
      expect(isValidShopHost('test.example.com')).toBe(false)
      expect(isValidShopHost('test.myshopify.com.evil.com')).toBe(false)
    })
  })

  describe('setOAuthState rejection branches', () => {
    it('rejects an empty or whitespace-only state key', () => {
      const expiresAt = Date.now() + TEN_MINUTES_MS

      setOAuthState('', 'test-shop', 'user-1', 'biz-1', expiresAt)
      setOAuthState('   ', 'test-shop', 'user-1', 'biz-1', expiresAt)

      expect(consumeOAuthState('')).toBeUndefined()
      expect(consumeOAuthState('   ')).toBeUndefined()
    })

    it('rejects an empty or whitespace-only shop', () => {
      const expiresAt = Date.now() + TEN_MINUTES_MS
      const state = 'state-empty-shop'
      setOAuthState(state, '', 'user-1', 'biz-1', expiresAt)
      expect(consumeOAuthState(state)).toBeUndefined()

      setOAuthState(state, '   ', 'user-1', 'biz-1', expiresAt)
      expect(consumeOAuthState(state)).toBeUndefined()
    })

    it('rejects a shop that is not a valid myshopify host', () => {
      const expiresAt = Date.now() + TEN_MINUTES_MS
      const state = 'state-bad-shop'

      setOAuthState(state, '-leading-dash', 'user-1', 'biz-1', expiresAt)
      expect(consumeOAuthState(state)).toBeUndefined()

      setOAuthState(state, 'under_score', 'user-1', 'biz-1', expiresAt)
      expect(consumeOAuthState(state)).toBeUndefined()
    })

    it('rejects non-finite expiry values', () => {
      const state = 'state-non-finite'

      for (const expiresAt of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
        setOAuthState(state, 'test-shop', 'user-1', 'biz-1', expiresAt)
        expect(consumeOAuthState(state)).toBeUndefined()
      }
    })

    it('rejects expiry that is already in the past', () => {
      const state = 'state-past'
      setOAuthState(state, 'test-shop', 'user-1', 'biz-1', Date.now() - 1)
      expect(consumeOAuthState(state)).toBeUndefined()
    })

    it('clears a previously stored entry when the same state is re-set with a past expiry', () => {
      const state = 'state-invalidate'
      setOAuthState(state, 'test-shop', 'user-1', 'biz-1', Date.now() + TEN_MINUTES_MS)

      // Re-setting the same key with a past expiry must invalidate the old record.
      setOAuthState(state, 'test-shop', 'user-2', 'biz-2', Date.now() - 1)

      expect(consumeOAuthState(state)).toBeUndefined()
    })

    it('clears a previously stored entry when the same state is re-set with a non-finite expiry', () => {
      const state = 'state-invalidate-nan'
      setOAuthState(state, 'test-shop', 'user-1', 'biz-1', Date.now() + TEN_MINUTES_MS)

      setOAuthState(state, 'test-shop', 'user-2', 'biz-2', Number.NaN)

      expect(consumeOAuthState(state)).toBeUndefined()
    })
  })

  describe('setOAuthState acceptance branches', () => {
    it('stores a valid state and returns the normalized record', () => {
      const state = 'state-valid'
      const expiresAt = Date.now() + TEN_MINUTES_MS

      setOAuthState(state, 'TEST-Shop', 'user-1', 'biz-1', expiresAt)

      expect(consumeOAuthState(state)).toEqual({
        shop: 'test-shop.myshopify.com',
        userId: 'user-1',
        businessId: 'biz-1',
        expiresAt,
      })
    })

    it('accepts an expiry exactly 1ms in the future', () => {
      const state = 'state-boundary-accept'
      setOAuthState(state, 'test-shop', 'user-1', 'biz-1', Date.now() + 1)
      expect(consumeOAuthState(state)).toBeDefined()
    })

    it('trims the stored state key so lookup ignores surrounding whitespace', () => {
      const expiresAt = Date.now() + TEN_MINUTES_MS
      setOAuthState('  padded-state  ', 'test-shop', 'user-1', 'biz-1', expiresAt)

      expect(consumeOAuthState('padded-state')).toBeDefined()
    })
  })

  describe('consumeOAuthState failure handling', () => {
    it('returns undefined for an unknown state', () => {
      expect(consumeOAuthState('never-stored')).toBeUndefined()
    })

    it('returns a valid record once and then undefined on replay', () => {
      const state = 'state-single-use'
      const expiresAt = Date.now() + TEN_MINUTES_MS
      setOAuthState(state, 'test-shop', 'user-1', 'biz-1', expiresAt)

      expect(consumeOAuthState(state)).toBeDefined()
      expect(consumeOAuthState(state)).toBeUndefined()
    })

    it('returns undefined for an expired record and keeps it consumed', () => {
      const state = 'state-expired'
      const expiresAt = Date.now() + TEN_MINUTES_MS
      setOAuthState(state, 'test-shop', 'user-1', 'biz-1', expiresAt)

      vi.setSystemTime(expiresAt + 1)

      expect(consumeOAuthState(state)).toBeUndefined()
      expect(consumeOAuthState(state)).toBeUndefined()
    })

    it('returns the record at the inclusive expiry boundary', () => {
      const state = 'state-at-expiry'
      const expiresAt = Date.now() + TEN_MINUTES_MS
      setOAuthState(state, 'test-shop', 'user-1', 'biz-1', expiresAt)

      vi.setSystemTime(expiresAt)

      expect(consumeOAuthState(state)).toBeDefined()
    })

    it('trims the lookup key before matching', () => {
      const state = 'state-trim-lookup'
      setOAuthState(state, 'test-shop', 'user-1', 'biz-1', Date.now() + TEN_MINUTES_MS)

      expect(consumeOAuthState('  state-trim-lookup  ')).toBeDefined()
    })
  })

  describe('token storage', () => {
    it('stores and retrieves a token under the normalized shop key', () => {
      saveToken('  TEST-Shop  ', 'token-1')

      expect(getToken('test-shop')).toBe('token-1')
      expect(getToken('test-shop.myshopify.com')).toBe('token-1')
      expect(getToken('  TEST-Shop  ')).toBe('token-1')
    })

    it('returns undefined for an unknown shop', () => {
      expect(getToken('unknown-shop')).toBeUndefined()
    })

    it('overwrites the token for the same normalized shop', () => {
      saveToken('test-shop', 'token-1')
      saveToken('TEST-SHOP.myshopify.com', 'token-2')

      expect(getToken('test-shop')).toBe('token-2')
    })

    it('deleteToken returns true for an existing token and false otherwise', () => {
      saveToken('test-shop', 'token-1')

      expect(deleteToken('TEST-SHOP')).toBe(true)
      expect(getToken('test-shop')).toBeUndefined()
      expect(deleteToken('test-shop')).toBe(false)
    })
  })

  describe('clearAll', () => {
    it('clears both the state map and the token map', () => {
      const state = 'state-clear'
      setOAuthState(state, 'test-shop', 'user-1', 'biz-1', Date.now() + TEN_MINUTES_MS)
      saveToken('test-shop', 'token-1')

      clearAll()

      expect(consumeOAuthState(state)).toBeUndefined()
      expect(getToken('test-shop')).toBeUndefined()
      expect(deleteToken('test-shop')).toBe(false)
    })
  })
})
