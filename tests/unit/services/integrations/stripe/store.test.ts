import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import { setOAuthState, consumeOAuthState } from '../../../../../src/services/integrations/stripe/store'

describe('Stripe OAuth State Store', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  describe('setOAuthState', () => {
    it('stores state token with expiration', () => {
      const state = 'test-state-token'
      const expiresAt = Date.now() + 10 * 60 * 1000 // 10 minutes from now

      setOAuthState(state, expiresAt)

      // Verify by consuming it
      const result = consumeOAuthState(state)
      expect(result).toBe(true)
    })
  })

  describe('consumeOAuthState', () => {
    it('returns true for valid non-expired token', () => {
      const state = 'valid-token'
      const expiresAt = Date.now() + 10 * 60 * 1000

      setOAuthState(state, expiresAt)
      const result = consumeOAuthState(state)

      expect(result).toBe(true)
    })

    it('returns false for non-existent token', () => {
      const result = consumeOAuthState('non-existent-token')
      expect(result).toBe(false)
    })

    it('returns false for expired token', () => {
      const state = 'expired-token'
      const now = Date.now()
      const expiresAt = now + 10 * 60 * 1000

      setOAuthState(state, expiresAt)

      // Advance time by 11 minutes
      vi.advanceTimersByTime(11 * 60 * 1000)

      const result = consumeOAuthState(state)
      expect(result).toBe(false)
    })

    it('removes token after consumption (one-time use)', () => {
      const state = 'one-time-token'
      const expiresAt = Date.now() + 10 * 60 * 1000

      setOAuthState(state, expiresAt)

      // First consumption should succeed
      const firstResult = consumeOAuthState(state)
      expect(firstResult).toBe(true)

      // Second consumption should fail
      const secondResult = consumeOAuthState(state)
      expect(secondResult).toBe(false)
    })
  })

  describe('automatic cleanup', () => {
    it('removes expired tokens after cleanup interval', () => {
      const state1 = 'token-1'
      const state2 = 'token-2'
      const now = Date.now()

      // Token 1 expires in 3 minutes
      setOAuthState(state1, now + 3 * 60 * 1000)
      // Token 2 expires in 10 minutes
      setOAuthState(state2, now + 10 * 60 * 1000)

      // Advance time by 5 minutes (cleanup interval)
      vi.advanceTimersByTime(5 * 60 * 1000)

      // Token 1 should be cleaned up (expired)
      const result1 = consumeOAuthState(state1)
      expect(result1).toBe(false)

      // Token 2 should still be valid
      const result2 = consumeOAuthState(state2)
      expect(result2).toBe(true)
    })
  })
})
