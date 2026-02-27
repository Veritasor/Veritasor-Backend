import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { startConnect } from '../../../../../src/services/integrations/stripe/connect'
import * as store from '../../../../../src/services/integrations/stripe/store'

describe('Stripe OAuth Connect Service', () => {
  const originalEnv = process.env

  beforeEach(() => {
    vi.useFakeTimers()
    process.env = {
      ...originalEnv,
      STRIPE_CLIENT_ID: 'test_client_id',
      STRIPE_REDIRECT_URI: 'http://localhost:3000/api/integrations/stripe/callback',
      STRIPE_SCOPES: 'read_write'
    }
  })

  afterEach(() => {
    vi.useRealTimers()
    process.env = originalEnv
  })

  describe('startConnect', () => {
    it('generates state token and stores it with expiration', () => {
      const setOAuthStateSpy = vi.spyOn(store, 'setOAuthState')
      const now = Date.now()
      vi.setSystemTime(now)

      const result = startConnect()

      expect(result.state).toBeDefined()
      expect(result.state.length).toBeGreaterThan(0)
      expect(setOAuthStateSpy).toHaveBeenCalledWith(
        result.state,
        now + 10 * 60 * 1000 // 10 minutes expiration
      )
    })

    it('constructs authorization URL with all required parameters', () => {
      const result = startConnect()

      const url = new URL(result.redirectUrl)
      expect(url.origin).toBe('https://connect.stripe.com')
      expect(url.pathname).toBe('/oauth/authorize')

      const params = url.searchParams
      expect(params.get('client_id')).toBe('test_client_id')
      expect(params.get('redirect_uri')).toBe('http://localhost:3000/api/integrations/stripe/callback')
      expect(params.get('state')).toBe(result.state)
      expect(params.get('scope')).toBe('read_write')
      expect(params.get('response_type')).toBe('code')
    })

    it('uses default scope when STRIPE_SCOPES not configured', () => {
      delete process.env.STRIPE_SCOPES

      const result = startConnect()

      const url = new URL(result.redirectUrl)
      expect(url.searchParams.get('scope')).toBe('read_write')
    })

    it('uses custom scope when STRIPE_SCOPES is configured', () => {
      process.env.STRIPE_SCOPES = 'read_only'

      const result = startConnect()

      const url = new URL(result.redirectUrl)
      expect(url.searchParams.get('scope')).toBe('read_only')
    })

    it('generates unique state tokens on each call', () => {
      const result1 = startConnect()
      const result2 = startConnect()

      expect(result1.state).not.toBe(result2.state)
    })

    it('generates state token with sufficient entropy (at least 16 bytes)', () => {
      const result = startConnect()

      // State is hex-encoded, so 16 bytes = 32 hex characters
      expect(result.state.length).toBeGreaterThanOrEqual(32)
    })
  })
})
