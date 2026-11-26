import { describe, it, expect, beforeEach } from 'vitest'
import {
  upsertStripeIntegration,
  getStripeIntegration,
  setOAuthState,
  consumeOAuthState,
  resetStoresForTesting
} from '../../../../../src/services/integrations/stripe/store'

describe('Stripe Integration Store', () => {
  const mockIntegration = {
    stripeUserId: 'acct_123',
    accessToken: 'sk_test_456',
    businessId: 'biz_789'
  }

  beforeEach(() => {
    resetStoresForTesting()
  })

  it('should create a new integration record', () => {
    const result = upsertStripeIntegration(mockIntegration)
    expect(result.stripeUserId).toBe(mockIntegration.stripeUserId)
    expect(result.createdAt).toBeDefined()
    expect(result.updatedAt).toBe(result.createdAt)
  })

  it('should perform an idempotent upsert (update existing)', async () => {
    const first = upsertStripeIntegration(mockIntegration)

    // Wait slightly to ensure timestamp difference
    await new Promise(resolve => setTimeout(resolve, 10))

    const updatedData = { ...mockIntegration, accessToken: 'sk_test_new' }
    const second = upsertStripeIntegration(updatedData)

    expect(second.stripeUserId).toBe(first.stripeUserId)
    expect(second.accessToken).toBe('sk_test_new')
    expect(second.createdAt).toBe(first.createdAt) // Should NOT change
    expect(second.updatedAt).toBeGreaterThan(first.updatedAt) // Should change
  })

  it('should retrieve a stored integration', () => {
    upsertStripeIntegration(mockIntegration)
    const retrieved = getStripeIntegration(mockIntegration.stripeUserId)
    expect(retrieved).toBeDefined()
    expect(retrieved?.accessToken).toBe(mockIntegration.accessToken)
  })

  describe('OAuth state store (in-memory fallback)', () => {
    it('should store and consume a valid OAuth state', async () => {
      const state = 'a'.repeat(64)
      const expiresAt = Date.now() + 60000

      await setOAuthState(state, expiresAt)
      const result = await consumeOAuthState(state)

      expect(result).toBe(true)
    })

    it('should reject an unknown state', async () => {
      const result = await consumeOAuthState('unknown-state')
      expect(result).toBe(false)
    })

    it('should reject an expired state', async () => {
      const state = 'b'.repeat(64)
      const expiresAt = Date.now() - 1000 // Expired 1 second ago

      await setOAuthState(state, expiresAt)
      const result = await consumeOAuthState(state)

      expect(result).toBe(false)
    })

    it('should reject a consumed state (one-time use)', async () => {
      const state = 'c'.repeat(64)
      const expiresAt = Date.now() + 60000

      await setOAuthState(state, expiresAt)
      const firstConsume = await consumeOAuthState(state)
      const secondConsume = await consumeOAuthState(state)

      expect(firstConsume).toBe(true)
      expect(secondConsume).toBe(false)
    })

    it('should handle concurrent consumption correctly', async () => {
      const state = 'd'.repeat(64)
      const expiresAt = Date.now() + 60000

      await setOAuthState(state, expiresAt)

      // Try to consume from multiple "concurrent" calls
      const results = await Promise.all([
        consumeOAuthState(state),
        consumeOAuthState(state),
        consumeOAuthState(state),
      ])

      // Only one should succeed
      const successCount = results.filter(r => r === true).length
      expect(successCount).toBe(1)
    })
  })
})
