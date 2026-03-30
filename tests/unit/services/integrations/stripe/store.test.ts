import { describe, it, expect, beforeEach } from 'vitest'
import { upsertStripeIntegration, getStripeIntegration } from '../../../../../src/services/integrations/stripe/store'

describe('Stripe Integration Store', () => {
  const mockIntegration = {
    stripeUserId: 'acct_123',
    accessToken: 'sk_test_456',
    businessId: 'biz_789'
  }

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
})
