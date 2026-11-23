import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { handleCallback } from './callback.js'
import * as store from './store.js'
import * as integrationRepository from '../../../repositories/integration.js'

describe('Stripe OAuth callback', () => {
  const originalEnv = process.env
  let mockFetch: ReturnType<typeof vi.fn>

  beforeEach(() => {
    process.env = { ...originalEnv }
    process.env.STRIPE_CLIENT_ID = 'test-client-id'
    process.env.STRIPE_CLIENT_SECRET = 'test-client-secret'
    store.resetStoresForTesting()
    integrationRepository.clearAll()
    mockFetch = vi.fn()
    vi.stubGlobal('fetch', mockFetch)
  })

  afterEach(() => {
    process.env = originalEnv
    vi.unstubAllGlobals()
  })

  it('loads the Stripe router', async () => {
    const routerModule = await import('../../../routes/integrations-stripe.js')

    expect(routerModule.integrationsStripeRouter).toBeDefined()
  })

  it('creates an integration and updates it on a repeated Stripe account callback', async () => {
    mockFetch
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ access_token: 'first-token', stripe_user_id: 'acct-123' }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ access_token: 'updated-token', stripe_user_id: 'acct-123' }),
      })

    const firstState = 'a'.repeat(64)
    store.setOAuthState(firstState, Date.now() + 60_000)
    const firstResult = await handleCallback(
      { code: 'first-code', state: firstState },
      'user-1',
      'business-1',
    )

    expect(firstResult.success).toBe(true)
    const createdIntegrations = await integrationRepository.listByBusinessId('business-1')
    expect(createdIntegrations).toHaveLength(1)
    expect(createdIntegrations[0].token.accessToken).toBe('first-token')

    const secondState = 'b'.repeat(64)
    store.setOAuthState(secondState, Date.now() + 60_000)
    const secondResult = await handleCallback(
      { code: 'second-code', state: secondState },
      'user-1',
      'business-1',
    )

    expect(secondResult.success).toBe(true)
    const updatedIntegrations = await integrationRepository.listByBusinessId('business-1')
    expect(updatedIntegrations).toHaveLength(1)
    expect(updatedIntegrations[0].id).toBe(createdIntegrations[0].id)
    expect(updatedIntegrations[0].token.accessToken).toBe('updated-token')
    expect(mockFetch).toHaveBeenCalledTimes(2)
  })
})
