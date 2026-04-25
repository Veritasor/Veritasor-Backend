/**
 * Unit tests for Stripe OAuth callback service
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import {
  handleCallback,
  isValidStripeOAuthState
} from '../../../../../src/services/integrations/stripe/callback.js'
import * as store from '../../../../../src/services/integrations/stripe/store.js'
import * as IntegrationRepository from '../../../../../src/repositories/integration.js'

// Mock dependencies
vi.mock('../../../../../src/services/integrations/stripe/store.js')
vi.mock('../../../../../src/repositories/integration.js')

describe('Stripe OAuth Callback Service', () => {
  const mockUserId = 'user-123'
  const mockCode = 'auth-code-xyz'
  const mockState = 'a'.repeat(64)
  const mockStripeUserId = 'acct_stripe123'
  
  beforeEach(() => {
    // Reset all mocks before each test
    vi.clearAllMocks()
    
    // Set up environment variables
    process.env.STRIPE_CLIENT_ID = 'test-client-id'
    process.env.STRIPE_CLIENT_SECRET = 'test-client-secret'
    
    // Mock global fetch
    global.fetch = vi.fn()

    vi.mocked(IntegrationRepository.listByUserId).mockResolvedValue([])
    vi.mocked(IntegrationRepository.update).mockResolvedValue(null)
  })
  
  afterEach(() => {
    vi.restoreAllMocks()
  })
  
  describe('Parameter Validation', () => {
    it('should return error when code is missing', async () => {
      const result = await handleCallback(
        { code: '', state: mockState },
        mockUserId
      )
      
      expect(result.success).toBe(false)
      expect(result.error).toBe('Missing code, or state')
    })
    
    it('should return error when state is missing', async () => {
      const result = await handleCallback(
        { code: mockCode, state: '' },
        mockUserId
      )
      
      expect(result.success).toBe(false)
      expect(result.error).toBe('Missing code, or state')
    })
    
    it('should return error when both code and state are missing', async () => {
      const result = await handleCallback(
        { code: '', state: '' },
        mockUserId
      )
      
      expect(result.success).toBe(false)
      expect(result.error).toBe('Missing code, or state')
    })
  })
  
  describe('State Token Validation', () => {
    it('accepts only 64-char lowercase hex state values', () => {
      expect(isValidStripeOAuthState('a'.repeat(64))).toBe(true)
      expect(isValidStripeOAuthState('A'.repeat(64))).toBe(false)
      expect(isValidStripeOAuthState('a'.repeat(63))).toBe(false)
      expect(isValidStripeOAuthState('z'.repeat(64))).toBe(false)
      expect(isValidStripeOAuthState('a'.repeat(64) + ' ')).toBe(false)
    })

    it('should return error when state token format is malformed', async () => {
      const result = await handleCallback(
        { code: mockCode, state: 'not-hex' },
        mockUserId
      )

      expect(result.success).toBe(false)
      expect(result.error).toBe('Invalid OAuth state format')
      expect(store.consumeOAuthState).not.toHaveBeenCalled()
      expect(global.fetch).not.toHaveBeenCalled()
    })

    it('should return error when state token is invalid', async () => {
      vi.mocked(store.consumeOAuthState).mockReturnValue(false)
      
      const result = await handleCallback(
        { code: mockCode, state: mockState },
        mockUserId
      )
      
      expect(result.success).toBe(false)
      expect(result.error).toBe('Invalid or expired state')
      expect(store.consumeOAuthState).toHaveBeenCalledWith(mockState)
    })
    
    it('should return error when state token has expired', async () => {
      vi.mocked(store.consumeOAuthState).mockReturnValue(false)
      
      const result = await handleCallback(
        { code: mockCode, state: 'b'.repeat(64) },
        mockUserId
      )
      
      expect(result.success).toBe(false)
      expect(result.error).toBe('Invalid or expired state')
    })
  })
  
  describe('Token Exchange', () => {
    beforeEach(() => {
      vi.mocked(store.consumeOAuthState).mockReturnValue(true)
    })
    
    it('should return error when network request fails', async () => {
      vi.mocked(global.fetch).mockRejectedValue(new Error('Network error'))
      
      const result = await handleCallback(
        { code: mockCode, state: mockState },
        mockUserId
      )
      
      expect(result.success).toBe(false)
      expect(result.error).toBe('Failed to reach Stripe API')
    })
    
    it('should return error when Stripe API returns error response', async () => {
      vi.mocked(global.fetch).mockResolvedValue({
        ok: false,
        status: 400,
        json: async () => ({ error: 'invalid_grant' })
      } as Response)
      
      const result = await handleCallback(
        { code: mockCode, state: mockState },
        mockUserId
      )
      
      expect(result.success).toBe(false)
      expect(result.error).toBe('Token exchange failed')
    })
    
    it('should return error when response is missing access token', async () => {
      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
        json: async () => ({
          stripe_user_id: mockStripeUserId,
          scope: 'read_write',
          token_type: 'bearer'
        })
      } as Response)
      
      const result = await handleCallback(
        { code: mockCode, state: mockState },
        mockUserId
      )
      
      expect(result.success).toBe(false)
      expect(result.error).toBe('No access token in response')
    })

    it('should return error when Stripe response is missing stripe_user_id', async () => {
      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
        json: async () => ({
          access_token: 'sk_test_token123',
          scope: 'read_write',
          token_type: 'bearer'
        })
      } as Response)

      const result = await handleCallback(
        { code: mockCode, state: mockState },
        mockUserId
      )

      expect(result.success).toBe(false)
      expect(result.error).toBe('No Stripe account ID in response')
      expect(IntegrationRepository.create).not.toHaveBeenCalled()
      expect(IntegrationRepository.update).not.toHaveBeenCalled()
    })
    
    it('should make correct token exchange request to Stripe', async () => {
      const mockAccessToken = 'sk_test_token123'
      
      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
        json: async () => ({
          access_token: mockAccessToken,
          stripe_user_id: mockStripeUserId,
          scope: 'read_write',
          token_type: 'bearer'
        })
      } as Response)
      
      vi.mocked(IntegrationRepository.create).mockResolvedValue({
        id: 'integration-123',
        userId: mockUserId,
        provider: 'stripe',
        externalId: mockStripeUserId,
        token: {
          accessToken: mockAccessToken,
          scope: 'read_write',
          tokenType: 'bearer'
        },
        metadata: {},
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      })
      
      await handleCallback(
        { code: mockCode, state: mockState },
        mockUserId
      )
      
      expect(global.fetch).toHaveBeenCalledWith(
        'https://connect.stripe.com/oauth/token',
        expect.objectContaining({
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
          }
        })
      )
      
      // Verify request body contains required fields
      const fetchCall = vi.mocked(global.fetch).mock.calls[0]
      const requestBody = fetchCall[1]?.body as string
      expect(requestBody).toContain('grant_type=authorization_code')
      expect(requestBody).toContain(`code=${mockCode}`)
      expect(requestBody).toContain('client_id=test-client-id')
      expect(requestBody).toContain('client_secret=test-client-secret')
    })
  })
  
  describe('Successful Token Exchange', () => {
    beforeEach(() => {
      vi.mocked(store.consumeOAuthState).mockReturnValue(true)
    })
    
    it('should create integration record with correct data', async () => {
      const mockAccessToken = 'sk_test_token123'
      const mockRefreshToken = 'rt_test_refresh456'
      
      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
        json: async () => ({
          access_token: mockAccessToken,
          refresh_token: mockRefreshToken,
          stripe_user_id: mockStripeUserId,
          scope: 'read_write',
          token_type: 'bearer'
        })
      } as Response)
      
      vi.mocked(IntegrationRepository.create).mockResolvedValue({
        id: 'integration-123',
        userId: mockUserId,
        provider: 'stripe',
        externalId: mockStripeUserId,
        token: {
          accessToken: mockAccessToken,
          refreshToken: mockRefreshToken,
          scope: 'read_write',
          tokenType: 'bearer'
        },
        metadata: {},
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      })
      
      const result = await handleCallback(
        { code: mockCode, state: mockState },
        mockUserId
      )
      
      expect(IntegrationRepository.create).toHaveBeenCalledWith({
        userId: mockUserId,
        provider: 'stripe',
        externalId: mockStripeUserId,
        token: {
          accessToken: mockAccessToken,
          refreshToken: mockRefreshToken,
          scope: 'read_write',
          tokenType: 'bearer'
        },
        metadata: {}
      })
      
      expect(result.success).toBe(true)
      expect(result.stripeAccountId).toBe(mockStripeUserId)
    })

    it('should reprocess idempotently by updating an existing Stripe integration', async () => {
      const mockAccessToken = 'sk_test_token_updated'
      const mockRefreshToken = 'rt_test_refresh_updated'
      const existingIntegration = {
        id: 'integration-existing',
        userId: mockUserId,
        provider: 'stripe',
        externalId: mockStripeUserId,
        token: {
          accessToken: 'sk_test_token_old',
          refreshToken: 'rt_test_refresh_old',
          scope: 'read_only',
          tokenType: 'bearer'
        },
        metadata: {},
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      }

      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
        json: async () => ({
          access_token: mockAccessToken,
          refresh_token: mockRefreshToken,
          stripe_user_id: mockStripeUserId,
          scope: 'read_write',
          token_type: 'bearer'
        })
      } as Response)

      vi.mocked(IntegrationRepository.listByUserId).mockResolvedValue([existingIntegration])
      vi.mocked(IntegrationRepository.update).mockResolvedValue({
        ...existingIntegration,
        token: {
          accessToken: mockAccessToken,
          refreshToken: mockRefreshToken,
          scope: 'read_write',
          tokenType: 'bearer'
        },
        updatedAt: new Date().toISOString()
      })

      const result = await handleCallback(
        { code: mockCode, state: mockState },
        mockUserId
      )

      expect(IntegrationRepository.listByUserId).toHaveBeenCalledWith(mockUserId)
      expect(IntegrationRepository.update).toHaveBeenCalledWith('integration-existing', {
        token: {
          accessToken: mockAccessToken,
          refreshToken: mockRefreshToken,
          scope: 'read_write',
          tokenType: 'bearer'
        },
        metadata: {}
      })
      expect(IntegrationRepository.create).not.toHaveBeenCalled()
      expect(result).toEqual({
        success: true,
        stripeAccountId: mockStripeUserId
      })
    })

    it('should create a new integration when existing records do not match the Stripe account', async () => {
      const mockAccessToken = 'sk_test_token123'

      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
        json: async () => ({
          access_token: mockAccessToken,
          stripe_user_id: mockStripeUserId,
          scope: 'read_write',
          token_type: 'bearer'
        })
      } as Response)

      vi.mocked(IntegrationRepository.listByUserId).mockResolvedValue([
        {
          id: 'integration-other-provider',
          userId: mockUserId,
          provider: 'shopify',
          externalId: mockStripeUserId,
          token: {},
          metadata: {},
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString()
        },
        {
          id: 'integration-other-account',
          userId: mockUserId,
          provider: 'stripe',
          externalId: 'acct_other',
          token: {},
          metadata: {},
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString()
        }
      ])

      vi.mocked(IntegrationRepository.create).mockResolvedValue({
        id: 'integration-new',
        userId: mockUserId,
        provider: 'stripe',
        externalId: mockStripeUserId,
        token: {
          accessToken: mockAccessToken,
          scope: 'read_write',
          tokenType: 'bearer'
        },
        metadata: {},
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      })

      const result = await handleCallback(
        { code: mockCode, state: mockState },
        mockUserId
      )

      expect(IntegrationRepository.update).not.toHaveBeenCalled()
      expect(IntegrationRepository.create).toHaveBeenCalledWith({
        userId: mockUserId,
        provider: 'stripe',
        externalId: mockStripeUserId,
        token: {
          accessToken: mockAccessToken,
          refreshToken: undefined,
          scope: 'read_write',
          tokenType: 'bearer'
        },
        metadata: {}
      })
      expect(result).toEqual({
        success: true,
        stripeAccountId: mockStripeUserId
      })
    })
    
    it('should handle response without refresh token', async () => {
      const mockAccessToken = 'sk_test_token123'
      
      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
        json: async () => ({
          access_token: mockAccessToken,
          stripe_user_id: mockStripeUserId,
          scope: 'read_write',
          token_type: 'bearer'
        })
      } as Response)
      
      vi.mocked(IntegrationRepository.create).mockResolvedValue({
        id: 'integration-123',
        userId: mockUserId,
        provider: 'stripe',
        externalId: mockStripeUserId,
        token: {
          accessToken: mockAccessToken,
          scope: 'read_write',
          tokenType: 'bearer'
        },
        metadata: {},
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      })
      
      const result = await handleCallback(
        { code: mockCode, state: mockState },
        mockUserId
      )
      
      expect(result.success).toBe(true)
      expect(result.stripeAccountId).toBe(mockStripeUserId)
      expect(IntegrationRepository.create).toHaveBeenCalledWith(
        expect.objectContaining({
          token: expect.objectContaining({
            accessToken: mockAccessToken,
            refreshToken: undefined
          })
        })
      )
    })
    
    it('should return success with Stripe account ID', async () => {
      const mockAccessToken = 'sk_test_token123'
      
      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
        json: async () => ({
          access_token: mockAccessToken,
          stripe_user_id: mockStripeUserId,
          scope: 'read_write',
          token_type: 'bearer'
        })
      } as Response)
      
      vi.mocked(IntegrationRepository.create).mockResolvedValue({
        id: 'integration-123',
        userId: mockUserId,
        provider: 'stripe',
        externalId: mockStripeUserId,
        token: {
          accessToken: mockAccessToken,
          scope: 'read_write',
          tokenType: 'bearer'
        },
        metadata: {},
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      })
      
      const result = await handleCallback(
        { code: mockCode, state: mockState },
        mockUserId
      )
      
      expect(result).toEqual({
        success: true,
        stripeAccountId: mockStripeUserId
      })
    })
  })
  
  describe('Token Confidentiality', () => {
    beforeEach(() => {
      vi.mocked(store.consumeOAuthState).mockReturnValue(true)
    })
    
    it('should not expose access token in error messages', async () => {
      const mockAccessToken = 'sk_test_secret_token'
      
      vi.mocked(global.fetch).mockResolvedValue({
        ok: false,
        status: 400,
        json: async () => ({
          error: 'invalid_grant',
          access_token: mockAccessToken
        })
      } as Response)
      
      const result = await handleCallback(
        { code: mockCode, state: mockState },
        mockUserId
      )
      
      expect(result.error).not.toContain(mockAccessToken)
      expect(result.error).toBe('Token exchange failed')
    })
    
    it('should not expose refresh token in error messages', async () => {
      const mockRefreshToken = 'rt_test_secret_refresh'
      
      vi.mocked(global.fetch).mockRejectedValue(
        new Error(`Network error with token ${mockRefreshToken}`)
      )
      
      const result = await handleCallback(
        { code: mockCode, state: mockState },
        mockUserId
      )
      
      expect(result.error).not.toContain(mockRefreshToken)
      expect(result.error).toBe('Failed to reach Stripe API')
    })
  })
})
