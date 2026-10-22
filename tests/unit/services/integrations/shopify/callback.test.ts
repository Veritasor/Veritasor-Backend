/**
 * Unit tests for Shopify OAuth callback service
 *
 * Covers:
 *   - CallbackParams interface shape (required / optional fields)
 *   - CallbackResult interface shape
 *   - handleCallback: parameter-completeness guard
 *   - handleCallback: HMAC presence guard
 *   - handleCallback: HMAC validation (match / mismatch / computation error)
 *   - handleCallback: shop-hostname validation
 *   - handleCallback: state consumption and shop-binding
 *   - handleCallback: token-exchange HTTP errors and parse failures
 *   - handleCallback: access-token presence guard
 *   - handleCallback: integration create / update / replace paths
 *   - handleCallback: token-save and integration-lookup errors
 *   - Token confidentiality (secrets must not appear in error strings)
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import {
  handleCallback,
  type CallbackParams,
  type CallbackResult,
} from '../../../../../src/services/integrations/shopify/callback.js'
import * as store from '../../../../../src/services/integrations/shopify/store.js'
import * as shopifyUtils from '../../../../../src/services/integrations/shopify/utils.js'
import * as integrationRepository from '../../../../../src/repositories/integration.js'

// ---------------------------------------------------------------------------
// Module mocks
// ---------------------------------------------------------------------------
vi.mock('../../../../../src/services/integrations/shopify/store.js')
vi.mock('../../../../../src/services/integrations/shopify/utils.js')
vi.mock('../../../../../src/repositories/integration.js')
vi.mock('../../../../../src/utils/logger.js', () => ({
  logger: { warn: vi.fn(), error: vi.fn(), info: vi.fn() },
}))

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Build a minimal valid CallbackParams object. */
function makeParams(overrides: Partial<CallbackParams> = {}): CallbackParams {
  return {
    code: 'auth-code-abc',
    shop: 'test-store.myshopify.com',
    state: 'state-token-xyz',
    hmac: 'valid-hmac-value',
    ...overrides,
  }
}

/** Stub a successful token-exchange HTTP response. */
function mockFetchOk(payload: Record<string, unknown> = {}): void {
  global.fetch = vi.fn().mockResolvedValue({
    ok: true,
    status: 200,
    json: async () => ({ access_token: 'shpat_test_token', ...payload }),
  } as Response)
}

const SHOP_HOST = 'test-store.myshopify.com'
const USER_ID = 'user-111'
const BIZ_ID = 'biz-222'

const BASE_INTEGRATION = {
  id: 'int-001',
  userId: USER_ID,
  businessId: BIZ_ID,
  provider: 'shopify' as const,
  externalId: SHOP_HOST,
  token: { accessToken: 'shpat_old' },
  metadata: { shop: SHOP_HOST },
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe('Shopify OAuth Callback Service', () => {
  beforeEach(() => {
    vi.clearAllMocks()

    // Env vars
    process.env.SHOPIFY_CLIENT_ID = 'test-client-id'
    process.env.SHOPIFY_CLIENT_SECRET = 'test-client-secret'

    // Default: HMAC computation succeeds and matches the provided value
    vi.mocked(shopifyUtils.computeShopifyHmac).mockReturnValue('valid-hmac-value')

    // Default: shop normalises and validates successfully
    vi.mocked(store.normalizeShop).mockReturnValue(SHOP_HOST)
    vi.mocked(store.isValidShopHost).mockReturnValue(true)

    // Default: state record matches the shop
    vi.mocked(store.consumeOAuthState).mockReturnValue({
      shop: SHOP_HOST,
      userId: USER_ID,
      businessId: BIZ_ID,
    })

    // Default: token save is a no-op
    vi.mocked(store.saveToken).mockImplementation(() => undefined)

    // Default: no existing integration
    vi.mocked(integrationRepository.listByUserId).mockResolvedValue([])
    vi.mocked(integrationRepository.create).mockResolvedValue({ ...BASE_INTEGRATION })
    vi.mocked(integrationRepository.update).mockResolvedValue({ ...BASE_INTEGRATION })
    vi.mocked(integrationRepository.deleteById).mockResolvedValue(true)

    // Default fetch — overridden by individual tests as needed
    mockFetchOk()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  // -------------------------------------------------------------------------
  // Interface contracts
  // -------------------------------------------------------------------------

  describe('CallbackParams interface', () => {
    it('accepts required fields: code, shop, state', () => {
      const params: CallbackParams = { code: 'c', shop: 's', state: 't' }
      expect(params.code).toBe('c')
      expect(params.shop).toBe('s')
      expect(params.state).toBe('t')
    })

    it('allows optional hmac field', () => {
      const withHmac: CallbackParams = { code: 'c', shop: 's', state: 't', hmac: 'h' }
      expect(withHmac.hmac).toBe('h')

      const withoutHmac: CallbackParams = { code: 'c', shop: 's', state: 't' }
      expect(withoutHmac.hmac).toBeUndefined()
    })

    it('allows arbitrary extra string fields via index signature', () => {
      const params: CallbackParams = { code: 'c', shop: 's', state: 't', extra_param: 'x' }
      expect(params['extra_param']).toBe('x')
    })
  })

  describe('CallbackResult interface', () => {
    it('success result carries shop and no error', () => {
      const result: CallbackResult = { success: true, shop: SHOP_HOST }
      expect(result.success).toBe(true)
      expect(result.shop).toBe(SHOP_HOST)
      expect(result.error).toBeUndefined()
    })

    it('failure result carries error and no shop', () => {
      const result: CallbackResult = { success: false, error: 'Something broke' }
      expect(result.success).toBe(false)
      expect(result.error).toBe('Something broke')
      expect(result.shop).toBeUndefined()
    })
  })

  // -------------------------------------------------------------------------
  // Parameter-completeness guard
  // -------------------------------------------------------------------------

  describe('Missing required parameters', () => {
    it('returns failure when code is empty', async () => {
      const result = await handleCallback(makeParams({ code: '' }))
      expect(result).toMatchObject<CallbackResult>({
        success: false,
        error: 'Missing required callback parameters',
      })
    })

    it('returns failure when shop is empty', async () => {
      const result = await handleCallback(makeParams({ shop: '' }))
      expect(result).toMatchObject<CallbackResult>({
        success: false,
        error: 'Missing required callback parameters',
      })
    })

    it('returns failure when state is empty', async () => {
      const result = await handleCallback(makeParams({ state: '' }))
      expect(result).toMatchObject<CallbackResult>({
        success: false,
        error: 'Missing required callback parameters',
      })
    })

    it('returns failure when all three required fields are empty', async () => {
      const result = await handleCallback(makeParams({ code: '', shop: '', state: '' }))
      expect(result.success).toBe(false)
      expect(result.error).toBe('Missing required callback parameters')
    })

    it('does not call fetch when parameters are missing', async () => {
      await handleCallback(makeParams({ code: '' }))
      expect(global.fetch).not.toHaveBeenCalled()
    })
  })

  // -------------------------------------------------------------------------
  // HMAC presence guard
  // -------------------------------------------------------------------------

  describe('Missing HMAC', () => {
    it('returns failure when hmac is absent', async () => {
      const result = await handleCallback(makeParams({ hmac: undefined }))
      expect(result).toMatchObject<CallbackResult>({
        success: false,
        error: 'Missing HMAC signature',
      })
    })

    it('does not call fetch when hmac is absent', async () => {
      await handleCallback(makeParams({ hmac: undefined }))
      expect(global.fetch).not.toHaveBeenCalled()
    })
  })

  // -------------------------------------------------------------------------
  // HMAC validation
  // -------------------------------------------------------------------------

  describe('HMAC validation', () => {
    it('returns failure when computed HMAC does not match provided HMAC', async () => {
      vi.mocked(shopifyUtils.computeShopifyHmac).mockReturnValue('different-hmac')
      const result = await handleCallback(makeParams())
      expect(result).toMatchObject<CallbackResult>({
        success: false,
        error: 'Invalid HMAC signature',
      })
    })

    it('returns failure when HMAC lengths differ (prevents timing-safe padding bypass)', async () => {
      vi.mocked(shopifyUtils.computeShopifyHmac).mockReturnValue('short')
      const result = await handleCallback(makeParams({ hmac: 'a-much-longer-hmac-value-here' }))
      expect(result.success).toBe(false)
      expect(result.error).toBe('Invalid HMAC signature')
    })

    it('returns failure when computeShopifyHmac throws', async () => {
      vi.mocked(shopifyUtils.computeShopifyHmac).mockImplementation(() => {
        throw new Error('crypto exploded')
      })
      const result = await handleCallback(makeParams())
      expect(result).toMatchObject<CallbackResult>({
        success: false,
        error: 'HMAC validation error',
      })
    })

    it('does not proceed to fetch when HMAC is invalid', async () => {
      vi.mocked(shopifyUtils.computeShopifyHmac).mockReturnValue('wrong')
      await handleCallback(makeParams())
      expect(global.fetch).not.toHaveBeenCalled()
    })

    it('passes clientSecret to computeShopifyHmac', async () => {
      process.env.SHOPIFY_CLIENT_SECRET = 'my-secret'
      await handleCallback(makeParams())
      expect(shopifyUtils.computeShopifyHmac).toHaveBeenCalledWith('my-secret', expect.any(Object))
    })
  })

  // -------------------------------------------------------------------------
  // Shop-hostname validation
  // -------------------------------------------------------------------------

  describe('Shop hostname validation', () => {
    it('returns failure when normalised shop fails isValidShopHost', async () => {
      vi.mocked(store.normalizeShop).mockReturnValue('not-valid')
      vi.mocked(store.isValidShopHost).mockReturnValue(false)
      const result = await handleCallback(makeParams())
      expect(result).toMatchObject<CallbackResult>({
        success: false,
        error: 'Invalid shop hostname',
      })
    })

    it('does not consume state when shop is invalid', async () => {
      vi.mocked(store.isValidShopHost).mockReturnValue(false)
      await handleCallback(makeParams())
      expect(store.consumeOAuthState).not.toHaveBeenCalled()
    })

    it('normalises the shop value before validation', async () => {
      await handleCallback(makeParams({ shop: '  RAW-SHOP  ' }))
      expect(store.normalizeShop).toHaveBeenCalledWith('  RAW-SHOP  ')
    })
  })

  // -------------------------------------------------------------------------
  // State validation
  // -------------------------------------------------------------------------

  describe('State validation', () => {
    it('returns failure when state is not found in the store', async () => {
      vi.mocked(store.consumeOAuthState).mockReturnValue(undefined)
      const result = await handleCallback(makeParams())
      expect(result).toMatchObject<CallbackResult>({
        success: false,
        error: 'Invalid or expired state',
      })
    })

    it('returns failure when state record shop does not match normalised shop', async () => {
      vi.mocked(store.consumeOAuthState).mockReturnValue({
        shop: 'other-store.myshopify.com',
        userId: USER_ID,
        businessId: BIZ_ID,
      })
      const result = await handleCallback(makeParams())
      expect(result).toMatchObject<CallbackResult>({
        success: false,
        error: 'Invalid or expired state',
      })
    })

    it('consumes the state (one-time use)', async () => {
      await handleCallback(makeParams())
      expect(store.consumeOAuthState).toHaveBeenCalledWith('state-token-xyz')
    })

    it('does not call fetch when state is invalid', async () => {
      vi.mocked(store.consumeOAuthState).mockReturnValue(undefined)
      await handleCallback(makeParams())
      expect(global.fetch).not.toHaveBeenCalled()
    })
  })

  // -------------------------------------------------------------------------
  // Token exchange — network / HTTP errors
  // -------------------------------------------------------------------------

  describe('Token exchange failures', () => {
    it('returns failure when fetch throws a network error', async () => {
      global.fetch = vi.fn().mockRejectedValue(new Error('ECONNREFUSED'))
      const result = await handleCallback(makeParams())
      expect(result).toMatchObject<CallbackResult>({
        success: false,
        error: 'Token exchange request failed',
      })
    })

    it('returns failure when Shopify responds with 4xx', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 401,
        json: async () => ({ error: 'invalid_client' }),
      } as Response)
      const result = await handleCallback(makeParams())
      expect(result).toMatchObject<CallbackResult>({
        success: false,
        error: 'Token exchange failed',
      })
    })

    it('returns failure when Shopify responds with 5xx', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        json: async () => ({}),
      } as Response)
      const result = await handleCallback(makeParams())
      expect(result.success).toBe(false)
      expect(result.error).toBe('Token exchange failed')
    })

    it('returns failure when response body is not valid JSON', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => { throw new SyntaxError('Unexpected token') },
      } as unknown as Response)
      const result = await handleCallback(makeParams())
      expect(result).toMatchObject<CallbackResult>({
        success: false,
        error: 'Token response parse failed',
      })
    })

    it('returns failure when access_token is absent from response', async () => {
      mockFetchOk({ access_token: undefined })
      const result = await handleCallback(makeParams())
      expect(result).toMatchObject<CallbackResult>({
        success: false,
        error: 'No access token in response',
      })
    })

    it('returns failure when access_token is not a string', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ access_token: 42 }),
      } as Response)
      const result = await handleCallback(makeParams())
      expect(result).toMatchObject<CallbackResult>({
        success: false,
        error: 'No access token in response',
      })
    })
  })

  // -------------------------------------------------------------------------
  // Token save error
  // -------------------------------------------------------------------------

  describe('Token persistence error', () => {
    it('returns failure when store.saveToken throws', async () => {
      vi.mocked(store.saveToken).mockImplementation(() => {
        throw new Error('disk full')
      })
      const result = await handleCallback(makeParams())
      expect(result).toMatchObject<CallbackResult>({
        success: false,
        error: 'Failed to persist Shopify token',
      })
    })
  })

  // -------------------------------------------------------------------------
  // Integration lookup error
  // -------------------------------------------------------------------------

  describe('Integration repository errors', () => {
    it('returns failure when listByUserId throws', async () => {
      vi.mocked(integrationRepository.listByUserId).mockRejectedValue(new Error('DB down'))
      const result = await handleCallback(makeParams())
      expect(result).toMatchObject<CallbackResult>({
        success: false,
        error: 'Failed to lookup Shopify integration',
      })
    })

    it('returns failure when integration create throws', async () => {
      vi.mocked(integrationRepository.create).mockRejectedValue(new Error('insert failed'))
      const result = await handleCallback(makeParams())
      expect(result).toMatchObject<CallbackResult>({
        success: false,
        error: 'Failed to persist Shopify integration',
      })
    })

    it('returns failure when integration update throws (reuse path)', async () => {
      vi.mocked(integrationRepository.listByUserId).mockResolvedValue([{ ...BASE_INTEGRATION }])
      vi.mocked(integrationRepository.update).mockRejectedValue(new Error('update failed'))
      const result = await handleCallback(makeParams())
      expect(result).toMatchObject<CallbackResult>({
        success: false,
        error: 'Failed to persist Shopify integration',
      })
    })

    it('returns failure when integration update returns null (record not found)', async () => {
      vi.mocked(integrationRepository.listByUserId).mockResolvedValue([{ ...BASE_INTEGRATION }])
      vi.mocked(integrationRepository.update).mockResolvedValue(null)
      const result = await handleCallback(makeParams())
      expect(result).toMatchObject<CallbackResult>({
        success: false,
        error: 'Failed to persist Shopify integration',
      })
    })

    it('returns failure when deleteById throws during shop-change path', async () => {
      const differentShop = { ...BASE_INTEGRATION, externalId: 'old-store.myshopify.com' }
      vi.mocked(integrationRepository.listByUserId).mockResolvedValue([differentShop])
      vi.mocked(integrationRepository.deleteById).mockRejectedValue(new Error('delete failed'))
      const result = await handleCallback(makeParams())
      expect(result).toMatchObject<CallbackResult>({
        success: false,
        error: 'Failed to update Shopify integration',
      })
    })
  })

  // -------------------------------------------------------------------------
  // Success — integration create (fresh install)
  // -------------------------------------------------------------------------

  describe('Successful fresh install', () => {
    it('returns success with normalised shop host', async () => {
      const result = await handleCallback(makeParams())
      expect(result).toMatchObject<CallbackResult>({
        success: true,
        shop: SHOP_HOST,
      })
    })

    it('calls integrationRepository.create with correct fields', async () => {
      await handleCallback(makeParams())
      expect(integrationRepository.create).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: USER_ID,
          businessId: BIZ_ID,
          provider: 'shopify',
          externalId: SHOP_HOST,
          token: { accessToken: 'shpat_test_token' },
          metadata: { shop: SHOP_HOST },
        }),
      )
    })

    it('does not call update or deleteById for a fresh install', async () => {
      await handleCallback(makeParams())
      expect(integrationRepository.update).not.toHaveBeenCalled()
      expect(integrationRepository.deleteById).not.toHaveBeenCalled()
    })
  })

  // -------------------------------------------------------------------------
  // Success — integration update (same shop reconnect)
  // -------------------------------------------------------------------------

  describe('Successful reconnect (same shop)', () => {
    beforeEach(() => {
      vi.mocked(integrationRepository.listByUserId).mockResolvedValue([{ ...BASE_INTEGRATION }])
      vi.mocked(integrationRepository.update).mockResolvedValue({
        ...BASE_INTEGRATION,
        token: { accessToken: 'shpat_test_token' },
      })
    })

    it('returns success with the shop host', async () => {
      const result = await handleCallback(makeParams())
      expect(result).toMatchObject<CallbackResult>({ success: true, shop: SHOP_HOST })
    })

    it('calls update (not create) for an existing same-shop integration', async () => {
      await handleCallback(makeParams())
      expect(integrationRepository.update).toHaveBeenCalledWith(
        BIZ_ID,
        BASE_INTEGRATION.id,
        expect.objectContaining({
          token: { accessToken: 'shpat_test_token' },
          metadata: { shop: SHOP_HOST },
        }),
      )
      expect(integrationRepository.create).not.toHaveBeenCalled()
    })
  })

  // -------------------------------------------------------------------------
  // Success — shop change (different shop on same account)
  // -------------------------------------------------------------------------

  describe('Successful shop change', () => {
    const oldShopRecord = {
      ...BASE_INTEGRATION,
      externalId: 'old-store.myshopify.com',
    }

    beforeEach(() => {
      vi.mocked(integrationRepository.listByUserId).mockResolvedValue([oldShopRecord])
      vi.mocked(integrationRepository.deleteById).mockResolvedValue(true)
      vi.mocked(store.deleteToken).mockReturnValue(true)
      vi.mocked(integrationRepository.create).mockResolvedValue({ ...BASE_INTEGRATION })
    })

    it('returns success', async () => {
      const result = await handleCallback(makeParams())
      expect(result.success).toBe(true)
    })

    it('deletes the old integration record before creating a new one', async () => {
      await handleCallback(makeParams())
      expect(integrationRepository.deleteById).toHaveBeenCalledWith(BIZ_ID, oldShopRecord.id)
      expect(store.deleteToken).toHaveBeenCalledWith(oldShopRecord.externalId)
      expect(integrationRepository.create).toHaveBeenCalled()
    })
  })

  // -------------------------------------------------------------------------
  // Token fetch request shape
  // -------------------------------------------------------------------------

  describe('Token exchange request shape', () => {
    it('POSTs to the correct Shopify token endpoint', async () => {
      await handleCallback(makeParams())
      expect(global.fetch).toHaveBeenCalledWith(
        `https://${SHOP_HOST}/admin/oauth/access_token`,
        expect.objectContaining({ method: 'POST' }),
      )
    })

    it('sends application/x-www-form-urlencoded Content-Type', async () => {
      await handleCallback(makeParams())
      const [, init] = vi.mocked(global.fetch).mock.calls[0]
      expect((init as RequestInit).headers).toMatchObject({
        'Content-Type': 'application/x-www-form-urlencoded',
      })
    })

    it('includes the authorization code in the request body', async () => {
      await handleCallback(makeParams({ code: 'my-special-code' }))
      const [, init] = vi.mocked(global.fetch).mock.calls[0]
      expect((init as RequestInit).body).toContain('code=my-special-code')
    })

    it('includes the client_id in the request body', async () => {
      process.env.SHOPIFY_CLIENT_ID = 'cid-999'
      await handleCallback(makeParams())
      const [, init] = vi.mocked(global.fetch).mock.calls[0]
      expect((init as RequestInit).body).toContain('client_id=cid-999')
    })
  })

  // -------------------------------------------------------------------------
  // Token confidentiality
  // -------------------------------------------------------------------------

  describe('Token confidentiality', () => {
    it('does not expose the client secret in error messages', async () => {
      process.env.SHOPIFY_CLIENT_SECRET = 'super-secret-value'
      global.fetch = vi.fn().mockRejectedValue(new Error('connection reset'))
      const result = await handleCallback(makeParams())
      expect(result.error).not.toContain('super-secret-value')
    })

    it('does not expose the access token in error messages', async () => {
      // Token arrives but integration create explodes – error must not leak the token
      mockFetchOk({ access_token: 'shpat_very_secret_token' })
      vi.mocked(integrationRepository.create).mockRejectedValue(new Error('insert error'))
      const result = await handleCallback(makeParams())
      expect(result.error).not.toContain('shpat_very_secret_token')
    })
  })
})
