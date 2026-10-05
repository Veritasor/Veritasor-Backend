/**
 * Unit tests for Shopify OAuth connect service
 * 
 * Covers:
 *   - startConnect failure paths (missing env variables, invalid shop)
 *   - startConnect normal return values (ConnectResult shape, URL format)
 *   - TTL parsing and limits (resolveOAuthStateTtlMs boundary conditions)
 *   - store integration (state registration)
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { startConnect, type ConnectResult } from '../../../../../src/services/integrations/shopify/connect.js'
import * as store from '../../../../../src/services/integrations/shopify/store.js'

// ---------------------------------------------------------------------------
// Module mocks
// ---------------------------------------------------------------------------
vi.mock('../../../../../src/services/integrations/shopify/store.js')

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe('Shopify OAuth Connect Service', () => {
    const SHOP = 'test-store.myshopify.com'
    const USER_ID = 'user-111'
    const BIZ_ID = 'biz-222'

    beforeEach(() => {
        vi.clearAllMocks()

        // Setup typical successful environment
        process.env.SHOPIFY_CLIENT_ID = 'test-client-id'
        process.env.SHOPIFY_REDIRECT_URI = 'https://app.example.com/callback'
        process.env.SHOPIFY_SCOPES = 'read_orders,write_products'
        delete process.env.SHOPIFY_OAUTH_STATE_TTL_MS

        // Mock store defaults for success path
        vi.mocked(store.normalizeShop).mockImplementation((s) => s.trim())
        vi.mocked(store.isValidShopHost).mockReturnValue(true)
        vi.mocked(store.setOAuthState).mockImplementation(() => undefined)
    })

    afterEach(() => {
        vi.restoreAllMocks()
        vi.useRealTimers()
    })

    // -------------------------------------------------------------------------
    // Failure / Throw Paths (Regression for connect.ts:45)
    // -------------------------------------------------------------------------

    describe('Validation and Failure Paths', () => {
        it('throws when SHOPIFY_CLIENT_ID is missing', () => {
            delete process.env.SHOPIFY_CLIENT_ID
            expect(() => startConnect(SHOP, USER_ID, BIZ_ID)).toThrow(
                'Missing SHOPIFY_CLIENT_ID, SHOPIFY_REDIRECT_URI, or invalid shop'
            )
        })

        it('throws when SHOPIFY_REDIRECT_URI is missing', () => {
            delete process.env.SHOPIFY_REDIRECT_URI
            expect(() => startConnect(SHOP, USER_ID, BIZ_ID)).toThrow(
                'Missing SHOPIFY_CLIENT_ID, SHOPIFY_REDIRECT_URI, or invalid shop'
            )
        })

        it('throws when shop hostname is invalid', () => {
            vi.mocked(store.isValidShopHost).mockReturnValue(false)
            expect(() => startConnect('not-a-valid-shop', USER_ID, BIZ_ID)).toThrow(
                'Missing SHOPIFY_CLIENT_ID, SHOPIFY_REDIRECT_URI, or invalid shop'
            )
        })

        it('throws when both environment variables are missing', () => {
            delete process.env.SHOPIFY_CLIENT_ID
            delete process.env.SHOPIFY_REDIRECT_URI
            expect(() => startConnect(SHOP, USER_ID, BIZ_ID)).toThrow(
                'Missing SHOPIFY_CLIENT_ID, SHOPIFY_REDIRECT_URI, or invalid shop'
            )
        })
    })

    // -------------------------------------------------------------------------
    // Success / Normal Paths
    // -------------------------------------------------------------------------

    describe('Normal Path', () => {
        it('returns a valid ConnectResult shape with expected redirect URL format', () => {
            vi.mocked(store.normalizeShop).mockReturnValue('normalized.myshopify.com')

            const result: ConnectResult = startConnect(SHOP, USER_ID, BIZ_ID)

            // Result shape
            expect(result.redirectUrl).toBeDefined()
            expect(typeof result.state).toBe('string')
            expect(result.state).toHaveLength(32) // 16 bytes encoded to hex

            // URL assertions
            const url = new URL(result.redirectUrl)
            expect(url.origin).toBe('https://normalized.myshopify.com')
            expect(url.pathname).toBe('/admin/oauth/authorize')

            // Query parameters
            expect(url.searchParams.get('client_id')).toBe('test-client-id')
            expect(url.searchParams.get('scope')).toBe('read_orders,write_products')
            expect(url.searchParams.get('redirect_uri')).toBe('https://app.example.com/callback')
            expect(url.searchParams.get('state')).toBe(result.state)

            // Store assertions
            expect(store.setOAuthState).toHaveBeenCalledTimes(1)
            expect(store.setOAuthState).toHaveBeenCalledWith(
                result.state,
                'normalized.myshopify.com',
                USER_ID,
                BIZ_ID,
                expect.any(Number) // expiresAt
            )
        })

        it('falls back to default scope if SHOPIFY_SCOPES is not set', () => {
            delete process.env.SHOPIFY_SCOPES

            const result = startConnect(SHOP, USER_ID, BIZ_ID)
            const url = new URL(result.redirectUrl)

            expect(url.searchParams.get('scope')).toBe('read_orders')
        })
    })

    // -------------------------------------------------------------------------
    // Bound/Default TTL Handling (resolveOAuthStateTtlMs test via side-effect)
    // -------------------------------------------------------------------------

    describe('OAuth State TTL Calculation', () => {
        const DEFAULT_TTL_MS = 10 * 60 * 1000 // 600000ms

        beforeEach(() => {
            vi.useFakeTimers()
            vi.setSystemTime(new Date('2026-09-28T20:00:00.000Z')) // 1790625600000 ms UTC
        })

        it('uses default TTL when env var is missing', () => {
            startConnect(SHOP, USER_ID, BIZ_ID)
            const expiresAt = Date.now() + DEFAULT_TTL_MS

            expect(store.setOAuthState).toHaveBeenCalledWith(
                expect.any(String),
                SHOP,
                USER_ID,
                BIZ_ID,
                expiresAt
            )
        })

        it('uses default TTL when env var is blank', () => {
            process.env.SHOPIFY_OAUTH_STATE_TTL_MS = '   '
            startConnect(SHOP, USER_ID, BIZ_ID)

            expect(store.setOAuthState).toHaveBeenCalledWith(
                expect.any(String), SHOP, USER_ID, BIZ_ID, Date.now() + DEFAULT_TTL_MS
            )
        })

        it('uses default TTL when env var cannot be parsed as a finite number', () => {
            process.env.SHOPIFY_OAUTH_STATE_TTL_MS = 'invalid-number'
            startConnect(SHOP, USER_ID, BIZ_ID)

            expect(store.setOAuthState).toHaveBeenCalledWith(
                expect.any(String), SHOP, USER_ID, BIZ_ID, Date.now() + DEFAULT_TTL_MS
            )
        })

        it('uses default TTL when env var is negative or zero', () => {
            process.env.SHOPIFY_OAUTH_STATE_TTL_MS = '0'
            startConnect(SHOP, USER_ID, BIZ_ID)

            expect(store.setOAuthState).toHaveBeenCalledWith(
                expect.any(String), SHOP, USER_ID, BIZ_ID, Date.now() + DEFAULT_TTL_MS
            )

            vi.clearAllMocks()
            process.env.SHOPIFY_OAUTH_STATE_TTL_MS = '-5000'
            startConnect(SHOP, USER_ID, BIZ_ID)

            expect(store.setOAuthState).toHaveBeenCalledWith(
                expect.any(String), SHOP, USER_ID, BIZ_ID, Date.now() + DEFAULT_TTL_MS
            )
        })

        it('uses custom TTL from env var when appropriately configured', () => {
            const customTtl = 1200000 // 20 mins
            process.env.SHOPIFY_OAUTH_STATE_TTL_MS = customTtl.toString()

            startConnect(SHOP, USER_ID, BIZ_ID)

            expect(store.setOAuthState).toHaveBeenCalledWith(
                expect.any(String), SHOP, USER_ID, BIZ_ID, Date.now() + customTtl
            )
        })
    })
})
