import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import express, { type Express } from 'express'
import request from 'supertest'
import { integrationsShopifyRouter } from '../../src/routes/integrations-shopify.js'
import * as integrationRepository from '../../src/repositories/integration.js'
import { clearAll as clearShopifyStore, getToken } from '../../src/services/integrations/shopify/store.js'
import * as shopifyUtils from '../../src/services/integrations/shopify/utils.js'

vi.mock('../../src/middleware/requireBusinessAuth.js', () => ({
  requireBusinessAuth: (req: any, res: any, next: any) => {
    const userId = req.headers['x-user-id']
    const businessId = req.headers['x-business-id']
    if (!userId || !businessId) {
      return res.status(401).json({ error: 'authentication required' })
    }
    req.user = { id: userId, userId: userId }
    req.business = { id: businessId, userId: userId }
    next()
  },
}))

vi.mock('../../src/services/integrations/shopify/utils.js', async (importOriginal) => {
  const actual = await importOriginal<typeof shopifyUtils>()
  return {
    ...actual,
    computeShopifyHmac: vi.fn().mockReturnValue('dummy'),
  }
})




function jsonResponse(status: number, body: unknown): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
    text: async () => JSON.stringify(body),
  } as Response
}

describe('Shopify disconnect revocation assurance', () => {
  let app: Express
  const originalFetch = global.fetch

  beforeEach(() => {
    app = express()
    app.use(express.json())
    app.use('/api/integrations/shopify', integrationsShopifyRouter)

    integrationRepository.clearAll()
    clearShopifyStore()

    process.env.SHOPIFY_CLIENT_ID = 'shopify-client-id'
    process.env.SHOPIFY_CLIENT_SECRET = 'shopify-client-secret'
    process.env.SHOPIFY_REDIRECT_URI = 'https://veritasor.example.com/api/integrations/shopify/callback'
    delete process.env.SHOPIFY_SUCCESS_REDIRECT

    global.fetch = vi.fn()
  })

  afterEach(() => {
    integrationRepository.clearAll()
    clearShopifyStore()

    delete process.env.SHOPIFY_CLIENT_ID
    delete process.env.SHOPIFY_CLIENT_SECRET
    delete process.env.SHOPIFY_REDIRECT_URI
    delete process.env.SHOPIFY_SUCCESS_REDIRECT

    global.fetch = originalFetch
    vi.restoreAllMocks()
  })

  async function connectShopifyInstallation(userId = 'user-123', businessId = 'biz-123', shop = 'demo-store') {
    vi.mocked(global.fetch).mockResolvedValueOnce(
      jsonResponse(200, { access_token: 'shpat_test_token' }),
    )

    const connectResponse = await request(app)
      .post('/api/integrations/shopify/connect')
      .set('x-user-id', userId)
      .set('x-business-id', businessId)
      .send({ shop })
      .expect(302)

    const redirectUrl = new URL(connectResponse.headers.location)
    const state = redirectUrl.searchParams.get('state')
    expect(state).toBeTruthy()

    await request(app)
      .get('/api/integrations/shopify/callback')
      .query({
        code: 'oauth-code-123',
        shop: `${shop}.myshopify.com`,
        state,
        hmac: 'dummy',
      })
      .expect(200)


    return { shopHost: `${shop}.myshopify.com` }
  }

  it('requires authentication before starting Shopify OAuth', async () => {
    const response = await request(app)
      .post('/api/integrations/shopify/connect')
      .send({ shop: 'demo-store' })
      .expect(401)

    expect(response.body.error).toMatch(/authentication required/i)
  })

  it('revokes the Shopify app remotely before deleting the local integration', async () => {
    const { shopHost } = await connectShopifyInstallation()

    const integrationsBeforeDisconnect = await integrationRepository.listByUserId('user-123')
    expect(integrationsBeforeDisconnect).toHaveLength(1)
    expect(integrationsBeforeDisconnect[0]?.externalId).toBe(shopHost)
    expect(getToken(shopHost)).toBe('shpat_test_token')

    vi.mocked(global.fetch).mockResolvedValueOnce(jsonResponse(200, {}))

    const response = await request(app)
      .delete('/api/integrations/shopify')
      .set('x-user-id', 'user-123')
      .set('x-business-id', 'biz-123')
      .expect(200)

    expect(global.fetch).toHaveBeenLastCalledWith(
      `https://${shopHost}/admin/api_permissions/current.json`,
      expect.objectContaining({
        method: 'DELETE',
        headers: expect.objectContaining({
          Accept: 'application/json',
          'X-Shopify-Access-Token': 'shpat_test_token',
        }),
      }),
    )
    expect(response.body).toEqual({
      message: 'ok',
      revoked: true,
      alreadyRevoked: false,
    })
    expect(await integrationRepository.listByUserId('user-123')).toHaveLength(0)
    expect(getToken(shopHost)).toBeUndefined()
  })

  it('keeps the local Shopify integration when upstream revocation fails', async () => {
    const { shopHost } = await connectShopifyInstallation()

    vi.mocked(global.fetch).mockResolvedValueOnce(jsonResponse(500, { error: 'boom' }))

    const response = await request(app)
      .delete('/api/integrations/shopify')
      .set('x-user-id', 'user-123')
      .set('x-business-id', 'biz-123')
      .expect(502)

    expect(response.body.error).toMatch(/failed to revoke shopify access/i)
    expect(await integrationRepository.listByUserId('user-123')).toHaveLength(1)
    expect(getToken(shopHost)).toBe('shpat_test_token')
  })

  it('returns 500 if local integration deletion fails after remote revocation', async () => {
    const { shopHost } = await connectShopifyInstallation()

    vi.mocked(global.fetch).mockResolvedValueOnce(jsonResponse(200, {}))
    vi.spyOn(integrationRepository, 'deleteById').mockResolvedValueOnce(false)

    const response = await request(app)
      .delete('/api/integrations/shopify')
      .set('x-user-id', 'user-123')
      .set('x-business-id', 'biz-123')
      .expect(500)

    expect(response.body.error).toBe('Failed to disconnect Shopify integration')
    expect(await integrationRepository.listByUserId('user-123')).toHaveLength(1)
    expect(getToken(shopHost)).toBe('shpat_test_token')
  })

  it('treats already-revoked Shopify access as a successful disconnect', async () => {
    const { shopHost } = await connectShopifyInstallation()

    vi.mocked(global.fetch).mockResolvedValueOnce(jsonResponse(401, { error: 'revoked' }))

    const response = await request(app)
      .delete('/api/integrations/shopify')
      .set('x-user-id', 'user-123')
      .set('x-business-id', 'biz-123')
      .expect(200)

    expect(response.body).toEqual({
      message: 'ok',
      revoked: true,
      alreadyRevoked: true,
    })
    expect(await integrationRepository.listByUserId('user-123')).toHaveLength(0)
    expect(getToken(shopHost)).toBeUndefined()
  })
})

