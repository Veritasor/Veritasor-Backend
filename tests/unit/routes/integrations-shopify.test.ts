import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import express, { type Express, type NextFunction, type Request, type Response } from 'express'
import request from 'supertest'

import { integrationsShopifyRouter } from '../../../src/routes/integrations-shopify.js'
import { startConnect } from '../../../src/services/integrations/shopify/connect.js'
import { handleCallback } from '../../../src/services/integrations/shopify/callback.js'
import disconnectShopify from '../../../src/services/integrations/shopify/disconnect.js'
import { requireBusinessAuth } from '../../../src/middleware/requireBusinessAuth.js'

vi.mock('../../../src/services/integrations/shopify/connect.js', () => ({
  startConnect: vi.fn(),
}))
vi.mock('../../../src/services/integrations/shopify/callback.js', () => ({
  handleCallback: vi.fn(),
}))
vi.mock('../../../src/services/integrations/shopify/disconnect.js', () => ({
  __esModule: true,
  default: vi.fn(),
}))
vi.mock('../../../src/middleware/requireBusinessAuth.js', () => ({
  requireBusinessAuth: vi.fn(),
}))

const passthroughAuth = (req: Request, _res: Response, next: NextFunction) => {
  req.user = { id: 'user-1', userId: 'user-1', email: 'user-1@example.com' }
  req.business = {
    id: 'biz-1',
    userId: 'user-1',
    name: 'Test Business',
    industry: null,
    description: null,
    website: null,
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-01T00:00:00Z',
  }
  next()
}

describe('integrationsShopifyRouter', () => {
  let app: Express

  beforeEach(() => {
    vi.resetAllMocks()
    vi.mocked(requireBusinessAuth).mockImplementation(passthroughAuth)
    vi.mocked(disconnectShopify).mockImplementation(async (_req: Request, res: Response) => {
      res.status(200).json({ message: 'disconnected', revoked: true, alreadyRevoked: false })
    })

    app = express()
    app.use(express.json())
    app.use('/api/integrations/shopify', integrationsShopifyRouter)
  })

  afterEach(() => {
    vi.restoreAllMocks()
    delete process.env.SHOPIFY_SUCCESS_REDIRECT
  })

  describe('POST /connect', () => {
    it('initiates OAuth and 302-redirects to the Shopify authorization URL', async () => {
      const redirectUrl =
        'https://demo-store.myshopify.com/admin/oauth/authorize?client_id=abc&scope=read_orders'
      vi.mocked(startConnect).mockReturnValueOnce({ redirectUrl, state: 'state-abc' })

      const res = await request(app)
        .post('/api/integrations/shopify/connect')
        .set('x-business-id', 'biz-1')
        .send({ shop: 'demo-store' })
        .expect(302)

      expect(res.headers.location).toBe(redirectUrl)
      expect(startConnect).toHaveBeenCalledTimes(1)
      expect(startConnect).toHaveBeenCalledWith('demo-store', 'user-1', 'biz-1')
    })

    it('requires business authentication before connecting', async () => {
      vi.mocked(requireBusinessAuth).mockImplementation(async (_req, res) => {
        res.status(401).json({ error: 'Unauthorized' })
      })

      const res = await request(app)
        .post('/api/integrations/shopify/connect')
        .send({ shop: 'demo-store' })
        .expect(401)

      expect(res.body.error).toBe('Unauthorized')
      expect(startConnect).not.toHaveBeenCalled()
    })

    it('rejects a missing shop with 400 Missing or invalid shop', async () => {
      const res = await request(app)
        .post('/api/integrations/shopify/connect')
        .set('x-business-id', 'biz-1')
        .send({})
        .expect(400)

      expect(res.body).toEqual({ error: 'Missing or invalid shop' })
      expect(startConnect).not.toHaveBeenCalled()
    })

    it('rejects a non-string shop with 400 Missing or invalid shop', async () => {
      const res = await request(app)
        .post('/api/integrations/shopify/connect')
        .set('x-business-id', 'biz-1')
        .send({ shop: 123 })
        .expect(400)

      expect(res.body).toEqual({ error: 'Missing or invalid shop' })
      expect(startConnect).not.toHaveBeenCalled()
    })

    it('maps a startConnect Error into a 400 response', async () => {
      vi.mocked(startConnect).mockImplementationOnce(() => {
        throw new Error('Missing SHOPIFY_CLIENT_ID, SHOPIFY_REDIRECT_URI, or invalid shop')
      })

      const res = await request(app)
        .post('/api/integrations/shopify/connect')
        .set('x-business-id', 'biz-1')
        .send({ shop: 'demo-store' })
        .expect(400)

      expect(res.body).toEqual({
        error: 'Missing SHOPIFY_CLIENT_ID, SHOPIFY_REDIRECT_URI, or invalid shop',
      })
    })

    it('maps a non-Error startConnect failure into a generic 400 Connect failed response', async () => {
      vi.mocked(startConnect).mockImplementationOnce(() => {
        throw 'something exploded'
      })

      const res = await request(app)
        .post('/api/integrations/shopify/connect')
        .set('x-business-id', 'biz-1')
        .send({ shop: 'demo-store' })
        .expect(400)

      expect(res.body).toEqual({ error: 'Connect failed' })
    })

    it('accepts a fully-qualified .myshopify.com shop', async () => {
      const redirectUrl = 'https://demo.myshopify.com/admin/oauth/authorize?client_id=abc'
      vi.mocked(startConnect).mockReturnValueOnce({ redirectUrl, state: 'state-xyz' })

      const res = await request(app)
        .post('/api/integrations/shopify/connect')
        .set('x-business-id', 'biz-1')
        .send({ shop: 'demo.myshopify.com' })
        .expect(302)

      expect(res.headers.location).toBe(redirectUrl)
      expect(startConnect).toHaveBeenCalledWith(
        'demo.myshopify.com',
        'user-1',
        'biz-1',
      )
    })
  })

  describe('GET /callback', () => {
    const params = {
      code: 'auth-code-1',
      shop: 'demo.myshopify.com',
      state: 'state-1',
      hmac: 'dummy',
    }

    it('returns a JSON success body when no success redirect is configured', async () => {
      vi.mocked(handleCallback).mockResolvedValueOnce({
        success: true,
        shop: 'demo.myshopify.com',
      })
      delete process.env.SHOPIFY_SUCCESS_REDIRECT

      const res = await request(app)
        .get('/api/integrations/shopify/callback')
        .query(params)
        .expect(200)

      expect(res.body).toEqual({ success: true, shop: 'demo.myshopify.com' })
      expect(handleCallback).toHaveBeenCalledTimes(1)
      expect(handleCallback).toHaveBeenCalledWith(expect.objectContaining(params))
    })

    it('redirects to the configured success URL on a successful callback', async () => {
      vi.mocked(handleCallback).mockResolvedValueOnce({
        success: true,
        shop: 'demo.myshopify.com',
      })
      process.env.SHOPIFY_SUCCESS_REDIRECT = 'https://app.example.com/integrations/shopify'

      const res = await request(app)
        .get('/api/integrations/shopify/callback')
        .query(params)
        .expect(302)

      expect(res.headers.location).toBe('https://app.example.com/integrations/shopify')
    })

    it('forwards the full raw query string to handleCallback', async () => {
      vi.mocked(handleCallback).mockResolvedValueOnce({
        success: true,
        shop: 'demo.myshopify.com',
      })
      delete process.env.SHOPIFY_SUCCESS_REDIRECT

      await request(app)
        .get('/api/integrations/shopify/callback')
        .query({ ...params, extra: 'ignored' })
        .expect(200)

      expect(handleCallback).toHaveBeenCalledWith(
        expect.objectContaining({
          code: 'auth-code-1',
          shop: 'demo.myshopify.com',
          state: 'state-1',
          hmac: 'dummy',
          extra: 'ignored',
        }),
      )
    })

    it('returns a 400 with the failure detail when the callback fails', async () => {
      vi.mocked(handleCallback).mockResolvedValueOnce({
        success: false,
        error: 'Invalid HMAC signature',
      })

      const res = await request(app)
        .get('/api/integrations/shopify/callback')
        .query(params)
        .expect(400)

      expect(res.body).toEqual({ success: false, error: 'Invalid HMAC signature' })
    })

    it('returns a 400 when required callback parameters are missing', async () => {
      vi.mocked(handleCallback).mockResolvedValueOnce({
        success: false,
        error: 'Missing required callback parameters',
      })

      const res = await request(app)
        .get('/api/integrations/shopify/callback')
        .query({ shop: 'demo.myshopify.com' })
        .expect(400)

      expect(res.body).toEqual({
        success: false,
        error: 'Missing required callback parameters',
      })
      expect(handleCallback).toHaveBeenCalledWith(
        expect.objectContaining({ shop: 'demo.myshopify.com' }),
      )
    })
  })

  describe('DELETE /', () => {
    it('delegates to disconnectShopify with auth context when authenticated', async () => {
      const res = await request(app)
        .delete('/api/integrations/shopify')
        .set('x-business-id', 'biz-1')
        .expect(200)

      expect(res.body).toEqual({
        message: 'disconnected',
        revoked: true,
        alreadyRevoked: false,
      })
      expect(disconnectShopify).toHaveBeenCalledTimes(1)
      const reqArg = vi.mocked(disconnectShopify).mock.calls[0][0] as Request
      expect(reqArg.user).toMatchObject({ userId: 'user-1' })
      expect(reqArg.business).toMatchObject({ id: 'biz-1' })
      expect(vi.mocked(disconnectShopify).mock.calls[0][1]).toEqual(expect.any(Object))
      expect(vi.mocked(disconnectShopify).mock.calls[0][2]).toEqual(
        expect.any(Function),
      )
    })

    it('does not invoke disconnectShopify when authentication fails', async () => {
      vi.mocked(requireBusinessAuth).mockImplementation(async (_req, res) => {
        res.status(401).json({ error: 'Unauthorized' })
      })

      const res = await request(app)
        .delete('/api/integrations/shopify')
        .expect(401)

      expect(res.body.error).toBe('Unauthorized')
      expect(disconnectShopify).not.toHaveBeenCalled()
    })
  })
})
