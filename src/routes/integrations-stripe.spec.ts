import express from 'express'
import request from 'supertest'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { handleCallback } from '../services/integrations/stripe/callback.js'
import { startConnect } from '../services/integrations/stripe/connect.js'
import { integrationsStripeRouter, path } from './integrations-stripe.js'

vi.mock('../services/integrations/stripe/connect.js', () => ({
  startConnect: vi.fn(),
}))

vi.mock('../services/integrations/stripe/callback.js', () => ({
  handleCallback: vi.fn(),
}))

vi.mock('../middleware/requireBusinessAuth.js', () => ({
  requireBusinessAuth: (req: express.Request, _res: express.Response, next: express.NextFunction) => {
    req.user = { id: 'user-1', userId: 'user-1' }
    req.business = {
      id: 'business-1',
      userId: 'user-1',
      name: 'Test business',
      industry: null,
      description: null,
      website: null,
      createdAt: '',
      updatedAt: '',
    }
    next()
  },
}))

const app = express()
app.use('/api/integrations/stripe', integrationsStripeRouter)

const originalStripeClientId = process.env.STRIPE_CLIENT_ID
const originalStripeRedirectUri = process.env.STRIPE_REDIRECT_URI
const originalStripeSuccessRedirect = process.env.STRIPE_SUCCESS_REDIRECT

function restoreEnv(key: string, value: string | undefined) {
  if (value === undefined) delete process.env[key]
  else process.env[key] = value
}

afterEach(() => {
  vi.clearAllMocks()
  restoreEnv('STRIPE_CLIENT_ID', originalStripeClientId)
  restoreEnv('STRIPE_REDIRECT_URI', originalStripeRedirectUri)
  restoreEnv('STRIPE_SUCCESS_REDIRECT', originalStripeSuccessRedirect)
})

describe('integrationsStripeRouter', () => {
  it('exports its router path', () => {
    expect(path).toBe('/integrations/stripe')
  })

  describe('POST /connect', () => {
    it('rejects missing Stripe configuration', async () => {
      delete process.env.STRIPE_CLIENT_ID
      process.env.STRIPE_REDIRECT_URI = 'https://app.example/callback'

      const response = await request(app).post('/api/integrations/stripe/connect')

      expect(response.status).toBe(400)
      expect(response.body).toEqual({ error: 'Missing STRIPE_CLIENT_ID or STRIPE_REDIRECT_URI' })
      expect(startConnect).not.toHaveBeenCalled()
    })

    it('redirects to the Stripe authorization URL when configured', async () => {
      process.env.STRIPE_CLIENT_ID = 'stripe-client'
      process.env.STRIPE_REDIRECT_URI = 'https://app.example/callback'
      vi.mocked(startConnect).mockReturnValue({
        redirectUrl: 'https://connect.stripe.com/oauth/authorize?state=abc',
        state: 'abc',
      })

      const response = await request(app).post('/api/integrations/stripe/connect')

      expect(response.status).toBe(302)
      expect(response.headers.location).toBe('https://connect.stripe.com/oauth/authorize?state=abc')
      expect(startConnect).toHaveBeenCalledOnce()
    })

    it('returns a deterministic error when connect initialization fails', async () => {
      process.env.STRIPE_CLIENT_ID = 'stripe-client'
      process.env.STRIPE_REDIRECT_URI = 'https://app.example/callback'
      vi.mocked(startConnect).mockImplementation(() => {
        throw new Error('OAuth setup failed')
      })

      const response = await request(app).post('/api/integrations/stripe/connect')

      expect(response.status).toBe(400)
      expect(response.body).toEqual({ error: 'OAuth setup failed' })
    })
  })

  describe('GET /callback', () => {
    it('passes missing query parameters as empty values and returns validation errors', async () => {
      vi.mocked(handleCallback).mockResolvedValue({
        success: false,
        error: 'Missing code, or state',
      })

      const response = await request(app).get('/api/integrations/stripe/callback')

      expect(response.status).toBe(400)
      expect(response.body).toEqual({ success: false, error: 'Missing code, or state' })
      expect(handleCallback).toHaveBeenCalledWith(
        { code: '', state: '' },
        'user-1',
        'business-1',
      )
    })

    it('returns 502 when Stripe cannot be reached', async () => {
      vi.mocked(handleCallback).mockResolvedValue({
        success: false,
        error: 'Failed to reach Stripe API',
      })

      const response = await request(app)
        .get('/api/integrations/stripe/callback')
        .query({ code: 'auth-code', state: 'state-token' })

      expect(response.status).toBe(502)
      expect(response.body).toEqual({ success: false, error: 'Failed to reach Stripe API' })
    })

    it('returns token exchange failures as 400 responses', async () => {
      vi.mocked(handleCallback).mockResolvedValue({
        success: false,
        error: 'Token exchange failed',
      })

      const response = await request(app)
        .get('/api/integrations/stripe/callback')
        .query({ code: 'auth-code', state: 'state-token' })

      expect(response.status).toBe(400)
      expect(response.body).toEqual({ success: false, error: 'Token exchange failed' })
    })

    it('returns the connected Stripe account when no success redirect is configured', async () => {
      delete process.env.STRIPE_SUCCESS_REDIRECT
      vi.mocked(handleCallback).mockResolvedValue({
        success: true,
        stripeAccountId: 'acct_123',
      })

      const response = await request(app)
        .get('/api/integrations/stripe/callback')
        .query({ code: 'auth-code', state: 'state-token' })

      expect(response.status).toBe(200)
      expect(response.body).toEqual({ success: true, stripeAccountId: 'acct_123' })
    })

    it('redirects to the configured success URL after connecting', async () => {
      process.env.STRIPE_SUCCESS_REDIRECT = 'https://app.example/integrations/stripe/success'
      vi.mocked(handleCallback).mockResolvedValue({
        success: true,
        stripeAccountId: 'acct_123',
      })

      const response = await request(app)
        .get('/api/integrations/stripe/callback')
        .query({ code: 'auth-code', state: 'state-token' })

      expect(response.status).toBe(302)
      expect(response.headers.location).toBe('https://app.example/integrations/stripe/success')
    })
  })
})