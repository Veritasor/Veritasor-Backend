import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import request from 'supertest'
import express, { type Express, type NextFunction, type Request, type Response } from 'express'

const stripeMocks = vi.hoisted(() => ({
  requireBusinessAuth: vi.fn((req: Request, _res: Response, next: NextFunction) => {
    req.user = { id: 'user-123', userId: 'user-123' }
    req.business = {
      id: 'business-123',
      userId: 'user-123',
      name: 'Test business',
      industry: null,
      description: null,
      website: null,
      createdAt: '',
      updatedAt: '',
    }
    next()
  }),
  startConnect: vi.fn(),
  handleCallback: vi.fn(),
}))

vi.mock('../../src/middleware/requireBusinessAuth.js', () => ({
  requireBusinessAuth: stripeMocks.requireBusinessAuth,
}))

vi.mock('../../src/services/integrations/stripe/connect.js', () => ({
  startConnect: stripeMocks.startConnect,
}))

vi.mock('../../src/services/integrations/stripe/callback.js', () => ({
  handleCallback: stripeMocks.handleCallback,
}))

import { integrationsStripeRouter } from '../../src/routes/integrations-stripe.js'

const originalStripeEnv = {
  STRIPE_CLIENT_ID: process.env.STRIPE_CLIENT_ID,
  STRIPE_REDIRECT_URI: process.env.STRIPE_REDIRECT_URI,
  STRIPE_SUCCESS_REDIRECT: process.env.STRIPE_SUCCESS_REDIRECT,
}

const connectRedirectUrl = 'https://connect.example.test/authorize'
const callbackQuery = { code: 'authorization-code', state: 'oauth-state' }

describe('Stripe OAuth router', () => {
  let app: Express

  beforeEach(() => {
    app = express()
    app.use(express.json())
    app.use('/api/integrations/stripe', integrationsStripeRouter)

    process.env.STRIPE_CLIENT_ID = 'test-client-id'
    process.env.STRIPE_REDIRECT_URI = 'https://app.example.test/stripe/callback'
    delete process.env.STRIPE_SUCCESS_REDIRECT

    vi.clearAllMocks()
    stripeMocks.startConnect.mockReturnValue({
      redirectUrl: connectRedirectUrl,
      state: 'oauth-state',
    })
    stripeMocks.handleCallback.mockResolvedValue({
      success: true,
      stripeAccountId: 'acct_123',
    })
  })

  afterEach(() => {
    for (const [key, value] of Object.entries(originalStripeEnv)) {
      if (value === undefined) {
        delete process.env[key]
      } else {
        process.env[key] = value
      }
    }
  })

  it.each(['STRIPE_CLIENT_ID', 'STRIPE_REDIRECT_URI'] as const)(
    'returns 400 when %s is missing',
    async (missingVariable) => {
      delete process.env[missingVariable]

      const response = await request(app).post('/api/integrations/stripe/connect')

      expect(response.status).toBe(400)
      expect(response.body).toEqual({
        error: 'Missing STRIPE_CLIENT_ID or STRIPE_REDIRECT_URI',
      })
      expect(stripeMocks.startConnect).not.toHaveBeenCalled()
    },
  )

  it('redirects to the Stripe authorization URL on connect', async () => {
    const response = await request(app).post('/api/integrations/stripe/connect')

    expect(response.status).toBe(302)
    expect(response.headers.location).toBe(connectRedirectUrl)
    expect(stripeMocks.startConnect).toHaveBeenCalledOnce()
  })

  it('returns 502 when the callback cannot reach Stripe', async () => {
    stripeMocks.handleCallback.mockResolvedValue({
      success: false,
      error: 'Failed to reach Stripe API',
    })

    const response = await request(app)
      .get('/api/integrations/stripe/callback')
      .query(callbackQuery)

    expect(response.status).toBe(502)
    expect(response.body).toEqual({
      success: false,
      error: 'Failed to reach Stripe API',
    })
    expect(stripeMocks.handleCallback).toHaveBeenCalledWith(
      callbackQuery,
      'user-123',
      'business-123',
    )
  })

  it('redirects successful callbacks to STRIPE_SUCCESS_REDIRECT when configured', async () => {
    const successRedirect = 'https://app.example.test/integrations/stripe/success'
    process.env.STRIPE_SUCCESS_REDIRECT = successRedirect

    const response = await request(app)
      .get('/api/integrations/stripe/callback')
      .query(callbackQuery)

    expect(response.status).toBe(302)
    expect(response.headers.location).toBe(successRedirect)
  })

  it('returns JSON for successful callbacks when no success redirect is configured', async () => {
    const response = await request(app)
      .get('/api/integrations/stripe/callback')
      .query(callbackQuery)

    expect(response.status).toBe(200)
    expect(response.body).toEqual({ success: true, stripeAccountId: 'acct_123' })
  })

  it('returns 400 when the callback reports an error', async () => {
    stripeMocks.handleCallback.mockResolvedValue({
      success: false,
      error: 'Invalid OAuth state',
    })

    const response = await request(app)
      .get('/api/integrations/stripe/callback')
      .query(callbackQuery)

    expect(response.status).toBe(400)
    expect(response.body).toEqual({ success: false, error: 'Invalid OAuth state' })
  })
})
