import { describe, it, expect, beforeAll } from 'vitest'
import request from 'supertest'
import express, { Express } from 'express'
import { integrationsStripeRouter } from '../../src/routes/integrations-stripe.js'

/**
 * Integration test to verify Stripe OAuth router is properly mounted
 * 
 * Tests verify:
 * - POST /api/integrations/stripe/connect endpoint exists
 * - GET /api/integrations/stripe/callback endpoint exists
 * - Endpoints are accessible at correct URLs
 */

describe('Stripe OAuth Router Mounting', () => {
  let app: Express

  beforeAll(() => {
    app = express()
    app.use(express.json())
    
    // Mount the Stripe router at the expected path
    app.use('/api/integrations/stripe', integrationsStripeRouter)
  })

  it('should have POST /api/integrations/stripe/connect endpoint', async () => {
    // This will return 401 (unauthorized) or 400 (missing config) but not 404
    const response = await request(app)
      .post('/api/integrations/stripe/connect')
      .send()
    
    // Endpoint exists if we don't get 404
    expect(response.status).not.toBe(404)
  })

  it('should have GET /api/integrations/stripe/callback endpoint', async () => {
    // This will return 401 (unauthorized) or 400 (validation error) but not 404
    const response = await request(app)
      .get('/api/integrations/stripe/callback')
    
    // Endpoint exists if we don't get 404
    expect(response.status).not.toBe(404)
  })

  it('should mount router at /api/integrations/stripe path', async () => {
    // Verify the base path doesn't return 404 for known endpoints
    const connectResponse = await request(app)
      .post('/api/integrations/stripe/connect')
    
    const callbackResponse = await request(app)
      .get('/api/integrations/stripe/callback')
    
    // Both endpoints should exist (not 404)
    expect(connectResponse.status).not.toBe(404)
    expect(callbackResponse.status).not.toBe(404)
  })
})
