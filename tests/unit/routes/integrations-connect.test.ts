import { describe, it, expect, beforeEach, vi } from 'vitest'
import express from 'express'
import request from 'supertest'
import router, { consumeState, _clearPendingStates } from '../../../src/routes/integrations.js'

// Mock auth + permissions so we can focus on connect logic
vi.mock('../../../src/middleware/auth.js', () => ({
  requireAuth: (req: any, _res: any, next: any) => {
    req.user = { id: 'u1', userId: 'u1', email: 'u@test.com' }
    next()
  },
}))
vi.mock('../../../src/middleware/permissions.js', () => ({
  requirePermissions: () => (_req: any, _res: any, next: any) => next(),
  IntegrationPermission: { CONNECT: 'CONNECT', READ_CONNECTED: 'READ_CONNECTED', READ_OWN: 'READ_OWN', DISCONNECT_OWN: 'DISCONNECT_OWN' },
}))
vi.mock('../../../src/repositories/integration.js', () => ({
  listByUserId: async () => [],
  deleteById: async () => true,
  clearAll: () => {},
}))

const app = express()
app.use(express.json())
app.use('/api/integrations', router)

describe('POST /api/integrations/connect — security hardening', () => {
  beforeEach(() => {
    _clearPendingStates()
  })

  // --- open-redirect prevention ---

  it('rejects a redirectUri whose origin is not in the allowlist', async () => {
    const res = await request(app)
      .post('/api/integrations/connect')
      .send({ provider: 'razorpay', redirectUri: 'https://evil.example.com/callback' })
      .expect(400)

    expect(res.body.message).toMatch(/allowed list/i)
  })

  it('rejects a redirectUri that is a relative path (not a valid URL)', async () => {
    const res = await request(app)
      .post('/api/integrations/connect')
      .send({ provider: 'razorpay', redirectUri: '/relative/path' })
      .expect(400)

    // Zod rejects non-URL strings before our allowlist check
    expect(res.body.error).toMatch(/validation/i)
  })

  it('accepts a redirectUri whose origin matches the default allowlist', async () => {
    const res = await request(app)
      .post('/api/integrations/connect')
      .send({ provider: 'razorpay', redirectUri: 'http://localhost:3000/integrations/callback' })
      .expect(200)

    expect(res.body.provider).toBe('razorpay')
  })

  it('uses the default callback when no redirectUri is supplied', async () => {
    const res = await request(app)
      .post('/api/integrations/connect')
      .send({ provider: 'razorpay' })
      .expect(200)

    expect(res.body.authUrl).toContain('localhost:3000')
  })

  // --- CSRF state format ---

  it('returns a 64-char hex state (32 random bytes)', async () => {
    const res = await request(app)
      .post('/api/integrations/connect')
      .send({ provider: 'razorpay' })
      .expect(200)

    expect(res.body.state).toMatch(/^[0-9a-f]{64}$/)
  })

  it('returns a different state on each call (no predictable pattern)', async () => {
    const r1 = await request(app).post('/api/integrations/connect').send({ provider: 'razorpay' })
    const r2 = await request(app).post('/api/integrations/connect').send({ provider: 'razorpay' })
    expect(r1.body.state).not.toBe(r2.body.state)
  })

  // --- replay prevention ---

  it('consumeState returns the bound userId on first use', async () => {
    const res = await request(app)
      .post('/api/integrations/connect')
      .send({ provider: 'razorpay' })
      .expect(200)

    expect(consumeState(res.body.state)).toBe('u1')
  })

  it('consumeState returns null on second use (single-use enforcement)', async () => {
    const res = await request(app)
      .post('/api/integrations/connect')
      .send({ provider: 'razorpay' })
      .expect(200)

    consumeState(res.body.state)                  // first use — valid
    expect(consumeState(res.body.state)).toBeNull() // replay — rejected
  })

  it('consumeState returns null for an unknown token', () => {
    expect(consumeState('0'.repeat(64))).toBeNull()
  })
})
