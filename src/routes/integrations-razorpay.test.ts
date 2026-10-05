import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import request from 'supertest'
import express, { Express } from 'express'
import {
  integrationsRazorpayRouter,
  default as defaultRouter,
} from './integrations-razorpay.js'
import * as jwt from '../utils/jwt.js'
import * as userRepository from '../repositories/userRepository.js'
import { businessRepository } from '../repositories/business.js'
import { integrationRepository } from '../repositories/integrations.js'
import * as clientWrapper from '../services/integrations/clientWrapper.js'
import { GlobalRetryBudgetExceededError } from '../services/integrations/retryBudget.js'

// ─── Test Helpers & Fixtures ──────────────────────────────────────────────────

const TEST_USER = {
  id: 'user-rzp-1',
  userId: 'user-rzp-1',
  email: 'merchant@example.com',
  role: 'user' as const,
}

const TEST_BUSINESS = {
  id: 'biz-rzp-1',
  userId: 'user-rzp-1',
  name: 'Acme Merchant Corp',
  industry: 'retail',
  description: 'E-commerce store',
  website: 'https://example.com',
  createdAt: '2026-01-01T00:00:00Z',
  updatedAt: '2026-01-01T00:00:00Z',
}

const OTHER_USER = {
  id: 'user-rzp-2',
  userId: 'user-rzp-2',
  email: 'other@example.com',
  role: 'user' as const,
}

const OTHER_BUSINESS = {
  id: 'biz-rzp-2',
  userId: 'user-rzp-2',
  name: 'Beta Merchant LLC',
  industry: 'services',
  description: 'Consulting',
  website: 'https://beta.example.com',
  createdAt: '2026-01-01T00:00:00Z',
  updatedAt: '2026-01-01T00:00:00Z',
}

const VALID_API_KEY_ID = 'rzp_test_1234567890abcdef'
const VALID_API_KEY_SECRET = 'secret_test_9876543210fedcba'

function jsonResponse(status: number, body: unknown): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
    text: async () => JSON.stringify(body),
  } as unknown as Response
}

function validRazorpayVerificationPayload() {
  return {
    entity: 'collection',
    items: [],
  }
}

function buildApp(): Express {
  const app = express()
  app.use(express.json())
  app.use('/api/integrations/razorpay', integrationsRazorpayRouter)
  return app
}

function setupDefaultAuthMocks() {
  vi.spyOn(jwt, 'verifyToken').mockImplementation((token: string) => {
    if (token === 'valid-token') {
      return { userId: TEST_USER.userId, email: TEST_USER.email }
    }
    if (token === 'other-user-token') {
      return { userId: OTHER_USER.userId, email: OTHER_USER.email }
    }
    return null
  })

  vi.spyOn(userRepository, 'findUserById').mockImplementation(async (id: string) => {
    if (id === TEST_USER.userId) return TEST_USER as any
    if (id === OTHER_USER.userId) return OTHER_USER as any
    return null
  })

  vi.spyOn(businessRepository, 'getById').mockImplementation(async (id: string) => {
    if (id === TEST_BUSINESS.id) return { ...TEST_BUSINESS } as any
    if (id === OTHER_BUSINESS.id) return { ...OTHER_BUSINESS } as any
    return null
  })
}

function clearIntegrationsForUser(userId: string) {
  const records = integrationRepository.listByUser(userId)
  for (const record of records) {
    integrationRepository.deleteById(record.id)
  }
}

// ─── Test Suite ───────────────────────────────────────────────────────────────

describe('integrationsRazorpayRouter', () => {
  let app: Express
  const originalFetch = global.fetch

  beforeEach(() => {
    app = buildApp()
    setupDefaultAuthMocks()
    global.fetch = vi.fn().mockResolvedValue(
      jsonResponse(200, validRazorpayVerificationPayload()),
    )
    clearIntegrationsForUser(TEST_USER.userId)
    clearIntegrationsForUser(OTHER_USER.userId)
  })

  afterEach(() => {
    clearIntegrationsForUser(TEST_USER.userId)
    clearIntegrationsForUser(OTHER_USER.userId)
    global.fetch = originalFetch
    vi.restoreAllMocks()
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // 1. Router Exports & Mounting Public Contract
  // ═══════════════════════════════════════════════════════════════════════════

  describe('router exports and mounting contract', () => {
    it('exports both named and default router referencing the same instance', () => {
      expect(integrationsRazorpayRouter).toBeDefined()
      expect(defaultRouter).toBeDefined()
      expect(integrationsRazorpayRouter).toBe(defaultRouter)
    })

    it('mounts without error on an Express application', () => {
      const testApp = express()
      expect(() => {
        testApp.use('/api/integrations/razorpay', integrationsRazorpayRouter)
      }).not.toThrow()
    })

    it('rejects unsupported HTTP methods with 404', async () => {
      const getRes = await request(app)
        .get('/api/integrations/razorpay')
        .set('Authorization', 'Bearer valid-token')
        .set('x-business-id', TEST_BUSINESS.id)

      expect(getRes.status).toBe(404)

      const putRes = await request(app)
        .put('/api/integrations/razorpay')
        .set('Authorization', 'Bearer valid-token')
        .set('x-business-id', TEST_BUSINESS.id)
        .send({ apiKeyId: VALID_API_KEY_ID, apiKeySecret: VALID_API_KEY_SECRET })

      expect(putRes.status).toBe(404)

      const patchRes = await request(app)
        .patch('/api/integrations/razorpay')
        .set('Authorization', 'Bearer valid-token')
        .set('x-business-id', TEST_BUSINESS.id)
        .send({ apiKeyId: VALID_API_KEY_ID })

      expect(patchRes.status).toBe(404)
    })
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // 2. Authentication & Authorization Middleware Coverage
  // ═══════════════════════════════════════════════════════════════════════════

  describe('requireBusinessAuth middleware enforcement', () => {
    it('rejects POST request without Authorization header with 401 MISSING_AUTH', async () => {
      const res = await request(app)
        .post('/api/integrations/razorpay')
        .set('x-business-id', TEST_BUSINESS.id)
        .send({
          apiKeyId: VALID_API_KEY_ID,
          apiKeySecret: VALID_API_KEY_SECRET,
        })

      expect(res.status).toBe(401)
      expect(res.body).toEqual({
        error: 'Business authentication required',
        message: "Missing or invalid authorization header. Format: 'Bearer <token>'",
        code: 'MISSING_AUTH',
      })
      expect(global.fetch).not.toHaveBeenCalled()
    })

    it('rejects POST request with invalid Bearer token with 401 INVALID_TOKEN', async () => {
      const res = await request(app)
        .post('/api/integrations/razorpay')
        .set('Authorization', 'Bearer invalid-token')
        .set('x-business-id', TEST_BUSINESS.id)
        .send({
          apiKeyId: VALID_API_KEY_ID,
          apiKeySecret: VALID_API_KEY_SECRET,
        })

      expect(res.status).toBe(401)
      expect(res.body).toEqual({
        error: 'Invalid authentication',
        message: 'Token is invalid, expired, or user not found',
        code: 'INVALID_TOKEN',
      })
      expect(global.fetch).not.toHaveBeenCalled()
    })

    it('rejects POST request when user is not found in database with 401 INVALID_TOKEN', async () => {
      vi.spyOn(userRepository, 'findUserById').mockResolvedValueOnce(null)

      const res = await request(app)
        .post('/api/integrations/razorpay')
        .set('Authorization', 'Bearer valid-token')
        .set('x-business-id', TEST_BUSINESS.id)
        .send({
          apiKeyId: VALID_API_KEY_ID,
          apiKeySecret: VALID_API_KEY_SECRET,
        })

      expect(res.status).toBe(401)
      expect(res.body.code).toBe('INVALID_TOKEN')
    })

    it('rejects POST request when business ID is missing with 400 MISSING_BUSINESS_ID', async () => {
      const res = await request(app)
        .post('/api/integrations/razorpay')
        .set('Authorization', 'Bearer valid-token')
        .send({
          apiKeyId: VALID_API_KEY_ID,
          apiKeySecret: VALID_API_KEY_SECRET,
        })

      expect(res.status).toBe(400)
      expect(res.body).toEqual({
        error: 'Business context required',
        message:
          "Business ID is required. Provide via 'x-business-id' header or 'business_id'/'businessId' in request body",
        code: 'MISSING_BUSINESS_ID',
      })
      expect(global.fetch).not.toHaveBeenCalled()
    })

    it('rejects POST request when business does not exist with 403 BUSINESS_NOT_FOUND', async () => {
      const res = await request(app)
        .post('/api/integrations/razorpay')
        .set('Authorization', 'Bearer valid-token')
        .set('x-business-id', 'non-existent-biz')
        .send({
          apiKeyId: VALID_API_KEY_ID,
          apiKeySecret: VALID_API_KEY_SECRET,
        })

      expect(res.status).toBe(403)
      expect(res.body).toEqual({
        error: 'Business access denied',
        message: 'Business not found or access denied. User must own the business.',
        code: 'BUSINESS_NOT_FOUND',
      })
      expect(global.fetch).not.toHaveBeenCalled()
    })

    it('rejects POST request when user does not own the business with 403 BUSINESS_NOT_FOUND', async () => {
      // Authenticated as TEST_USER, but requesting access to OTHER_BUSINESS
      const res = await request(app)
        .post('/api/integrations/razorpay')
        .set('Authorization', 'Bearer valid-token')
        .set('x-business-id', OTHER_BUSINESS.id)
        .send({
          apiKeyId: VALID_API_KEY_ID,
          apiKeySecret: VALID_API_KEY_SECRET,
        })

      expect(res.status).toBe(403)
      expect(res.body.code).toBe('BUSINESS_NOT_FOUND')
      expect(global.fetch).not.toHaveBeenCalled()
    })

    it('rejects POST request when business is suspended with 403 BUSINESS_SUSPENDED', async () => {
      vi.spyOn(businessRepository, 'getById').mockResolvedValueOnce({
        ...TEST_BUSINESS,
        suspended: true,
      } as any)

      const res = await request(app)
        .post('/api/integrations/razorpay')
        .set('Authorization', 'Bearer valid-token')
        .set('x-business-id', TEST_BUSINESS.id)
        .send({
          apiKeyId: VALID_API_KEY_ID,
          apiKeySecret: VALID_API_KEY_SECRET,
        })

      expect(res.status).toBe(403)
      expect(res.body).toEqual({
        error: 'Business suspended',
        message: 'This business account has been suspended.',
        code: 'BUSINESS_SUSPENDED',
      })
      expect(global.fetch).not.toHaveBeenCalled()
    })

    it('rejects DELETE request without Authorization header with 401 MISSING_AUTH', async () => {
      const res = await request(app)
        .delete('/api/integrations/razorpay')
        .set('x-business-id', TEST_BUSINESS.id)
        .send({ id: 'integration-123' })

      expect(res.status).toBe(401)
      expect(res.body.code).toBe('MISSING_AUTH')
    })

    it('rejects DELETE request with missing business ID with 400 MISSING_BUSINESS_ID', async () => {
      const res = await request(app)
        .delete('/api/integrations/razorpay')
        .set('Authorization', 'Bearer valid-token')
        .send({ id: 'integration-123' })

      expect(res.status).toBe(400)
      expect(res.body.code).toBe('MISSING_BUSINESS_ID')
    })
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // 3. POST /api/integrations/razorpay (Connect flow)
  // ═══════════════════════════════════════════════════════════════════════════

  describe('POST /api/integrations/razorpay (Connect)', () => {
    describe('representative invalid inputs', () => {
      it('rejects missing apiKeyId', async () => {
        const res = await request(app)
          .post('/api/integrations/razorpay')
          .set('Authorization', 'Bearer valid-token')
          .set('x-business-id', TEST_BUSINESS.id)
          .send({ apiKeySecret: VALID_API_KEY_SECRET })

        expect(res.status).toBe(400)
        expect(res.body).toEqual({
          error:
            'apiKeyId and apiKeySecret must be non-empty strings without surrounding whitespace',
        })
        expect(global.fetch).not.toHaveBeenCalled()
      })

      it('rejects missing apiKeySecret', async () => {
        const res = await request(app)
          .post('/api/integrations/razorpay')
          .set('Authorization', 'Bearer valid-token')
          .set('x-business-id', TEST_BUSINESS.id)
          .send({ apiKeyId: VALID_API_KEY_ID })

        expect(res.status).toBe(400)
        expect(res.body.error).toMatch(/without surrounding whitespace/i)
        expect(global.fetch).not.toHaveBeenCalled()
      })

      it('rejects empty string credentials', async () => {
        const res = await request(app)
          .post('/api/integrations/razorpay')
          .set('Authorization', 'Bearer valid-token')
          .set('x-business-id', TEST_BUSINESS.id)
          .send({ apiKeyId: '', apiKeySecret: '' })

        expect(res.status).toBe(400)
        expect(res.body.error).toMatch(/without surrounding whitespace/i)
        expect(global.fetch).not.toHaveBeenCalled()
      })

      it('rejects whitespace-padded apiKeyId', async () => {
        const res = await request(app)
          .post('/api/integrations/razorpay')
          .set('Authorization', 'Bearer valid-token')
          .set('x-business-id', TEST_BUSINESS.id)
          .send({
            apiKeyId: `  ${VALID_API_KEY_ID}  `,
            apiKeySecret: VALID_API_KEY_SECRET,
          })

        expect(res.status).toBe(400)
        expect(res.body.error).toMatch(/without surrounding whitespace/i)
        expect(global.fetch).not.toHaveBeenCalled()
      })

      it('rejects whitespace-padded apiKeySecret', async () => {
        const res = await request(app)
          .post('/api/integrations/razorpay')
          .set('Authorization', 'Bearer valid-token')
          .set('x-business-id', TEST_BUSINESS.id)
          .send({
            apiKeyId: VALID_API_KEY_ID,
            apiKeySecret: `${VALID_API_KEY_SECRET} `,
          })

        expect(res.status).toBe(400)
        expect(res.body.error).toMatch(/without surrounding whitespace/i)
        expect(global.fetch).not.toHaveBeenCalled()
      })

      it('rejects non-string credentials', async () => {
        const res = await request(app)
          .post('/api/integrations/razorpay')
          .set('Authorization', 'Bearer valid-token')
          .set('x-business-id', TEST_BUSINESS.id)
          .send({
            apiKeyId: 12345,
            apiKeySecret: { key: 'secret' },
          })

        expect(res.status).toBe(400)
        expect(res.body.error).toMatch(/without surrounding whitespace/i)
        expect(global.fetch).not.toHaveBeenCalled()
      })

      it('rejects credentials exceeding maximum length (256 characters)', async () => {
        const oversized = 'a'.repeat(257)
        const res = await request(app)
          .post('/api/integrations/razorpay')
          .set('Authorization', 'Bearer valid-token')
          .set('x-business-id', TEST_BUSINESS.id)
          .send({
            apiKeyId: oversized,
            apiKeySecret: VALID_API_KEY_SECRET,
          })

        expect(res.status).toBe(400)
        expect(res.body.error).toMatch(/without surrounding whitespace/i)
        expect(global.fetch).not.toHaveBeenCalled()
      })

      it('rejects credentials containing null bytes or control characters', async () => {
        const withNull = `${VALID_API_KEY_ID}\x00hack`
        const res = await request(app)
          .post('/api/integrations/razorpay')
          .set('Authorization', 'Bearer valid-token')
          .set('x-business-id', TEST_BUSINESS.id)
          .send({
            apiKeyId: withNull,
            apiKeySecret: VALID_API_KEY_SECRET,
          })

        expect(res.status).toBe(400)
        expect(res.body.error).toMatch(/without surrounding whitespace/i)
        expect(global.fetch).not.toHaveBeenCalled()
      })
    })

    describe('business context resolution', () => {
      it('accepts businessId passed in request body when x-business-id header is absent', async () => {
        const res = await request(app)
          .post('/api/integrations/razorpay')
          .set('Authorization', 'Bearer valid-token')
          .send({
            businessId: TEST_BUSINESS.id,
            apiKeyId: VALID_API_KEY_ID,
            apiKeySecret: VALID_API_KEY_SECRET,
          })

        expect(res.status).toBe(201)
        expect(res.body.businessId).toBe(TEST_BUSINESS.id)
      })

      it('accepts business_id (snake_case) in request body', async () => {
        const res = await request(app)
          .post('/api/integrations/razorpay')
          .set('Authorization', 'Bearer valid-token')
          .send({
            business_id: TEST_BUSINESS.id,
            apiKeyId: VALID_API_KEY_ID,
            apiKeySecret: VALID_API_KEY_SECRET,
          })

        expect(res.status).toBe(201)
        expect(res.body.businessId).toBe(TEST_BUSINESS.id)
      })
    })

    describe('upstream verification and primary state transitions', () => {
      it('successfully connects Razorpay and returns sanitized record (201)', async () => {
        const res = await request(app)
          .post('/api/integrations/razorpay')
          .set('Authorization', 'Bearer valid-token')
          .set('x-business-id', TEST_BUSINESS.id)
          .send({
            apiKeyId: VALID_API_KEY_ID,
            apiKeySecret: VALID_API_KEY_SECRET,
          })

        expect(res.status).toBe(201)
        expect(res.body).toHaveProperty('id')
        expect(res.body.provider).toBe('razorpay')
        expect(res.body.userId).toBe(TEST_USER.userId)
        expect(res.body.businessId).toBe(TEST_BUSINESS.id)
        expect(res.body.meta.apiKeyId).toBe(VALID_API_KEY_ID)
        expect(res.body.meta.apiKeySecret).toBe('*****') // Masked
        expect(res.body.meta.credentialFingerprint).toMatch(/^[a-f0-9]{64}$/)
        expect(res.body.meta.verifiedAt).toBeDefined()

        // Verify upstream call parameters
        const expectedBasicAuth = Buffer.from(
          `${VALID_API_KEY_ID}:${VALID_API_KEY_SECRET}`,
        ).toString('base64')
        expect(global.fetch).toHaveBeenCalledWith(
          'https://api.razorpay.com/v1/payments?count=1',
          expect.objectContaining({
            headers: {
              Authorization: `Basic ${expectedBasicAuth}`,
              Accept: 'application/json',
            },
            signal: expect.any(AbortSignal),
          }),
        )

        // Verify underlying storage contains raw secret
        const stored = integrationRepository.findById(res.body.id)
        expect(stored).not.toBeNull()
        expect(stored!.meta.apiKeySecret).toBe(VALID_API_KEY_SECRET)
      })

      it('returns 409 Conflict if Razorpay is already connected for this business', async () => {
        // First connection succeeds
        const first = await request(app)
          .post('/api/integrations/razorpay')
          .set('Authorization', 'Bearer valid-token')
          .set('x-business-id', TEST_BUSINESS.id)
          .send({
            apiKeyId: VALID_API_KEY_ID,
            apiKeySecret: VALID_API_KEY_SECRET,
          })
        expect(first.status).toBe(201)

        // Second connection for same business returns 409
        const second = await request(app)
          .post('/api/integrations/razorpay')
          .set('Authorization', 'Bearer valid-token')
          .set('x-business-id', TEST_BUSINESS.id)
          .send({
            apiKeyId: 'rzp_test_another_key',
            apiKeySecret: 'secret_another_key_val',
          })

        expect(second.status).toBe(409)
        expect(second.body).toEqual({
          error: 'Razorpay integration already connected',
        })
        expect(global.fetch).toHaveBeenCalledTimes(1) // Not called for the duplicate attempt
      })

      it('allows different businesses to connect independent Razorpay credentials', async () => {
        const resA = await request(app)
          .post('/api/integrations/razorpay')
          .set('Authorization', 'Bearer valid-token')
          .set('x-business-id', TEST_BUSINESS.id)
          .send({
            apiKeyId: VALID_API_KEY_ID,
            apiKeySecret: VALID_API_KEY_SECRET,
          })
        expect(resA.status).toBe(201)

        const resB = await request(app)
          .post('/api/integrations/razorpay')
          .set('Authorization', 'Bearer other-user-token')
          .set('x-business-id', OTHER_BUSINESS.id)
          .send({
            apiKeyId: 'rzp_test_biz_2_key_id',
            apiKeySecret: 'secret_biz_2_secret_id',
          })
        expect(resB.status).toBe(201)

        expect(integrationRepository.listByBusiness(TEST_BUSINESS.id)).toHaveLength(1)
        expect(integrationRepository.listByBusiness(OTHER_BUSINESS.id)).toHaveLength(1)
      })

      it('returns 400 when upstream Razorpay responds with 401 without leaking internal details', async () => {
        vi.mocked(global.fetch).mockResolvedValueOnce(
          jsonResponse(401, {
            error: {
              code: 'BAD_REQUEST_ERROR',
              description: 'The key/secret provided is invalid',
            },
          }),
        )

        const res = await request(app)
          .post('/api/integrations/razorpay')
          .set('Authorization', 'Bearer valid-token')
          .set('x-business-id', TEST_BUSINESS.id)
          .send({
            apiKeyId: VALID_API_KEY_ID,
            apiKeySecret: VALID_API_KEY_SECRET,
          })

        expect(res.status).toBe(400)
        expect(res.body).toEqual({ error: 'Invalid Razorpay credentials' })
        expect(JSON.stringify(res.body)).not.toMatch(/BAD_REQUEST_ERROR/i)
      })

      it('returns 400 when upstream Razorpay responds with 403', async () => {
        vi.mocked(global.fetch).mockResolvedValueOnce(
          jsonResponse(403, { error: 'Forbidden' }),
        )

        const res = await request(app)
          .post('/api/integrations/razorpay')
          .set('Authorization', 'Bearer valid-token')
          .set('x-business-id', TEST_BUSINESS.id)
          .send({
            apiKeyId: VALID_API_KEY_ID,
            apiKeySecret: VALID_API_KEY_SECRET,
          })

        expect(res.status).toBe(400)
        expect(res.body).toEqual({ error: 'Invalid Razorpay credentials' })
      })

      it('returns 502 when upstream Razorpay returns 500 error', async () => {
        vi.mocked(global.fetch).mockResolvedValue(
          jsonResponse(500, { error: 'Internal Server Error' }),
        )

        const res = await request(app)
          .post('/api/integrations/razorpay')
          .set('Authorization', 'Bearer valid-token')
          .set('x-business-id', TEST_BUSINESS.id)
          .send({
            apiKeyId: VALID_API_KEY_ID,
            apiKeySecret: VALID_API_KEY_SECRET,
          })

        expect(res.status).toBe(502)
        expect(res.body).toEqual({
          error: 'Razorpay credential verification failed',
        })
      })

      it('returns 502 when upstream Razorpay returns unexpected JSON format', async () => {
        vi.mocked(global.fetch).mockResolvedValue(
          jsonResponse(200, { success: true, count: 0 }), // Missing entity: "collection" and items array
        )

        const res = await request(app)
          .post('/api/integrations/razorpay')
          .set('Authorization', 'Bearer valid-token')
          .set('x-business-id', TEST_BUSINESS.id)
          .send({
            apiKeyId: VALID_API_KEY_ID,
            apiKeySecret: VALID_API_KEY_SECRET,
          })

        expect(res.status).toBe(502)
        expect(res.body).toEqual({
          error: 'Unexpected Razorpay verification response',
        })
      })

      it('returns 502 when fetch throws a network / connection error', async () => {
        vi.mocked(global.fetch).mockRejectedValue(new Error('ECONNRESET'))

        const res = await request(app)
          .post('/api/integrations/razorpay')
          .set('Authorization', 'Bearer valid-token')
          .set('x-business-id', TEST_BUSINESS.id)
          .send({
            apiKeyId: VALID_API_KEY_ID,
            apiKeySecret: VALID_API_KEY_SECRET,
          })

        expect(res.status).toBe(502)
        expect(res.body).toEqual({ error: 'Failed to reach Razorpay API' })
      })

      it('returns 503 when the global outbound retry budget is exhausted', async () => {
        const error = Object.create(GlobalRetryBudgetExceededError.prototype)
        error.message = 'Global outbound retry budget exhausted'
        vi.spyOn(clientWrapper, 'executeWithRetry').mockRejectedValueOnce(error)

        const res = await request(app)
          .post('/api/integrations/razorpay')
          .set('Authorization', 'Bearer valid-token')
          .set('x-business-id', TEST_BUSINESS.id)
          .send({
            apiKeyId: VALID_API_KEY_ID,
            apiKeySecret: VALID_API_KEY_SECRET,
          })

        expect(res.status).toBe(503)
        expect(res.body).toEqual({
          error: 'Global outbound retry budget exhausted',
        })
      })
    })
  })

  // ═══════════════════════════════════════════════════════════════════════════
  // 4. DELETE /api/integrations/razorpay (Disconnect flow)
  // ═══════════════════════════════════════════════════════════════════════════

  describe('DELETE /api/integrations/razorpay (Disconnect)', () => {
    describe('representative invalid inputs', () => {
      it('rejects request with missing id in body (400)', async () => {
        const res = await request(app)
          .delete('/api/integrations/razorpay')
          .set('Authorization', 'Bearer valid-token')
          .set('x-business-id', TEST_BUSINESS.id)
          .send({})

        expect(res.status).toBe(400)
        expect(res.body).toEqual({ error: 'id is required' })
      })

      it('returns 404 when integration id does not exist in store', async () => {
        const res = await request(app)
          .delete('/api/integrations/razorpay')
          .set('Authorization', 'Bearer valid-token')
          .set('x-business-id', TEST_BUSINESS.id)
          .send({ id: 'non-existent-integration-id' })

        expect(res.status).toBe(404)
        expect(res.body).toEqual({ error: 'Integration not found' })
      })

      it('returns 404 when integration belongs to a different provider (e.g. stripe)', async () => {
        const stripeRecord = integrationRepository.create({
          provider: 'stripe',
          userId: TEST_USER.userId,
          businessId: TEST_BUSINESS.id,
          meta: { accountId: 'acct_123' },
        })

        const res = await request(app)
          .delete('/api/integrations/razorpay')
          .set('Authorization', 'Bearer valid-token')
          .set('x-business-id', TEST_BUSINESS.id)
          .send({ id: stripeRecord.id })

        expect(res.status).toBe(404)
        expect(res.body).toEqual({ error: 'Integration not found' })
        expect(integrationRepository.findById(stripeRecord.id)).not.toBeNull()
      })

      it('returns 404 when integration belongs to a different business (cross-tenant isolation)', async () => {
        const otherBizRecord = integrationRepository.create({
          provider: 'razorpay',
          userId: OTHER_USER.userId,
          businessId: OTHER_BUSINESS.id,
          meta: { apiKeyId: 'other-key' },
        })

        // TEST_BUSINESS attempts to delete OTHER_BUSINESS's integration
        const res = await request(app)
          .delete('/api/integrations/razorpay')
          .set('Authorization', 'Bearer valid-token')
          .set('x-business-id', TEST_BUSINESS.id)
          .send({ id: otherBizRecord.id })

        expect(res.status).toBe(404)
        expect(res.body).toEqual({ error: 'Integration not found' })
        expect(integrationRepository.findById(otherBizRecord.id)).not.toBeNull()
      })
    })

    describe('primary state transitions & failure handling', () => {
      it('successfully disconnects an existing Razorpay integration (200)', async () => {
        const created = integrationRepository.create({
          provider: 'razorpay',
          userId: TEST_USER.userId,
          businessId: TEST_BUSINESS.id,
          meta: { apiKeyId: VALID_API_KEY_ID },
        })

        const res = await request(app)
          .delete('/api/integrations/razorpay')
          .set('Authorization', 'Bearer valid-token')
          .set('x-business-id', TEST_BUSINESS.id)
          .send({ id: created.id })

        expect(res.status).toBe(200)
        expect(res.body).toEqual({ message: 'ok' })
        expect(integrationRepository.findById(created.id)).toBeNull()
      })

      it('returns 500 when repository deleteById returns false', async () => {
        const created = integrationRepository.create({
          provider: 'razorpay',
          userId: TEST_USER.userId,
          businessId: TEST_BUSINESS.id,
          meta: { apiKeyId: VALID_API_KEY_ID },
        })

        vi.spyOn(integrationRepository, 'deleteById').mockReturnValueOnce(false)

        const res = await request(app)
          .delete('/api/integrations/razorpay')
          .set('Authorization', 'Bearer valid-token')
          .set('x-business-id', TEST_BUSINESS.id)
          .send({ id: created.id })

        expect(res.status).toBe(500)
        expect(res.body).toEqual({ error: 'Failed to delete integration' })
      })

      it('executes the full connect -> reconnect-blocked -> disconnect -> reconnect state lifecycle', async () => {
        // Step 1: Connect
        const connectRes = await request(app)
          .post('/api/integrations/razorpay')
          .set('Authorization', 'Bearer valid-token')
          .set('x-business-id', TEST_BUSINESS.id)
          .send({
            apiKeyId: VALID_API_KEY_ID,
            apiKeySecret: VALID_API_KEY_SECRET,
          })
        expect(connectRes.status).toBe(201)
        const integrationId = connectRes.body.id

        // Step 2: Attempting duplicate connect is blocked (409)
        const duplicateRes = await request(app)
          .post('/api/integrations/razorpay')
          .set('Authorization', 'Bearer valid-token')
          .set('x-business-id', TEST_BUSINESS.id)
          .send({
            apiKeyId: VALID_API_KEY_ID,
            apiKeySecret: VALID_API_KEY_SECRET,
          })
        expect(duplicateRes.status).toBe(409)

        // Step 3: Disconnect
        const disconnectRes = await request(app)
          .delete('/api/integrations/razorpay')
          .set('Authorization', 'Bearer valid-token')
          .set('x-business-id', TEST_BUSINESS.id)
          .send({ id: integrationId })
        expect(disconnectRes.status).toBe(200)

        // Step 4: Repeating disconnect returns 404 (already deleted)
        const repeatDisconnectRes = await request(app)
          .delete('/api/integrations/razorpay')
          .set('Authorization', 'Bearer valid-token')
          .set('x-business-id', TEST_BUSINESS.id)
          .send({ id: integrationId })
        expect(repeatDisconnectRes.status).toBe(404)

        // Step 5: Can connect again after disconnection
        const reconnectRes = await request(app)
          .post('/api/integrations/razorpay')
          .set('Authorization', 'Bearer valid-token')
          .set('x-business-id', TEST_BUSINESS.id)
          .send({
            apiKeyId: VALID_API_KEY_ID,
            apiKeySecret: VALID_API_KEY_SECRET,
          })
        expect(reconnectRes.status).toBe(201)
        expect(reconnectRes.body.id).not.toBe(integrationId)
      })
    })
  })
})
