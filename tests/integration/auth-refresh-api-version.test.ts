/**
 * Integration tests: refresh behavior respects API versioning middleware expectations.
 *
 * Coverage:
 * - Default version negotiation (no signal → v1)
 * - X-API-Version header
 * - Accept-Version header
 * - Query parameter (apiVersion)
 * - Accept header parameter (version=)
 * - Unsupported-major fallback (API-Version-Fallback: true)
 * - Vary header presence on all responses
 * - Error-path coverage (missing/invalid token still carries version headers)
 * - Token rotation works correctly under negotiated version
 *
 * Assumptions:
 * - app.ts mounts apiVersionMiddleware + versionResponseMiddleware globally.
 * - auth router is mounted at /api/auth.
 * - refresh service uses in-memory userRepository and jwt utils.
 */

import { describe, it, expect, afterAll, beforeEach } from 'vitest'
import request from 'supertest'
import { app } from '../../src/app.js'
import { clearUsedRefreshTokens } from '../../src/services/auth/refresh.js'
import { clearAllUsers } from '../../src/repositories/userRepository.js'

const testUser = {
  email: 'refresh-test@example.com',
  password: 'SecurePass123!',
  name: 'Refresh Test User',
}

/**
 * Extracts API-Version and related headers from a Supertest response.
 */
function getVersionHeaders(res: request.Response) {
  return {
    apiVersion: res.headers['api-version'] as string | undefined,
    apiVersionFallback: res.headers['api-version-fallback'] as string | undefined,
    vary: (res.headers.vary ?? '') as string,
  }
}

describe('POST /api/auth/refresh — API version negotiation', () => {
  beforeEach(() => {
    clearAllUsers()
    clearUsedRefreshTokens()
  })

  afterAll(() => {
    clearAllUsers()
    clearUsedRefreshTokens()
  })

  // ---------------------------------------------------------------------------
  // Helper: signup and capture refresh token
  // ---------------------------------------------------------------------------
  async function signupAndGetRefreshToken(): Promise<string> {
    const signupRes = await request(app)
      .post('/api/auth/signup')
      .send(testUser)

    // If signup is rate-limited or returns 201, handle both paths
    if (signupRes.status === 201) {
      return signupRes.body.refreshToken as string
    }

    // Fallback: try login if user already exists from a leaked state
    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({ email: testUser.email, password: testUser.password })

    expect(loginRes.status).toBe(200)
    return loginRes.body.refreshToken as string
  }

  // =========================================================================
  // Success-path version negotiation
  // =========================================================================

  it('responds with API-Version v1 when no version signal is provided (default)', async () => {
    const refreshToken = await signupAndGetRefreshToken()

    const res = await request(app)
      .post('/api/auth/refresh')
      .send({ refreshToken })

    expect(res.status).toBe(200)
    const headers = getVersionHeaders(res)
    expect(headers.apiVersion).toBe('v1')
    expect(headers.apiVersionFallback).toBeUndefined()
  })

  it('honors X-API-Version: 1 without fallback on success', async () => {
    const refreshToken = await signupAndGetRefreshToken()

    const res = await request(app)
      .post('/api/auth/refresh')
      .set('X-API-Version', '1')
      .send({ refreshToken })

    expect(res.status).toBe(200)
    const headers = getVersionHeaders(res)
    expect(headers.apiVersion).toBe('v1')
    expect(headers.apiVersionFallback).toBeUndefined()
  })

  it('honors Accept-Version: 1 without fallback on success', async () => {
    const refreshToken = await signupAndGetRefreshToken()

    const res = await request(app)
      .post('/api/auth/refresh')
      .set('Accept-Version', '1')
      .send({ refreshToken })

    expect(res.status).toBe(200)
    const headers = getVersionHeaders(res)
    expect(headers.apiVersion).toBe('v1')
    expect(headers.apiVersionFallback).toBeUndefined()
  })

  it('honors query parameter apiVersion=1 without fallback', async () => {
    const refreshToken = await signupAndGetRefreshToken()

    const res = await request(app)
      .post('/api/auth/refresh?apiVersion=1')
      .send({ refreshToken })

    expect(res.status).toBe(200)
    const headers = getVersionHeaders(res)
    expect(headers.apiVersion).toBe('v1')
    expect(headers.apiVersionFallback).toBeUndefined()
  })

  it('honors Accept header parameter version=1 without fallback', async () => {
    const refreshToken = await signupAndGetRefreshToken()

    const res = await request(app)
      .post('/api/auth/refresh')
      .set('Accept', 'application/json; version=1')
      .send({ refreshToken })

    expect(res.status).toBe(200)
    const headers = getVersionHeaders(res)
    expect(headers.apiVersion).toBe('v1')
    expect(headers.apiVersionFallback).toBeUndefined()
  })

  it('falls back to v1 with API-Version-Fallback when unsupported major is requested', async () => {
    const refreshToken = await signupAndGetRefreshToken()

    const res = await request(app)
      .post('/api/auth/refresh')
      .set('X-API-Version', '99')
      .send({ refreshToken })

    expect(res.status).toBe(200)
    const headers = getVersionHeaders(res)
    expect(headers.apiVersion).toBe('v1')
    expect(headers.apiVersionFallback).toBe('true')
  })

  // =========================================================================
  // Cache correctness — Vary header
  // =========================================================================

  it('includes Vary header containing Accept and X-API-Version on success', async () => {
    const refreshToken = await signupAndGetRefreshToken()

    const res = await request(app)
      .post('/api/auth/refresh')
      .set('X-API-Version', '1')
      .send({ refreshToken })

    const headers = getVersionHeaders(res)
    const varyLower = headers.vary.toLowerCase()
    expect(varyLower).toContain('accept')
    expect(varyLower).toContain('x-api-version')
  })

  it('includes Vary header on error responses', async () => {
    const res = await request(app)
      .post('/api/auth/refresh')
      .set('X-API-Version', '1')
      .send({}) // missing refreshToken

    expect(res.status).toBe(401)
    const headers = getVersionHeaders(res)
    const varyLower = headers.vary.toLowerCase()
    expect(varyLower).toContain('accept')
    expect(varyLower).toContain('x-api-version')
  })

  // =========================================================================
  // Error-path version coverage
  // =========================================================================

  it('carries API-Version v1 on missing refresh token error', async () => {
    const res = await request(app)
      .post('/api/auth/refresh')
      .send({})

    expect(res.status).toBe(401)
    const headers = getVersionHeaders(res)
    expect(headers.apiVersion).toBe('v1')
  })

  it('carries API-Version v1 on invalid refresh token error', async () => {
    const res = await request(app)
      .post('/api/auth/refresh')
      .set('Accept-Version', '1')
      .send({ refreshToken: 'totally-invalid-token' })

    expect(res.status).toBe(401)
    const headers = getVersionHeaders(res)
    expect(headers.apiVersion).toBe('v1')
  })

  it('carries API-Version-Fallback on error when unsupported major requested', async () => {
    const res = await request(app)
      .post('/api/auth/refresh')
      .set('X-API-Version', '999')
      .send({ refreshToken: 'invalid' })

    expect(res.status).toBe(401)
    const headers = getVersionHeaders(res)
    expect(headers.apiVersion).toBe('v1')
    expect(headers.apiVersionFallback).toBe('true')
  })

  // =========================================================================
  // Token rotation works under version negotiation
  // =========================================================================

  it('rotates tokens successfully when version is negotiated via X-API-Version header', async () => {
    const originalRefreshToken = await signupAndGetRefreshToken()

    const res = await request(app)
      .post('/api/auth/refresh')
      .set('X-API-Version', '1')
      .send({ refreshToken: originalRefreshToken })

    expect(res.status).toBe(200)
    expect(res.body).toHaveProperty('accessToken')
    expect(res.body).toHaveProperty('refreshToken')
    expect(res.body.refreshToken).not.toBe(originalRefreshToken)

    // Old token is invalidated
    const replayRes = await request(app)
      .post('/api/auth/refresh')
      .set('X-API-Version', '1')
      .send({ refreshToken: originalRefreshToken })

    expect(replayRes.status).toBe(401)
  })

  it('rotates tokens successfully when version is negotiated via Accept header', async () => {
    const originalRefreshToken = await signupAndGetRefreshToken()

    const res = await request(app)
      .post('/api/auth/refresh')
      .set('Accept', 'application/json; version=1')
      .send({ refreshToken: originalRefreshToken })

    expect(res.status).toBe(200)
    expect(res.body).toHaveProperty('accessToken')
    expect(res.body).toHaveProperty('refreshToken')
    expect(res.body.refreshToken).not.toBe(originalRefreshToken)
  })

  it('rotates tokens successfully with fallback version negotiation', async () => {
    const originalRefreshToken = await signupAndGetRefreshToken()

    const res = await request(app)
      .post('/api/auth/refresh')
      .set('X-API-Version', '99')
      .send({ refreshToken: originalRefreshToken })

    expect(res.status).toBe(200)
    const headers = getVersionHeaders(res)
    expect(headers.apiVersion).toBe('v1')
    expect(headers.apiVersionFallback).toBe('true')
    expect(res.body).toHaveProperty('accessToken')
    expect(res.body).toHaveProperty('refreshToken')
    expect(res.body.refreshToken).not.toBe(originalRefreshToken)
  })
})

