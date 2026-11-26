import { beforeEach, describe, expect, it, afterEach } from 'vitest'
import request from 'supertest'
import { generateKeyPairSync } from 'node:crypto'
import jwt from 'jsonwebtoken'
import { app } from '../app.js'
import { jwksManager } from '../utils/jwks.js'
import { secretLoader } from '../utils/secret-loader.js'
import { verifyToken } from '../utils/jwt.js'

const ORIGINAL_ENV = { ...process.env }

function restoreEnv() {
  for (const key of Object.keys(process.env)) {
    if (!(key in ORIGINAL_ENV)) {
      delete process.env[key]
    }
  }
  for (const [key, value] of Object.entries(ORIGINAL_ENV)) {
    process.env[key] = value
  }
}

describe('JWKS endpoint and token verification', () => {
  beforeEach(async () => {
    restoreEnv()
    delete process.env.JWT_PRIVATE_KEY
    delete process.env.JWT_PUBLIC_JWKS
    delete process.env.JWT_JWKS_CACHE_TTL_SECONDS
    delete process.env.JWT_JWKS_GRACE_WINDOW_SECONDS
    delete process.env.JWT_SIGNING_ALGORITHM
    await secretLoader.reload()
  })

  afterEach(() => {
    restoreEnv()
  })

  it('publishes a JWKS document with cache headers', async () => {
    const { privateKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    })

    process.env.JWT_PRIVATE_KEY = privateKey
    process.env.JWT_JWKS_CACHE_TTL_SECONDS = '123'
    await secretLoader.reload()
    await jwksManager.reload()

    const res = await request(app).get('/.well-known/jwks.json')

    expect(res.status).toBe(200)
    expect(res.headers['cache-control']).toContain('max-age=123')
    expect(res.headers.etag).toBeDefined()
    expect(Array.isArray(res.body.keys)).toBe(true)
    expect(res.body.keys).toHaveLength(1)
    expect(res.body.keys[0]).toHaveProperty('kty', 'RSA')
    expect(res.body.keys[0]).toHaveProperty('kid')
  })

  it('verifies RS256 tokens using the published JWKS key', async () => {
    const { privateKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    })

    process.env.JWT_PRIVATE_KEY = privateKey
    await secretLoader.reload()
    await jwksManager.reload()

    const token = jwt.sign({ userId: 'u1', email: 'test@example.com' }, privateKey, {
      algorithm: 'RS256',
      expiresIn: '1h',
      issuer: 'veritasor-api',
      audience: 'veritasor-client',
      keyid: jwksManager.getSigningKey()?.kid,
    })

    expect(verifyToken(token)).not.toBeNull()
  })

  it('verifies EdDSA tokens using the published JWKS key', async () => {
    const { privateKey } = generateKeyPairSync('ed25519', {
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    })

    process.env.JWT_PRIVATE_KEY = privateKey
    process.env.JWT_SIGNING_ALGORITHM = 'EdDSA'
    await secretLoader.reload()
    await jwksManager.reload()

    const token = jwt.sign({ userId: 'u2', email: 'eds@example.com' }, privateKey, {
      algorithm: 'EdDSA' as jwt.Algorithm,
      expiresIn: '1h',
      issuer: 'veritasor-api',
      audience: 'veritasor-client',
      keyid: jwksManager.getSigningKey()?.kid,
    })

    expect(verifyToken(token)).not.toBeNull()
    const decoded = jwt.decode(token, { complete: true }) as any
    expect(decoded.header.alg).toBe('EdDSA')
  })

  it('rejects old tokens after the JWKS grace window expires', async () => {
    const { privateKey: firstPrivateKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    })

    process.env.JWT_PRIVATE_KEY = firstPrivateKey
    process.env.JWT_JWKS_GRACE_WINDOW_SECONDS = '1'
    await secretLoader.reload()
    await jwksManager.reload()

    const oldToken = jwt.sign({ userId: 'u3', email: 'old@example.com' }, firstPrivateKey, {
      algorithm: 'RS256',
      expiresIn: '1h',
      issuer: 'veritasor-api',
      audience: 'veritasor-client',
      keyid: jwksManager.getSigningKey()?.kid,
    })

    const { privateKey: nextPrivateKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    })

    process.env.JWT_PRIVATE_KEY = nextPrivateKey
    process.env.JWT_PUBLIC_JWKS = '[]'
    await secretLoader.reload()
    await jwksManager.reload()

    expect(verifyToken(oldToken)).not.toBeNull()

    await new Promise((resolve) => setTimeout(resolve, 1100))

    expect(verifyToken(oldToken)).toBeNull()
  })

  describe('ETag caching', () => {
    it('returns 304 with no body when If-None-Match matches current ETag', async () => {
      const { privateKey } = generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      })

      process.env.JWT_PRIVATE_KEY = privateKey
      await secretLoader.reload()
      await jwksManager.reload()

      // First request to get the ETag
      const res1 = await request(app).get('/.well-known/jwks.json')
      expect(res1.status).toBe(200)
      expect(res1.headers.etag).toBeDefined()

      const etag = res1.headers.etag

      // Second request with matching If-None-Match
      const res2 = await request(app)
        .get('/.well-known/jwks.json')
        .set('If-None-Match', etag)

      expect(res2.status).toBe(304)
      expect(res2.headers.etag).toBe(etag)
      expect(res2.headers['cache-control']).toBeDefined()
      expect(res2.body).toEqual({})
    })

    it('returns 200 with body when If-None-Match does not match', async () => {
      const { privateKey } = generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      })

      process.env.JWT_PRIVATE_KEY = privateKey
      await secretLoader.reload()
      await jwksManager.reload()

      const res = await request(app)
        .get('/.well-known/jwks.json')
        .set('If-None-Match', '"invalid-etag"')

      expect(res.status).toBe(200)
      expect(res.headers.etag).toBeDefined()
      expect(Array.isArray(res.body.keys)).toBe(true)
      expect(res.body.keys).toHaveLength(1)
    })

    it('returns 200 with body when If-None-Match header is absent', async () => {
      const { privateKey } = generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      })

      process.env.JWT_PRIVATE_KEY = privateKey
      await secretLoader.reload()
      await jwksManager.reload()

      const res = await request(app).get('/.well-known/jwks.json')

      expect(res.status).toBe(200)
      expect(res.headers.etag).toBeDefined()
      expect(Array.isArray(res.body.keys)).toBe(true)
      expect(res.body.keys).toHaveLength(1)
    })

    it('handles comma-separated ETag values in If-None-Match', async () => {
      const { privateKey } = generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      })

      process.env.JWT_PRIVATE_KEY = privateKey
      await secretLoader.reload()
      await jwksManager.reload()

      // First request to get the ETag
      const res1 = await request(app).get('/.well-known/jwks.json')
      const etag = res1.headers.etag

      // Second request with matching ETag in a comma-separated list
      const res2 = await request(app)
        .get('/.well-known/jwks.json')
        .set('If-None-Match', `"wrong-etag", ${etag}, "another-wrong-etag"`)

      expect(res2.status).toBe(304)
      expect(res2.body).toEqual({})
    })

    it('handles weak ETag comparison (W/ prefix)', async () => {
      const { privateKey } = generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      })

      process.env.JWT_PRIVATE_KEY = privateKey
      await secretLoader.reload()
      await jwksManager.reload()

      // First request to get the ETag
      const res1 = await request(app).get('/.well-known/jwks.json')
      const etag = res1.headers.etag

      // Strip W/ prefix if present to test weak comparison
      const strippedEtag = etag.startsWith('W/') ? etag.slice(2) : etag

      // Second request with weak ETag
      const res2 = await request(app)
        .get('/.well-known/jwks.json')
        .set('If-None-Match', `W/${strippedEtag}`)

      expect(res2.status).toBe(304)
      expect(res2.body).toEqual({})
    })

    it('ensures Cache-Control is identical in both 200 and 304 responses', async () => {
      const { privateKey } = generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      })

      process.env.JWT_PRIVATE_KEY = privateKey
      process.env.JWT_JWKS_CACHE_TTL_SECONDS = '300'
      await secretLoader.reload()
      await jwksManager.reload()

      // First request (200)
      const res1 = await request(app).get('/.well-known/jwks.json')
      expect(res1.status).toBe(200)
      const cacheControl200 = res1.headers['cache-control']
      const etag = res1.headers.etag

      // Second request with matching ETag (304)
      const res2 = await request(app)
        .get('/.well-known/jwks.json')
        .set('If-None-Match', etag)

      expect(res2.status).toBe(304)
      expect(res2.headers['cache-control']).toBe(cacheControl200)
    })
  })
})
