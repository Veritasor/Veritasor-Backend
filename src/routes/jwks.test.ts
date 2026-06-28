import { beforeEach, describe, expect, it, afterEach } from 'vitest'
import request from 'supertest'
import { generateKeyPairSync } from 'node:crypto'
import jwt from 'jsonwebtoken'
import { app } from './app.js'
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
      algorithm: 'EdDSA',
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
})
