import crypto from 'node:crypto'
import { secretLoader, SecretNotFoundError } from './secret-loader.js'
import { logger } from './logger.js'

export type JwksKey = {
  kty: 'RSA' | 'OKP'
  use: 'sig'
  alg: 'RS256' | 'EdDSA'
  kid: string
  [key: string]: unknown
}

export interface JwksResponse {
  keys: JwksKey[]
}

interface KeyBundle {
  kid: string
  alg: 'RS256' | 'EdDSA'
  publicJwk: JwksKey
  publicKey: crypto.KeyObject
  privateKey?: crypto.KeyObject
}

interface RetiredKeyBundle {
  bundle: KeyBundle
  retireAt: number
}

const DEFAULT_CACHE_TTL_SECONDS = 300
const DEFAULT_GRACE_WINDOW_SECONDS = 300
const DEFAULT_SIGNING_ALGORITHM: 'RS256' | 'EdDSA' = 'RS256'
const SUPPORTED_ALGORITHMS = ['RS256', 'EdDSA'] as const

type SupportedAlgorithm = (typeof SUPPORTED_ALGORITHMS)[number]

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function normalizeJwkValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(normalizeJwkValue)
  }
  if (isObject(value)) {
    return Object.keys(value)
      .sort()
      .reduce<Record<string, unknown>>((accumulator, key) => {
        accumulator[key] = normalizeJwkValue(value[key])
        return accumulator
      }, {})
  }
  return value
}

function computeKid(jwk: Record<string, unknown>): string {
  const normalized = normalizeJwkValue(jwk)
  const hash = crypto.createHash('sha256').update(JSON.stringify(normalized)).digest('base64url')
  return hash
}

function parseJsonSecret(secret: string): unknown {
  try {
    return JSON.parse(secret)
  } catch {
    return secret
  }
}

function determineAlgorithmFromJwk(jwk: JwksKey): SupportedAlgorithm {
  const alg = jwk.alg?.toString()
  if (alg === 'RS256' || alg === 'EdDSA') {
    return alg
  }

  if (jwk.kty === 'RSA') {
    return 'RS256'
  }

  if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519') {
    return 'EdDSA'
  }

  throw new Error(`Unsupported JWK type ${jwk.kty} / curve ${jwk.crv ?? 'unknown'}`)
}

function normalizeJwk(jwk: JwksKey): JwksKey {
  const normalized = {
    ...jwk,
    use: jwk.use ?? 'sig',
    alg: jwk.alg ?? determineAlgorithmFromJwk(jwk),
    kty: jwk.kty,
  } as JwksKey

  if (!normalized.kid || typeof normalized.kid !== 'string' || normalized.kid.trim() === '') {
    normalized.kid = computeKid(normalized)
  }

  return normalized
}

function parseJwksFromSecret(value: string): JwksKey[] {
  const parsed = parseJsonSecret(value)
  if (!Array.isArray(parsed)) {
    throw new Error('JWT_PUBLIC_JWKS must be a JSON array of JWK objects')
  }
  return parsed.map((entry) => {
    if (!isObject(entry)) {
      throw new Error('Each entry in JWT_PUBLIC_JWKS must be an object')
    }
    const jwk = normalizeJwk(entry as JwksKey)
    if (!jwk.kid) throw new Error('JWK entries must include a kid')
    return jwk
  })
}

function parsePrivateKeySecret(raw: unknown): crypto.KeyObject {
  if (isObject(raw) && 'kty' in raw) {
    return crypto.createPrivateKey({ key: raw as Record<string, unknown>, format: 'jwk' })
  }

  if (typeof raw === 'string') {
    const parsed = parseJsonSecret(raw)
    if (isObject(parsed) && 'kty' in parsed) {
      return crypto.createPrivateKey({ key: parsed as Record<string, unknown>, format: 'jwk' })
    }
    return crypto.createPrivateKey({ key: raw, format: 'pem' })
  }

  throw new Error('Unsupported JWT_PRIVATE_KEY format')
}

function exportPublicJwk(publicKey: crypto.KeyObject, alg: SupportedAlgorithm, kid?: string): JwksKey {
  const jwk = publicKey.export({ format: 'jwk' }) as Record<string, unknown>
  const publicJwk: JwksKey = {
    ...jwk,
    use: 'sig',
    alg,
    kid: (kid && kid.trim()) || (typeof jwk.kid === 'string' && jwk.kid.trim()) || computeKid(jwk),
  } as JwksKey
  return normalizeJwk(publicJwk)
}

function createKeyBundleFromPrivateKey(secret: string): KeyBundle {
  const keyObject = parsePrivateKeySecret(parseJsonSecret(secret))
  const asymmetricKeyType = keyObject.asymmetricKeyType
  const algorithm = (process.env.JWT_SIGNING_ALGORITHM?.toUpperCase() as SupportedAlgorithm) ??
    (asymmetricKeyType === 'ed25519' ? 'EdDSA' : 'RS256')

  if (!SUPPORTED_ALGORITHMS.includes(algorithm)) {
    throw new Error(`Unsupported JWT signing algorithm: ${algorithm}`)
  }

  const publicKey = crypto.createPublicKey(keyObject)
  const kidFromSecret = (() => {
    try {
      return secretLoader.get('JWT_PRIVATE_KEY_KID')
    } catch (error) {
      if (error instanceof SecretNotFoundError) {
        return undefined
      }
      throw error
    }
  })()

  const publicJwk = exportPublicJwk(publicKey, algorithm, kidFromSecret)

  return {
    kid: publicJwk.kid,
    alg: algorithm,
    publicJwk,
    publicKey,
    privateKey: keyObject,
  }
}

function generateFallbackSigningKey(): KeyBundle {
  const requestedAlgorithm = (process.env.JWT_SIGNING_ALGORITHM?.toUpperCase() as SupportedAlgorithm) ?? DEFAULT_SIGNING_ALGORITHM

  if (requestedAlgorithm === 'RS256') {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicExponent: 0x10001,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    })
    const privateKeyObject = crypto.createPrivateKey({ key: privateKey, format: 'pem' })
    const publicKeyObject = crypto.createPublicKey({ key: publicKey, format: 'pem' })
    const publicJwk = exportPublicJwk(publicKeyObject, 'RS256')
    return {
      kid: publicJwk.kid,
      alg: 'RS256',
      publicJwk,
      publicKey: publicKeyObject,
      privateKey: privateKeyObject,
    }
  }

  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  })
  const privateKeyObject = crypto.createPrivateKey({ key: privateKey, format: 'pem' })
  const publicKeyObject = crypto.createPublicKey({ key: publicKey, format: 'pem' })
  const publicJwk = exportPublicJwk(publicKeyObject, 'EdDSA')
  return {
    kid: publicJwk.kid,
    alg: 'EdDSA',
    publicJwk,
    publicKey: publicKeyObject,
    privateKey: privateKeyObject,
  }
}

function parsePositiveInt(value: string | undefined, fallback: number): number {
  if (!value) return fallback
  const parsed = Number.parseInt(value, 10)
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback
}

function convertKeyBundle(jwk: JwksKey): KeyBundle {
  const alg = determineAlgorithmFromJwk(jwk)
  const publicKey = crypto.createPublicKey({ key: jwk, format: 'jwk' })
  return {
    kid: jwk.kid,
    alg,
    publicJwk: normalizeJwk(jwk),
    publicKey,
  }
}

function calculateEtag(response: JwksResponse): string {
  const canonical = JSON.stringify(response.keys.sort((a, b) => a.kid.localeCompare(b.kid)))
  return `W/"${crypto.createHash('sha256').update(canonical).digest('base64url')}"`
}

export class JwksManager {
  private activeKeys = new Map<string, KeyBundle>()
  private retiredKeys = new Map<string, RetiredKeyBundle>()
  private signingKey: KeyBundle | null = null
  private etag = ''
  private cacheExpiresAt = 0
  private cacheTtlSeconds = DEFAULT_CACHE_TTL_SECONDS
  private graceWindowSeconds = DEFAULT_GRACE_WINDOW_SECONDS

  public async reload(): Promise<void> {
    const now = Date.now()
    this.cacheTtlSeconds = parsePositiveInt(process.env.JWT_JWKS_CACHE_TTL_SECONDS, DEFAULT_CACHE_TTL_SECONDS)
    this.graceWindowSeconds = parsePositiveInt(process.env.JWT_JWKS_GRACE_WINDOW_SECONDS, DEFAULT_GRACE_WINDOW_SECONDS)

    const previousActiveKidSet = new Set(this.activeKeys.keys())
    const nextSigningKey = await this.buildSigningKey()
    const nextActiveKeys = await this.buildActiveKeyMap(nextSigningKey)

    for (const oldKid of previousActiveKidSet) {
      if (!nextActiveKeys.has(oldKid) && this.activeKeys.has(oldKid)) {
        const bundle = this.activeKeys.get(oldKid)!
        this.retiredKeys.set(oldKid, {
          bundle,
          retireAt: now + this.graceWindowSeconds * 1000,
        })
      }
    }

    for (const [kid, retired] of this.retiredKeys.entries()) {
      if (retired.retireAt <= now) {
        this.retiredKeys.delete(kid)
      }
    }

    this.signingKey = nextSigningKey
    this.activeKeys = nextActiveKeys
    this.cacheExpiresAt = now + this.cacheTtlSeconds * 1000
    this.etag = calculateEtag({ keys: Array.from(this.activeKeys.values()).map((bundle) => bundle.publicJwk) })

    logger.info({
      event: 'jwks_reload',
      activeKeyCount: this.activeKeys.size,
      retiredKeyCount: this.retiredKeys.size,
      cacheTtlSeconds: this.cacheTtlSeconds,
      graceWindowSeconds: this.graceWindowSeconds,
    })
  }

  public async ensureLoaded(): Promise<void> {
    if (Date.now() >= this.cacheExpiresAt || this.activeKeys.size === 0) {
      await this.reload()
    }
  }

  public getJwksResponse(): JwksResponse {
    return { keys: Array.from(this.activeKeys.values()).map((bundle) => bundle.publicJwk) }
  }

  public getEtag(): string {
    return this.etag
  }

  public getCacheTtlSeconds(): number {
    return this.cacheTtlSeconds
  }

  public getVerificationKey(kid: string): KeyBundle | null {
    const active = this.activeKeys.get(kid)
    if (active) {
      return active
    }

    const retired = this.retiredKeys.get(kid)
    if (retired && retired.retireAt > Date.now()) {
      return retired.bundle
    }

    if (retired) {
      this.retiredKeys.delete(kid)
    }

    return null
  }

  public getAllActiveKeys(): KeyBundle[] {
    return Array.from(this.activeKeys.values())
  }

  public getSigningKey(): KeyBundle | null {
    return this.signingKey
  }

  private async buildSigningKey(): Promise<KeyBundle | null> {
    try {
      const rawPrivateKey = secretLoader.get('JWT_PRIVATE_KEY')
      return createKeyBundleFromPrivateKey(rawPrivateKey)
    } catch (error) {
      if (error instanceof SecretNotFoundError) {
        return null
      }
      throw error
    }
  }

  private async buildActiveKeyMap(currentSigningKey: KeyBundle | null): Promise<Map<string, KeyBundle>> {
    const keys = new Map<string, KeyBundle>()
    const publicJwks = [] as JwksKey[]

    try {
      const rawJwks = secretLoader.get('JWT_PUBLIC_JWKS')
      publicJwks.push(...parseJwksFromSecret(rawJwks))
    } catch (error) {
      if (!(error instanceof SecretNotFoundError)) {
        throw error
      }
    }

    if (currentSigningKey) {
      if (!publicJwks.some((jwk) => jwk.kid === currentSigningKey.kid)) {
        publicJwks.push(currentSigningKey.publicJwk)
      }
    }

    if (publicJwks.length === 0 && !currentSigningKey) {
      const fallbackKey = generateFallbackSigningKey()
      publicJwks.push(fallbackKey.publicJwk)
      currentSigningKey = fallbackKey
    }

    for (const jwk of publicJwks) {
      const normalized = normalizeJwk(jwk)
      const bundle = convertKeyBundle(normalized)
      keys.set(bundle.kid, bundle)
    }

    return keys
  }
}

export const jwksManager = new JwksManager()
