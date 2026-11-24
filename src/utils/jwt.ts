import jwt from 'jsonwebtoken'
import { SignOptions, JwtPayload, VerifyOptions} from 'jsonwebtoken'
import { secretLoader, SecretNotFoundError } from './secret-loader.js'
import { config } from '../config/index.js'
import { randomUUID } from 'crypto'
import crypto from 'node:crypto'
import { logger } from './logger.js'
import { jwksManager } from './jwks.js'
import { getRedisClient } from '../redis.js'

// ===========================================================================
// CONFIGURATION
// ===========================================================================

const JWT_CLOCK_SKEW_SECONDS = parseInt(
  process.env.JWT_CLOCK_SKEW_SECONDS ?? '10',
  10
)

// Token TTLs in seconds
const JWT_ACCESS_TOKEN_TTL = parseInt(
  process.env.JWT_ACCESS_TOKEN_TTL ?? '3600', // 1h
  10
)
const JWT_REFRESH_TOKEN_TTL = parseInt(
  process.env.JWT_REFRESH_TOKEN_TTL ?? '604800', // 7d
  10
)

// ===========================================================================
// TYPES & ERRORS
// ===========================================================================

export interface TokenPayload {
  userId: string
  email: string
}

/**
 * Enhanced token claims for rotation tracking and security
 */
export interface EnhancedTokenPayload extends TokenPayload {
  jti: string // JWT ID - unique per token
  familyId: string // Rotation family tracking
  iat: number // Issued at
  nbf: number // Not before
  exp: number // Expiration
}

/**
 * Decoded claims for rotation-aware tokens. These are validated at runtime
 * (not merely cast) so that a signature-valid token still cannot smuggle in a
 * missing, empty, or wrong-typed `jti` / `familyId` / `type`.
 */
type RotationAwareClaims = TokenPayload & {
  jti: string
  familyId: string
  type: 'access' | 'refresh'
}

/**
 * Runtime shape guard for rotation-aware token claims.
 * @throws {TokenInvalidError} When any required rotation claim is absent.
 */
function assertRotationClaims(value: unknown): asserts value is RotationAwareClaims {
  if (!value || typeof value !== 'object') {
    throw new TokenInvalidError(
      'Token payload is missing rotation claims'
    )
  }
  const claims = value as Record<string, unknown>
  const valid =
    typeof claims.jti === 'string' && claims.jti.length > 0 &&
    typeof claims.familyId === 'string' && claims.familyId.length > 0 &&
    typeof claims.userId === 'string' && claims.userId.length > 0 &&
    typeof claims.email === 'string' && claims.email.length > 0 &&
    (claims.type === 'access' || claims.type === 'refresh')
  if (!valid) {
    throw new TokenInvalidError(
      'Token payload is missing rotation claims'
    )
  }
}

/**
 * Custom error types for JWT operations
 */
export class JWTError extends Error {
  constructor(
    message: string,
    public code: string,
    public statusCode: number = 401
  ) {
    super(message)
    this.name = 'JWTError'
  }
}

export class TokenExpiredError extends JWTError {
  constructor(message: string = 'Token has expired') {
    super(message, 'TOKEN_EXPIRED', 401)
    this.name = 'TokenExpiredError'
  }
}

export class TokenInvalidError extends JWTError {
  constructor(message: string = 'Token is invalid or malformed') {
    super(message, 'TOKEN_INVALID', 401)
    this.name = 'TokenInvalidError'
  }
}

export class TokenReusedError extends JWTError {
  constructor(message: string = 'Refresh token has been reused - possible theft detected') {
    super(message, 'TOKEN_REUSED', 401)
    this.name = 'TokenReusedError'
  }
}

// ===========================================================================
// TOKEN STORE (in-memory for now, can be swapped for Redis/DB)
// ===========================================================================

interface TokenRotationFamily {
  familyId: string
  userId: string
  currentJti: string | null // Most recent token jti in this family
  blacklistedJtis: Set<string>
  issuedJtis: Set<string> // Every access+refresh jti minted for this family
  lastRotation: number
  concurrentRefreshDetected: boolean
  createdAt: number
}

/**
 * Pluggable store for revocation state. The default in-memory implementation
 * is process-local; {@link RedisTokenStore} shares state across instances and
 * survives restarts. Redis keys carry TTLs equal to the maximum token lifetime
 * so key space cannot grow without bound.
 */
export interface TokenRevocationStore {
  isBlacklisted(jti: string): Promise<boolean>
  blacklist(jti: string, ttlSeconds: number): Promise<void>
  isFamilyCompromised(familyId: string): Promise<boolean>
  markFamilyCompromised(familyId: string, ttlSeconds: number): Promise<void>
  isConsumed(familyId: string, jti: string): Promise<boolean>
  markConsumed(familyId: string, jti: string, ttlSeconds: number): Promise<void>
  recordIssued(familyId: string, jti: string, ttlSeconds: number): Promise<void>
  listIssued(familyId: string): Promise<string[]>
}

export class InMemoryTokenStore implements TokenRevocationStore {
  private readonly blacklistSet = new Set<string>()
  private readonly compromised = new Set<string>()
  private readonly consumed = new Map<string, Set<string>>()
  private readonly issued = new Map<string, Set<string>>()

  async isBlacklisted(jti: string): Promise<boolean> {
    return this.blacklistSet.has(jti)
  }
  async blacklist(jti: string): Promise<void> {
    this.blacklistSet.add(jti)
  }
  async isFamilyCompromised(familyId: string): Promise<boolean> {
    return this.compromised.has(familyId)
  }
  async markFamilyCompromised(familyId: string): Promise<void> {
    this.compromised.add(familyId)
  }
  async isConsumed(familyId: string, jti: string): Promise<boolean> {
    return this.consumed.get(familyId)?.has(jti) ?? false
  }
  async markConsumed(familyId: string, jti: string): Promise<void> {
    let set = this.consumed.get(familyId)
    if (!set) this.consumed.set(familyId, (set = new Set()))
    set.add(jti)
  }
  async recordIssued(familyId: string, jti: string): Promise<void> {
    let set = this.issued.get(familyId)
    if (!set) this.issued.set(familyId, (set = new Set()))
    set.add(jti)
  }
  async listIssued(familyId: string): Promise<string[]> {
    return [...(this.issued.get(familyId) ?? [])]
  }
}

/**
 * Redis-backed revocation store. Every key is written with an expiry equal to
 * the token lifetime, so stale revocation entries age out automatically.
 * Callers must treat Redis errors as fail-closed (see refresh path).
 */
export class RedisTokenStore implements TokenRevocationStore {
  private key(kind: string, id: string): string {
    return `jwt:${kind}:${id}`
  }
  private async client() {
    const client = await getRedisClient()
    if (!client) throw new Error('Redis unavailable')
    return client
  }
  async isBlacklisted(jti: string): Promise<boolean> {
    return (await (await this.client()).exists(this.key('jti', jti))) === 1
  }
  async blacklist(jti: string, ttlSeconds: number): Promise<void> {
    await (await this.client()).set(this.key('jti', jti), '1', { EX: ttlSeconds })
  }
  async isFamilyCompromised(familyId: string): Promise<boolean> {
    return (await (await this.client()).exists(this.key('compromised', familyId))) === 1
  }
  async markFamilyCompromised(familyId: string, ttlSeconds: number): Promise<void> {
    await (await this.client()).set(this.key('compromised', familyId), '1', { EX: ttlSeconds })
  }
  async isConsumed(familyId: string, jti: string): Promise<boolean> {
    return (await (await this.client()).sIsMember(this.key('consumed', familyId), jti)) === true
  }
  async markConsumed(familyId: string, jti: string, ttlSeconds: number): Promise<void> {
    const c = await this.client()
    const k = this.key('consumed', familyId)
    await c.sAdd(k, jti)
    await c.expire(k, ttlSeconds)
  }
  async recordIssued(familyId: string, jti: string, ttlSeconds: number): Promise<void> {
    const c = await this.client()
    const k = this.key('issued', familyId)
    await c.sAdd(k, jti)
    await c.expire(k, ttlSeconds)
  }
  async listIssued(familyId: string): Promise<string[]> {
    return (await (await this.client()).sMembers(this.key('issued', familyId))) as string[]
  }
}

let tokenStore: TokenRevocationStore = new InMemoryTokenStore()

/**
 * Install the revocation store (call from startServer, mirroring
 * setUsedTokenStore). Defaults to the in-memory store.
 */
export function setTokenRevocationStore(store: TokenRevocationStore): void {
  tokenStore = store
}

// Process-local family metadata (userId/createdAt/currentJti) used for
// cleanup and ownership checks. Revocation state lives in tokenStore.
const tokenFamilies = new Map<string, TokenRotationFamily>()
const jtiBlacklist = new Set<string>()

/**
 * Per-family mutexes serialise refresh rotations so two concurrent requests
 * presenting the SAME refresh token cannot both pass the reuse check and mint
 * fresh tokens. See {@link withFamilyLock} and the rotation security model in
 * the "ENHANCED ROTATION-AWARE FUNCTIONS" section.
 */
const familyLocks = new Map<string, Promise<void>>()

/**
 * Run `operation` exclusively for a token family. Later callers wait for the
 * current holder to finish (success or failure) before running in sequence.
 */
async function withFamilyLock<T>(
  familyId: string,
  operation: () => Promise<T> | T
): Promise<T> {
  const previous = familyLocks.get(familyId) ?? Promise.resolve()
  let release: () => void = () => {}
  const gate = new Promise<void>((resolve) => {
    release = resolve
  })
  familyLocks.set(familyId, previous.then(() => gate))
  await previous
  try {
    return await operation()
  } finally {
    release()
  }
}

/**
 * Get or create a token family
 */
function getOrCreateFamily(familyId: string, userId: string): TokenRotationFamily {
  if (!tokenFamilies.has(familyId)) {
    tokenFamilies.set(familyId, {
      familyId,
      userId,
      currentJti: null,
      blacklistedJtis: new Set(),
      issuedJtis: new Set(),
      lastRotation: Date.now(),
      concurrentRefreshDetected: false,
      createdAt: Date.now(),
    })
  }
  return tokenFamilies.get(familyId)!
}

/**
 * Check if a jti is blacklisted
 */
export async function isTokenBlacklisted(jti: string): Promise<boolean> {
  if (jtiBlacklist.has(jti)) return true
  return tokenStore.isBlacklisted(jti)
}

/**
 * Blacklist a token by jti (for logout/revocation)
 */
export async function blacklistToken(jti: string, familyId?: string, ttlSeconds: number = JWT_REFRESH_TOKEN_TTL): Promise<void> {
  jtiBlacklist.add(jti)
  await tokenStore.blacklist(jti, ttlSeconds)
  if (familyId) {
    const family = tokenFamilies.get(familyId)
    if (family) {
      family.blacklistedJtis.add(jti)
    }
  }
  logger.info('Token blacklisted', { jti, familyId })
}

/**
 * Get token family for rotation tracking
 */
export function getTokenFamily(familyId: string): TokenRotationFamily | undefined {
  return tokenFamilies.get(familyId)
}

const JWT_ISSUER = process.env.JWT_ISSUER ?? 'veritasor-api'
const JWT_AUDIENCE = process.env.JWT_AUDIENCE ?? 'veritasor-client'


const JWT_REFRESH_AUDIENCE =
  process.env.JWT_REFRESH_AUDIENCE ?? 'veritasor-refresh'

export { JWT_ISSUER, JWT_AUDIENCE, JWT_REFRESH_AUDIENCE }


// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Internal function to retrieve JWT secret with fallback logic.
 *
 * @returns JWT secret string.
 * @throws {Error} If secret is missing in production.
 */
function getPrimaryJwtSecret(): string {
  try {
    return secretLoader.get('JWT_SECRET')
  } catch (error) {
    if (error instanceof SecretNotFoundError) {
      if (config.jwtSecret) {
        return config.jwtSecret
      }
      if (process.env.NODE_ENV !== 'production') {
        return 'dev-secret-key'
      }
      throw new Error('JWT secret is required in production')
    }

    throw error
  }
}

function getRefreshJwtSecret(): string {
  try {
    return secretLoader.get('JWT_REFRESH_SECRET')
  } catch (error) {
    if (error instanceof SecretNotFoundError) {
      if (process.env.JWT_REFRESH_SECRET) {
        return process.env.JWT_REFRESH_SECRET
      }
      if (process.env.NODE_ENV !== 'production') {
        return 'dev-refresh-secret-key'
      }

      logger.warn(
        'JWT_REFRESH_SECRET missing in production; falling back to primary JWT_SECRET. Configure a dedicated refresh secret.'
      )
      return getPrimaryJwtSecret()
    }

    throw error
  }
}


// ---------------------------------------------------------------------------
// High-level token generation / verification
// ---------------------------------------------------------------------------

/**
 * @notice Generates a short-lived JWT access token for the authenticated user.
 * @dev Embeds `iss` (JWT_ISSUER) and `aud` (JWT_AUDIENCE) claims. Any call to
 *      `verifyToken` will cryptographically enforce both claims, preventing the
 *      token from being accepted in any other context.
 * @param payload - The user identity data to encode (`userId`, `email`).
 * @returns Signed JWT string valid for 1 hour.
 *
 * @example
 * const token = generateToken({ userId: 'abc', email: 'user@example.com' })
 */
function getSigningKeyBundle() {
  return jwksManager.getSigningKey()
}

function getVerificationKeyInfo(token: string): { publicKey: crypto.KeyObject; alg: 'RS256' | 'EdDSA' } | { publicKey: null; hasKid: boolean } {
  const decoded = jwt.decode(token, { complete: true }) as { header?: Record<string, unknown> } | null
  const kid = decoded?.header?.kid
  if (!kid || typeof kid !== 'string') {
    return { publicKey: null, hasKid: false }
  }

  const bundle = jwksManager.getVerificationKey(kid)
  if (!bundle) {
    return { publicKey: null, hasKid: true }
  }

  return { publicKey: bundle.publicKey, alg: bundle.alg }
}

export function generateToken(payload: TokenPayload): string {
  const signingKey = getSigningKeyBundle()
  const tokenPayload = { ...payload, jti: randomUUID() }

  if (signingKey?.privateKey) {
    return jwt.sign(tokenPayload, signingKey.privateKey, {
      expiresIn: '1h',
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
      algorithm: signingKey.alg,
      keyid: signingKey.kid,
    } as SignOptions)
  }

  const secret = getPrimaryJwtSecret()
  return jwt.sign(tokenPayload, secret, {
    expiresIn: '1h',
    issuer: JWT_ISSUER,
    audience: JWT_AUDIENCE,
    algorithm: 'HS256',
  } as SignOptions)
}

/**
 * @notice Generates a long-lived JWT refresh token for session rotation.
 * @dev Uses a separate secret (JWT_REFRESH_SECRET) AND a distinct audience
 *      (JWT_REFRESH_AUDIENCE) to prevent substitution attacks. A refresh token
 *      cannot be accepted by `verifyToken` because both the secret and the
 *      audience claim will fail to match.
 * @param payload - The user identity data to encode (`userId`, `email`).
 * @returns Signed JWT string valid for 7 days.
 *
 * @example
 * const refreshToken = generateRefreshToken({ userId: 'abc', email: 'user@example.com' })
 */
export function generateRefreshToken(payload: TokenPayload): string {
  const secret = getRefreshJwtSecret()
  return jwt.sign(
    { ...payload, jti: randomUUID() },
    secret,
    {
      expiresIn: '7d',
      issuer: JWT_ISSUER,
      audience: JWT_REFRESH_AUDIENCE,
      algorithm: 'HS256',
    } as SignOptions
  )
}

/**
 * @notice Verifies an access token and returns its payload if valid.
 * @dev Supports JWKS-signed tokens with a `kid` header and falls back to the
 *      legacy HMAC secret path when no `kid` is present.
 *      All verification errors are caught and collapsed to `null`.
 * @param token - The raw JWT string from the `Authorization: Bearer` header.
 * @returns Decoded `TokenPayload`, or `null` if verification fails for any reason
 *          (wrong key, expired, wrong issuer, wrong audience, malformed).
 *
 * @example
 * const payload = verifyToken(req.headers.authorization?.slice(7) ?? '')
 * if (!payload) return res.status(401).json({ error: 'Unauthorized' })
 */
export function verifyToken(token: string): TokenPayload | null {
  try {
    const verification = getVerificationKeyInfo(token)
    const options: VerifyOptions = {
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
    }

    if (verification.publicKey) {
      return jwt.verify(token, verification.publicKey, {
        ...options,
        algorithms: [verification.alg],
      } as VerifyOptions) as TokenPayload
    }

    if (verification.hasKid) {
      return null
    }

    const secret = getPrimaryJwtSecret()
    const decoded = jwt.verify(token, secret, {
      ...options,
      algorithms: ['HS256'],
    } as VerifyOptions)
    return decoded as TokenPayload
  } catch {
    return null
  }
}

/**
 * @notice Verifies a refresh token and returns its payload if valid.
 * @dev Passes `{ issuer: JWT_ISSUER, audience: JWT_REFRESH_AUDIENCE }` to
 *      `jwt.verify`. An access token will be rejected because its `aud` claim
 *      is `JWT_AUDIENCE`, not `JWT_REFRESH_AUDIENCE`. This creates a second
 *      layer of isolation on top of the separate secrets.
 * @param token - The raw refresh JWT string from the request body.
 * @returns Decoded `TokenPayload`, or `null` if verification fails for any reason.
 *
 * @example
 * const payload = verifyRefreshToken(req.body.refreshToken)
 * if (!payload) throw new Error('Invalid refresh token')
 */
export function verifyRefreshToken(token: string): TokenPayload | null {
  try {
    const secret = getRefreshJwtSecret()
    const decoded = jwt.verify(token, secret, {
      issuer: JWT_ISSUER,
      audience: JWT_REFRESH_AUDIENCE,
      algorithms: ['HS256'],
    } as VerifyOptions)
    return decoded as TokenPayload
  } catch {
    return null
  }
}


// ---------------------------------------------------------------------------
// Low-level primitives (flexible, caller-controlled)
// ---------------------------------------------------------------------------

/**
 * @notice Low-level JWT signing primitive. Uses the application's primary secret.
 * @dev This function does NOT automatically embed `iss` or `aud` claims.
 *      Callers requiring audience or issuer binding should pass them explicitly
 *      via `options.audience` and `options.issuer`. For standard authentication
 *      tokens, prefer `generateToken` and `generateRefreshToken` instead.
 * @param payload - Data to encode in the JWT (string, object, or Buffer).
 * @param options - Standard `jsonwebtoken` `SignOptions` (e.g., `expiresIn`,
 *                  `algorithm`, `audience`, `issuer`).
 * @returns Signed JWT token string.
 * @throws {Error} In production if `JWT_SECRET` is not configured.
 *
 * @example
 * // Password-reset token scoped to a dedicated audience
 * const token = sign({ sub: userId }, { expiresIn: '15m', audience: 'password-reset' })
 */
export function sign(
  payload: string | object | Buffer,
  options?: SignOptions
): string {
  const secret = getPrimaryJwtSecret()
  return jwt.sign(payload, secret, options)
}

/**
 * @notice Low-level JWT verification primitive. Uses the application's primary secret.
 * @dev Unlike `verifyToken`, this function throws on failure rather than
 *      returning `null`. Pass `options.audience` and `options.issuer` to
 *      enforce strict claim validation. Without those options, no `iss`/`aud`
 *      checks are performed — tokens without those claims will be accepted if
 *      the signature is valid. This is intentional for backward-compatible
 *      use cases such as verifying custom scoped tokens (e.g., password-reset).
 *      For standard access token verification, prefer `verifyToken`.
 * @param token - JWT token string to verify.
 * @param options - Optional `VerifyOptions`; pass `{ audience, issuer }` to
 *                  enable strict audience/issuer validation.
 * @returns Decoded payload as `string`, `object`, or `jwt.JwtPayload`.
 * @throws {JsonWebTokenError} For invalid signature, malformed token, wrong
 *         audience, or wrong issuer (when options provided).
 * @throws {TokenExpiredError} For tokens past their `exp` claim.
 * @throws {NotBeforeError} For tokens used before their `nbf` claim.
 *
 * @example
 * // Enforce a scoped audience for a custom token type
 * const payload = verify(token, { audience: 'password-reset' })
 */
export function verify(
  token: string,
  options?: VerifyOptions
): string | object | jwt.JwtPayload {
  const secret = getPrimaryJwtSecret()
  return jwt.verify(token, secret, options)
}

// ===========================================================================
// ENHANCED ROTATION-AWARE FUNCTIONS
// ===========================================================================

/**
 * Rotation-aware token lifecycle — security model
 *
 * - Refresh tokens are single-use: `refreshTokenPair` consumes the presented
 *   jti (adds it to the family's `blacklistedJtis`) BEFORE issuing a
 *   replacement, so replaying a consumed token is always detected.
 *
 * - Reuse of a consumed refresh token is treated as a theft signal. The family
 *   is flagged `concurrentRefreshDetected` and EVERY token minted for it
 *   (access + refresh, including the current jti) is globally blacklisted so
 *   nothing minted before the theft is usable — the attacker's replay AND the
 *   valid sibling access token are both revoked at once.
 *
 * - Concurrent refresh of the same token is impossible by construction:
 *   rotations are serialised per family with {@link withFamilyLock}, so
 *   exactly one caller can rotate while the peers observe reuse and are
 *   rejected with `TOKEN_REUSED`.
 *
 * - Family tokens are bound to distinct audiences (`JWT_AUDIENCE` for access,
 *   `JWT_REFRESH_AUDIENCE` for refresh) plus an explicit `type` claim,
 *   mirroring the legacy access/refresh isolation: an access token can never
 *   be accepted as a refresh token (and vice-versa), even under a shared
 *   secret.
 *
 * - All family verification enforces issuer (`JWT_ISSUER`), audience, and
 *   `alg: HS256`, and tolerates `JWT_CLOCK_SKEW_SECONDS` of clock drift.
 *
 * - Scope: the family store is in-memory and process-local. Multi-instance
 *   deployments must use the durable `usedTokenStore` replay detection (see
 *   `src/services/auth/usedTokenStore.js`) which already backs the deployed
 *   `/auth/refresh` route.
 */

/**
 * Generate an access token with rotation tracking
 * @param payload - User payload
 * @param familyId - Token family ID for rotation tracking (generates new if not provided)
 * @returns Access token with embedded jti and familyId
 */
export function generateAccessToken(
  payload: TokenPayload,
  familyId?: string
): string {
  const jti = randomUUID()
  const family = familyId || randomUUID()

  // Register the family and track the issued jti so a compromise or
  // revocation can revoke every token (access + refresh) in the family.
  const tracking = getOrCreateFamily(family, payload.userId)
  tracking.issuedJtis.add(jti)
  void tokenStore.recordIssued(family, jti, JWT_REFRESH_TOKEN_TTL).catch(() => {})

  const tokenPayload = {
    ...payload,
    jti,
    familyId: family,
    type: 'access',
  }

  return jwt.sign(tokenPayload, getPrimaryJwtSecret(), {
    expiresIn: JWT_ACCESS_TOKEN_TTL,
    issuer: JWT_ISSUER,
    audience: JWT_AUDIENCE,
    algorithm: 'HS256',
  } as SignOptions)
}

/**
 * Generate a refresh token with rotation tracking
 * @param payload - User payload
 * @param familyId - Token family ID for rotation tracking (generates new if not provided)
 * @returns Refresh token with embedded jti and familyId
 */
export function generateRefreshTokenWithFamily(
  payload: TokenPayload,
  familyId?: string
): string {
  const jti = randomUUID()
  const family = familyId || randomUUID()

  // Initialize or update the family tracking
  const tracking = getOrCreateFamily(family, payload.userId)
  tracking.issuedJtis.add(jti)
  void tokenStore.recordIssued(family, jti, JWT_REFRESH_TOKEN_TTL).catch(() => {})

  const tokenPayload = {
    ...payload,
    jti,
    familyId: family,
    type: 'refresh',
  }

  return jwt.sign(tokenPayload, getRefreshJwtSecret(), {
    expiresIn: JWT_REFRESH_TOKEN_TTL,
    issuer: JWT_ISSUER,
    audience: JWT_REFRESH_AUDIENCE,
    algorithm: 'HS256',
  } as SignOptions)
}

/**
 * Generate both access and refresh tokens with family tracking
 * @param payload - User payload
 * @param familyId - Token family ID (generates new if not provided)
 * @returns Token pair with shared familyId
 */
export function generateTokenPair(payload: TokenPayload, familyId?: string) {
  const family = familyId || randomUUID()

  const accessToken = generateAccessToken(payload, family)
  const refreshToken = generateRefreshTokenWithFamily(payload, family)

  return { accessToken, refreshToken, familyId: family }
}

/**
 * Verify access token with rotation tracking
 * @param token - Access token to verify
 * @throws JWTError variants on failure
 */
export function verifyAccessToken(token: string): EnhancedTokenPayload {
  try {
    const decoded = jwt.verify(token, getPrimaryJwtSecret(), {
      clockTimestamp: Math.floor(Date.now() / 1000),
      clockTolerance: JWT_CLOCK_SKEW_SECONDS,
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
      algorithms: ['HS256'],
    } as VerifyOptions)

    assertRotationClaims(decoded)

    // Check if token is blacklisted
    if (decoded.jti && jtiBlacklist.has(decoded.jti)) {
      throw new JWTError('Token has been revoked', 'TOKEN_REVOKED', 401)
    }

    // Validate token type
    if (decoded.type !== 'access') {
      throw new JWTError('Token type mismatch', 'TYPE_MISMATCH', 401)
    }

    return decoded as unknown as EnhancedTokenPayload
  } catch (error) {
    if (error instanceof JWTError) throw error
    if (error instanceof jwt.TokenExpiredError) {
      throw new TokenExpiredError('Access token has expired')
    }
    if (error instanceof jwt.JsonWebTokenError) {
      throw new TokenInvalidError(error.message)
    }
    throw new TokenInvalidError()
  }
}

/**
 * Verify refresh token with rotation and reuse detection
 * @param token - Refresh token to verify
 * @throws JWTError variants on failure or detected theft
 */
export function verifyRefreshTokenRotationAware(
  token: string
): EnhancedTokenPayload {
  try {
    const decoded = jwt.verify(token, getRefreshJwtSecret(), {
      clockTimestamp: Math.floor(Date.now() / 1000),
      clockTolerance: JWT_CLOCK_SKEW_SECONDS,
      issuer: JWT_ISSUER,
      audience: JWT_REFRESH_AUDIENCE,
      algorithms: ['HS256'],
    } as VerifyOptions)

    assertRotationClaims(decoded)

    const { jti, familyId, userId } = decoded

    // Validate token type
    if (decoded.type !== 'refresh') {
      throw new JWTError('Token type mismatch', 'TYPE_MISMATCH', 401)
    }

    // Check blacklist
    if (jti && jtiBlacklist.has(jti)) {
      throw new JWTError('Token has been revoked', 'TOKEN_REVOKED', 401)
    }

    // Get family and check for reuse/theft
    const family = getOrCreateFamily(familyId, userId)

    if (family.concurrentRefreshDetected) {
      logger.warn('Concurrent refresh detected on compromised family', {
        event: 'family_compromised',
        familyId,
        userId,
        jti,
      })
      throw new JWTError(
        'Family marked as compromised due to concurrent refresh',
        'FAMILY_COMPROMISED',
        401
      )
    }

    // Reuse of a consumed refresh token is a theft signal: flag the family as
    // compromised and revoke EVERY token minted for it (access + refresh,
    // including the current jti) so the stolen token and its siblings become
    // unusable immediately. The family entry is intentionally NOT deleted so
    // the compromise marker persists for the record.
    if (family.blacklistedJtis.has(jti)) {
      logger.error(
        'token_reuse_detected: consumed refresh token reused; revoking entire token family',
        {
          event: 'token_reuse_detected',
          familyId,
          userId,
          jti,
        }
      )
      family.concurrentRefreshDetected = true
      void tokenStore.markFamilyCompromised(familyId, JWT_REFRESH_TOKEN_TTL).catch(() => {})
      for (const compromisedJti of family.issuedJtis) {
        jtiBlacklist.add(compromisedJti)
        void tokenStore.blacklist(compromisedJti, JWT_REFRESH_TOKEN_TTL).catch(() => {})
      }
      throw new TokenReusedError()
    }

    return decoded as unknown as EnhancedTokenPayload
  } catch (error) {
    if (error instanceof JWTError) throw error
    if (error instanceof jwt.TokenExpiredError) {
      throw new TokenExpiredError('Refresh token has expired')
    }
    if (error instanceof jwt.JsonWebTokenError) {
      throw new TokenInvalidError(error.message)
    }
    throw new TokenInvalidError()
  }
}

/**
 * Perform refresh with rotation and theft detection
 *
 * Async: rotations for the same token family are serialised with a per-family
 * mutex so concurrent requests presenting the same refresh token can never
 * both rotate. The caller that wins mints the replacement; the losers are
 * rejected with `TOKEN_REUSED`. There are no in-repo callers yet, so making
 * this function async is a safe (documented) API change.
 *
 * @param refreshToken - Current refresh token
 * @returns Promise resolving to the new token pair with shared family tracking
 * @throws JWTError variants on failure, including theft detection
 */
export async function refreshTokenPair(refreshToken: string): Promise<{
  accessToken: string
  refreshToken: string
  familyId: string
}> {
  // Resolve the family for the lock BEFORE verifying: if the token is
  // malformed, verification inside the lock rejects it.
  let familyId = 'unbound-refresh'
  try {
    const preview = jwt.decode(refreshToken) as RotationAwareClaims | null
    if (preview?.familyId) {
      familyId = preview.familyId
    }
  } catch {
    // Malformed token; verification inside the lock rejects it.
  }

  return withFamilyLock(familyId, async () => {
    // Verify and extract claims (confirms this token has not been consumed yet)
    const decoded = verifyRefreshTokenRotationAware(refreshToken)
    const { jti: oldJti, familyId: tokenFamilyId, userId, email } = decoded

    // Get family
    const family = getOrCreateFamily(tokenFamilyId, userId)

    // Mark old token as used (consumed) BEFORE minting the replacement so a
    // concurrent call presenting the same token is rejected as reuse.
    family.blacklistedJtis.add(oldJti)
    await tokenStore.markConsumed(tokenFamilyId, oldJti, JWT_REFRESH_TOKEN_TTL)
    await tokenStore.blacklist(oldJti, JWT_REFRESH_TOKEN_TTL)
    family.lastRotation = Date.now()

    // Generate new token pair with same family
    const { accessToken, refreshToken: newRefreshToken } = generateTokenPair(
      { userId, email },
      tokenFamilyId
    )

    // Update family's current jti
    const newDecoded = jwt.decode(newRefreshToken) as RotationAwareClaims
    family.currentJti = newDecoded.jti

    logger.info('Token pair refreshed', {
      event: 'refresh_rotated',
      userId,
      familyId: tokenFamilyId,
      oldJti,
      newJti: newDecoded.jti,
    })

    return {
      accessToken,
      refreshToken: newRefreshToken,
      familyId: tokenFamilyId,
    }
  })
}

/**
 * Revoke a token family (logout all devices)
 *
 * Blacklists every jti minted for the family (access + refresh, including the
 * current jti) before removing the in-memory entry, so previously-issued
 * tokens from the family are unusable even after a process restart.
 */
export async function revokeTokenFamily(familyId: string): Promise<void> {
  const family = tokenFamilies.get(familyId)
  const issued = await tokenStore.listIssued(familyId).catch(() => [] as string[])
  for (const jti of issued) {
    jtiBlacklist.add(jti)
    void tokenStore.blacklist(jti, JWT_REFRESH_TOKEN_TTL).catch(() => {})
  }
  if (family) {
    for (const jti of family.issuedJtis) {
      jtiBlacklist.add(jti)
      await tokenStore.blacklist(jti, JWT_REFRESH_TOKEN_TTL)
    }
    family.blacklistedJtis.forEach((jti) => jtiBlacklist.add(jti))
    tokenFamilies.delete(familyId)
    logger.warn('Token family revoked', { event: 'family_revoked', familyId })
  }
}

/**
 * Revoke every token family owned by a user (e.g. after a password reset).
 *
 * Iterates `tokenFamilies` and, for each family whose `userId` matches,
 * blacklists every minted JTI (access + refresh, including already-rotated
 * ones) and deletes the family entry. Families belonging to other users are
 * left untouched.
 *
 * @returns The number of families revoked.
 */
export function revokeAllUserTokenFamilies(userId: string): number {
  const revokedFamilyIds: string[] = []

  for (const [familyId, family] of tokenFamilies.entries()) {
    if (family.userId !== userId) continue
    for (const jti of family.issuedJtis) {
      jtiBlacklist.add(jti)
    }
    family.blacklistedJtis.forEach((jti) => jtiBlacklist.add(jti))
    revokedFamilyIds.push(familyId)
  }

  // Delete after iterating so entries are never mutated mid-iteration.
  for (const familyId of revokedFamilyIds) {
    tokenFamilies.delete(familyId)
  }

  if (revokedFamilyIds.length > 0) {
    logger.warn('Token families revoked for user', {
      event: 'families_revoked_for_user',
      userId,
      familyCount: revokedFamilyIds.length,
    })
  }

  return revokedFamilyIds.length
}

/**
 * Clear old families (cleanup, can be called periodically)
 * @param maxAgeMs - Maximum age in milliseconds (default: 30 days)
 */
export function clearExpiredFamilies(maxAgeMs: number = 30 * 24 * 60 * 60 * 1000): number {
  const now = Date.now()
  let cleared = 0

  for (const [familyId, family] of tokenFamilies.entries()) {
    if (now - family.createdAt > maxAgeMs) {
      tokenFamilies.delete(familyId)
      cleared++
    }
  }

  if (cleared > 0) {
    logger.info('Expired token families cleared', { count: cleared })
  }

  return cleared
}
