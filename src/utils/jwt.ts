import jwt from 'jsonwebtoken'
import { SignOptions, JwtPayload, VerifyOptions} from 'jsonwebtoken'
import { config } from '../config/index.js'
import { randomUUID } from 'crypto'
import { logger } from './logger.js'

// ===========================================================================
// CONFIGURATION
// ===========================================================================

const JWT_SECRET = process.env.JWT_SECRET ?? 'dev-secret-key'
const JWT_REFRESH_SECRET =
  process.env.JWT_REFRESH_SECRET ?? 'dev-refresh-secret-key'

// Clock skew tolerance in seconds (default: 10s)
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
  lastRotation: number
  concurrentRefreshDetected: boolean
  createdAt: number
}

// In-memory token rotation tracking
const tokenFamilies = new Map<string, TokenRotationFamily>()
const jtiBlacklist = new Set<string>()

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
export function isTokenBlacklisted(jti: string): boolean {
  return jtiBlacklist.has(jti)
}

/**
 * Blacklist a token by jti (for logout/revocation)
 */
export function blacklistToken(jti: string, familyId?: string): void {
  jtiBlacklist.add(jti)
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

/**
 * @notice Intended recipient audience for long-lived refresh tokens.
 *         Intentionally distinct from JWT_AUDIENCE to prevent cross-token
 *         substitution attacks.
 *         Override via the JWT_REFRESH_AUDIENCE environment variable.
 */
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
function getSecret(): string {
  // Check config.jwtSecret first
  if (config.jwtSecret) {
    return config.jwtSecret
  }

  // Fallback to JWT_SECRET environment variable
  if (process.env.JWT_SECRET) {
    return process.env.JWT_SECRET
  }

  // In production, throw error if no secret is configured
  if (process.env.NODE_ENV === 'production') {
    throw new Error(
      'JWT secret is required in production. Set JWT_SECRET environment variable or config.jwtSecret'
    )
  }

  // In development, return default secret
  return 'dev-secret-key'
}

// ---------------------------------------------------------------------------
// Token payload type
// ---------------------------------------------------------------------------

export interface TokenPayload {
  userId: string
  email: string
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
export function generateToken(payload: TokenPayload): string {
  return jwt.sign(payload, config.jwtSecret, {
    expiresIn: '1h',
    issuer: JWT_ISSUER,
    audience: JWT_AUDIENCE,
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
  const secret = process.env.JWT_REFRESH_SECRET || config.jwtSecret;
  return jwt.sign(payload, secret, {
    expiresIn: '7d',
    issuer: JWT_ISSUER,
    audience: JWT_REFRESH_AUDIENCE,
  } as SignOptions)
}

/**
 * @notice Verifies an access token and returns its payload if valid.
 * @dev Passes `{ issuer: JWT_ISSUER, audience: JWT_AUDIENCE }` to `jwt.verify`,
 *      which causes the library to throw `JsonWebTokenError` if either claim is
 *      absent or does not match. A refresh token will be rejected here because
 *      its `aud` claim is `JWT_REFRESH_AUDIENCE`, not `JWT_AUDIENCE`.
 *      All verification errors are caught and collapsed to `null`.
 * @param token - The raw JWT string from the `Authorization: Bearer` header.
 * @returns Decoded `TokenPayload`, or `null` if verification fails for any reason
 *          (wrong secret, expired, wrong issuer, wrong audience, malformed).
 *
 * @example
 * const payload = verifyToken(req.headers.authorization?.slice(7) ?? '')
 * if (!payload) return res.status(401).json({ error: 'Unauthorized' })
 */
export function verifyToken(token: string): TokenPayload | null {
  try {
    const decoded = jwt.verify(token, config.jwtSecret, {
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
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
    const secret = process.env.JWT_REFRESH_SECRET || config.jwtSecret;
    const decoded = jwt.verify(token, secret, {
      issuer: JWT_ISSUER,
      audience: JWT_REFRESH_AUDIENCE,
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
  const secret = getSecret()
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
  const secret = getSecret()
  return jwt.verify(token, secret, options)
}

// ===========================================================================
// ENHANCED ROTATION-AWARE FUNCTIONS
// ===========================================================================

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

  const tokenPayload = {
    ...payload,
    jti,
    familyId: family,
    type: 'access',
  }

  return jwt.sign(tokenPayload, JWT_SECRET, {
    expiresIn: JWT_ACCESS_TOKEN_TTL,
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
  getOrCreateFamily(family, payload.userId)

  const tokenPayload = {
    ...payload,
    jti,
    familyId: family,
    type: 'refresh',
  }

  return jwt.sign(tokenPayload, JWT_REFRESH_SECRET, {
    expiresIn: JWT_REFRESH_TOKEN_TTL,
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
    const decoded = jwt.verify(token, JWT_SECRET, {
      clockTimestamp: Math.floor(Date.now() / 1000),
      clockTolerance: JWT_CLOCK_SKEW_SECONDS,
    }) as any

    // Check if token is blacklisted
    if (decoded.jti && isTokenBlacklisted(decoded.jti)) {
      throw new JWTError('Token has been revoked', 'TOKEN_REVOKED', 401)
    }

    // Validate token type
    if (decoded.type !== 'access') {
      throw new JWTError('Token type mismatch', 'TYPE_MISMATCH', 401)
    }

    return decoded as EnhancedTokenPayload
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
    const decoded = jwt.verify(token, JWT_REFRESH_SECRET, {
      clockTimestamp: Math.floor(Date.now() / 1000),
      clockTolerance: JWT_CLOCK_SKEW_SECONDS,
    }) as any

    const { jti, familyId, userId } = decoded

    // Validate token type
    if (decoded.type !== 'refresh') {
      throw new JWTError('Token type mismatch', 'TYPE_MISMATCH', 401)
    }

    // Check blacklist
    if (jti && isTokenBlacklisted(jti)) {
      throw new JWTError('Token has been revoked', 'TOKEN_REVOKED', 401)
    }

    // Get family and check for reuse/theft
    const family = getOrCreateFamily(familyId, userId)

    if (family.concurrentRefreshDetected) {
      logger.warn('Concurrent refresh detected on compromised family', {
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

    // Check if this jti was already used (token reuse = theft signal)
    if (family.blacklistedJtis.has(jti)) {
      logger.error('Token reuse detected - possible theft!', {
        familyId,
        userId,
        jti,
      })
      family.concurrentRefreshDetected = true
      throw new TokenReusedError()
    }

    return decoded as EnhancedTokenPayload
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
 * @param refreshToken - Current refresh token
 * @returns New token pair with advanced family tracking
 * @throws JWTError variants on failure, including theft detection
 */
export function refreshTokenPair(refreshToken: string): {
  accessToken: string
  refreshToken: string
  familyId: string
} {
  // Verify and extract claims
  const decoded = verifyRefreshTokenRotationAware(refreshToken)
  const { jti: oldJti, familyId, userId, email } = decoded

  // Get family
  const family = getOrCreateFamily(familyId, userId)

  // Mark old token as used (consumed)
  family.blacklistedJtis.add(oldJti)
  family.lastRotation = Date.now()

  // Generate new token pair with same family
  const { accessToken, refreshToken: newRefreshToken } = generateTokenPair(
    { userId, email },
    familyId
  )

  // Update family's current jti
  const newDecoded = jwt.decode(newRefreshToken) as any
  family.currentJti = newDecoded.jti

  logger.info('Token pair refreshed', {
    userId,
    familyId,
    oldJti,
    newJti: newDecoded.jti,
  })

  return { accessToken, refreshToken: newRefreshToken, familyId }
}

/**
 * Revoke a token family (logout all devices)
 */
export function revokeTokenFamily(familyId: string): void {
  const family = tokenFamilies.get(familyId)
  if (family) {
    family.blacklistedJtis.forEach((jti) => jtiBlacklist.add(jti))
    tokenFamilies.delete(familyId)
    logger.info('Token family revoked', { familyId })
  }
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
