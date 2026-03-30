import jwt from 'jsonwebtoken'
import { SignOptions, VerifyOptions } from 'jsonwebtoken'
import { config } from '../config/index.js'

const JWT_SECRET = process.env.JWT_SECRET ?? 'dev-secret-key'
const JWT_REFRESH_SECRET =
  process.env.JWT_REFRESH_SECRET ?? 'dev-refresh-secret-key'

// ---------------------------------------------------------------------------
// Audience / Issuer constants
// ---------------------------------------------------------------------------

/**
 * @notice Identity of the party that issued the token.
 *         Override via the JWT_ISSUER environment variable for multi-tenant
 *         or multi-service deployments.
 */
const JWT_ISSUER = process.env.JWT_ISSUER ?? 'veritasor-api'

/**
 * @notice Intended recipient audience for short-lived access tokens.
 *         Override via the JWT_AUDIENCE environment variable.
 */
const JWT_AUDIENCE = process.env.JWT_AUDIENCE ?? 'veritasor-client'

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
  return jwt.sign(payload, JWT_SECRET, {
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
  return jwt.sign(payload, JWT_REFRESH_SECRET, {
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
    const decoded = jwt.verify(token, JWT_SECRET, {
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
    const decoded = jwt.verify(token, JWT_REFRESH_SECRET, {
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
