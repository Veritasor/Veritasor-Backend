import jwt from 'jsonwebtoken'
import { SignOptions } from 'jsonwebtoken'
import { config } from '../config/index.js'

const JWT_SECRET = process.env.JWT_SECRET ?? 'dev-secret-key'
const JWT_REFRESH_SECRET =
  process.env.JWT_REFRESH_SECRET ?? 'dev-refresh-secret-key'

/**
 * Internal function to retrieve JWT secret with fallback logic
 * @returns JWT secret string
 * @throws Error if secret is missing in production
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

export interface TokenPayload {
  userId: string
  email: string
}

export function generateToken(payload: TokenPayload): string {
  return jwt.sign(payload, JWT_SECRET, {
    expiresIn: '1h',
  } as SignOptions)
}

export function generateRefreshToken(payload: TokenPayload): string {
  return jwt.sign(payload, JWT_REFRESH_SECRET, {
    expiresIn: '7d',
  } as SignOptions)
}

export function verifyToken(token: string): TokenPayload | null {
  try {
    const decoded = jwt.verify(token, JWT_SECRET)
    return decoded as TokenPayload
  } catch (error) {
    return null
  }
}

export function verifyRefreshToken(token: string): TokenPayload | null {
  try {
    const decoded = jwt.verify(token, JWT_REFRESH_SECRET)
    return decoded as TokenPayload
  } catch (error) {
    return null
  }
}
