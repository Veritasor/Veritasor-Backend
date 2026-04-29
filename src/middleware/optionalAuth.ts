import { Request, Response, NextFunction } from "express";
import { verifyToken } from "../utils/jwt.js";
import { findUserById } from "../repositories/userRepository.js";

// Auth event types for structured logging
export enum AuthEventType {
  NO_TOKEN = 'NO_TOKEN',
  MALFORMED_HEADER = 'MALFORMED_HEADER', 
  INVALID_TOKEN = 'INVALID_TOKEN',
  EXPIRED_TOKEN = 'EXPIRED_TOKEN',
  WRONG_ISSUER = 'WRONG_ISSUER',
  WRONG_AUDIENCE = 'WRONG_AUDIENCE',
  USER_NOT_FOUND = 'USER_NOT_FOUND',
  AUTH_SUCCESS = 'AUTH_SUCCESS',
  DATABASE_ERROR = 'DATABASE_ERROR',
  UNEXPECTED_ERROR = 'UNEXPECTED_ERROR',
}

// Structured logging interface for auth events
interface AuthLogContext {
  eventType: AuthEventType;
  userId?: string;
  userAgent?: string;
  ip?: string;
  requestId?: string;
  error?: string;
  tokenLength?: number;
  hasBearerPrefix?: boolean;
  headerPresent?: boolean;
  duration?: number;
}

function logAuthEvent(context: AuthLogContext): void {
  const timestamp = new Date().toISOString();
  const logEntry = {
    timestamp,
    level: context.eventType === AuthEventType.AUTH_SUCCESS ? 'info' : 'warn',
    service: 'optional-auth',
    event: context.eventType,
    ...context,
  };
  
  console[context.eventType === AuthEventType.AUTH_SUCCESS ? 'log' : 'warn'](JSON.stringify(logEntry));
}

// Enhanced token extraction with classification
interface TokenExtractionResult {
  token: string | null;
  eventType: AuthEventType;
  details: Partial<AuthLogContext>;
}

function extractAndClassifyToken(authHeader: string | undefined): TokenExtractionResult {
  // No header present
  if (!authHeader) {
    return {
      token: null,
      eventType: AuthEventType.NO_TOKEN,
      details: { headerPresent: false, hasBearerPrefix: false }
    };
  }

  // Header is empty string
  if (authHeader.trim() === '') {
    return {
      token: null,
      eventType: AuthEventType.MALFORMED_HEADER,
      details: { headerPresent: true, hasBearerPrefix: false, tokenLength: 0 }
    };
  }

  // Split on the first whitespace to separate prefix from credentials
  const parts = authHeader.split(/\s+/);

  // Need at least 2 parts: prefix and token
  if (parts.length < 2) {
    return {
      token: null,
      eventType: AuthEventType.MALFORMED_HEADER,
      details: { 
        headerPresent: true, 
        hasBearerPrefix: parts[0]?.toLowerCase() === 'bearer',
        tokenLength: 0 
      }
    };
  }

  // Validate prefix is exactly "bearer" (case-insensitive)
  const prefix = parts[0].toLowerCase();
  if (prefix !== "bearer") {
    return {
      token: null,
      eventType: AuthEventType.MALFORMED_HEADER,
      details: { 
        headerPresent: true, 
        hasBearerPrefix: false,
        tokenLength: authHeader.length - parts[0].length 
      }
    };
  }

  // Get the token (everything after the prefix, handling multiple spaces)
  const token = parts.slice(1).join(" ");

  // Validate token is non-empty after trimming
  if (!token || token.trim() === "") {
    return {
      token: null,
      eventType: AuthEventType.MALFORMED_HEADER,
      details: { 
        headerPresent: true, 
        hasBearerPrefix: true,
        tokenLength: 0 
      }
    };
  }

  // Return the token with classification
  return {
    token: token.trim(),
    eventType: AuthEventType.AUTH_SUCCESS, // Will be updated based on verification
    details: { 
      headerPresent: true, 
      hasBearerPrefix: true,
      tokenLength: token.trim().length 
    }
  };
}

// Extend Express Request to include user consistently across auth middlewares
declare global {
  namespace Express {
    interface Request {
      user?: {
        id: string;
        userId: string;
        email?: string;
      };
    }
  }
}

/**
 * Extracts and validates the Bearer token from the Authorization header.
 * 
 * This helper function handles various malformed Authorization headers gracefully:
 * - Missing or empty headers return null (unauthenticated)
 * - Non-"Bearer" schemes return null (unauthenticated, e.g., "Basic", "Token")
 * - Typos in "Bearer" prefix return null (e.g., "Bearr", "BEARER", "Bearer:")
 * - Missing or empty tokens (e.g., "Bearer " or "Bearer") return null
 * - Multiple spaces are normalized correctly (e.g., "Bearer  token" -> "token")
 * - Case-insensitive for the prefix (converts to lowercase before checking)
 * 
 * Algorithm:
 * 1. Return null if header is missing or empty (falsy)
 * 2. Split on first whitespace and validate prefix is exactly "bearer" (case-insensitive)
 * 3. Trim any excess whitespace and validate token is non-empty
 * 4. Return null if validation fails at any step (malformed header)
 * 
 * @param authHeader - The Authorization header value from the request
 * @returns The extracted Bearer token, or null if header is malformed/missing
 * 
 * @example
 * extractBearerToken('Bearer valid-token') // returns 'valid-token'
 * extractBearerToken('Bearer  multiple  spaces') // returns 'multiple  spaces'
 * extractBearerToken('Bearer') // returns null (no token)
 * extractBearerToken('Bearr token') // returns null (typo in prefix)
 * extractBearerToken('Bearer:token') // returns null (colon instead of space)
 * extractBearerToken('Token token') // returns null (wrong scheme)
 * extractBearerToken('') // returns null (empty)
 * extractBearerToken(undefined) // returns null (missing)
 */
export function extractBearerToken(authHeader: string | undefined): string | null {
  // Return null if header is missing or empty
  if (!authHeader) {
    return null;
  }

  // Split on the first whitespace to separate prefix from credentials
  const parts = authHeader.split(/\s+/);

  // Need at least 2 parts: prefix and token
  if (parts.length < 2) {
    return null;
  }

  // Validate prefix is exactly "bearer" (case-insensitive)
  const prefix = parts[0].toLowerCase();
  if (prefix !== "bearer") {
    return null;
  }

  // Get the token (everything after the prefix, handling multiple spaces)
  // We use slice(1) to get all parts after prefix and join with space
  const token = parts.slice(1).join(" ");

  // Validate token is non-empty after trimming
  if (!token || token.trim() === "") {
    return null;
  }

  // Return the token with internal whitespace preserved
  // but external whitespace trimmed (handles edge cases like "Bearer  token  ")
  return token.trim();
}

/**
 * Optional authentication middleware that attempts to authenticate requests
 * by verifying a JWT token in the Authorization header.
 *
 * Enhanced Features:
 * - Clear distinction between absent vs malformed tokens
 * - Structured logging for all auth events with correlation
 * - Comprehensive error classification for observability
 * - Database verification with proper error handling
 * - Performance tracking and security monitoring
 *
 * Security Assumptions:
 * - If no token is provided, request is treated as unauthenticated (NO_TOKEN)
 * - If token is malformed, request is treated as unauthenticated (MALFORMED_HEADER)
 * - If token is provided but invalid/expired, request is treated as unauthenticated (INVALID_TOKEN/EXPIRED_TOKEN)
 * - If token is valid but user no longer exists, request is treated as unauthenticated (USER_NOT_FOUND)
 * - This middleware NEVER returns 401 Unauthorized; use requireAuth for protected routes.
 * - All auth events are logged for security monitoring and debugging
 *
 * Auth Event Classification:
 * - NO_TOKEN: No Authorization header present
 * - MALFORMED_HEADER: Authorization header present but malformed (wrong format, missing token, etc.)
 * - INVALID_TOKEN: Token present but cryptographically invalid
 * - EXPIRED_TOKEN: Token present but expired
 * - WRONG_ISSUER: Token present but from wrong issuer
 * - WRONG_AUDIENCE: Token present but for wrong audience
 * - USER_NOT_FOUND: Token valid but user not found in database
 * - AUTH_SUCCESS: Token valid and user found
 * - DATABASE_ERROR: Database lookup failed
 * - UNEXPECTED_ERROR: Unexpected system error
 *
 * @param req - Express Request object
 * @param res - Express Response object
 * @param next - Express NextFunction
 */
export async function optionalAuth(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  const startTime = Date.now();
  
  // Extract request metadata for logging
  const requestId = req.headers['x-request-id'] as string || `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  const userAgent = req.headers['user-agent'] as string || 'unknown';
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  
  try {
    // Extract Authorization header and classify token
    const authHeader = req.headers.authorization;
    const extractionResult = extractAndClassifyToken(authHeader);
    
    // If no valid token, log and proceed without auth
    if (!extractionResult.token) {
      const logContext: AuthLogContext = {
        eventType: extractionResult.eventType,
        userAgent,
        ip,
        requestId,
        duration: Date.now() - startTime,
        ...extractionResult.details
      };
      
      logAuthEvent(logContext);
      next();
      return;
    }

    // Verify token using existing JWT verification logic
    let payload;
    try {
      payload = verifyToken(extractionResult.token);
    } catch (error) {
      // Classify the specific JWT error
      let eventType: AuthEventType;
      
      if (error instanceof Error) {
        if (error.message.includes('expired') || error.message.includes('exp')) {
          eventType = AuthEventType.EXPIRED_TOKEN;
        } else if (error.message.includes('issuer') || error.message.includes('iss')) {
          eventType = AuthEventType.WRONG_ISSUER;
        } else if (error.message.includes('audience') || error.message.includes('aud')) {
          eventType = AuthEventType.WRONG_AUDIENCE;
        } else {
          eventType = AuthEventType.INVALID_TOKEN;
        }
      } else {
        eventType = AuthEventType.INVALID_TOKEN;
      }
      
      const logContext: AuthLogContext = {
        eventType,
        userAgent,
        ip,
        requestId,
        error: error instanceof Error ? error.message : 'Unknown JWT error',
        tokenLength: extractionResult.details.tokenLength,
        duration: Date.now() - startTime
      };
      
      logAuthEvent(logContext);
      
      // Ensure req.user is undefined and proceed
      req.user = undefined;
      next();
      return;
    }

    // If token is invalid, log and proceed
    if (!payload) {
      const logContext: AuthLogContext = {
        eventType: AuthEventType.INVALID_TOKEN,
        userAgent,
        ip,
        requestId,
        tokenLength: extractionResult.details.tokenLength,
        duration: Date.now() - startTime
      };
      
      logAuthEvent(logContext);
      next();
      return;
    }

    // If token is valid, verify user existence and attach to request
    try {
      const user = await findUserById(payload.userId);

      if (user) {
        req.user = {
          id: user.id,
          userId: user.id,
          email: user.email,
        };
        
        // Log successful authentication
        const logContext: AuthLogContext = {
          eventType: AuthEventType.AUTH_SUCCESS,
          userId: user.id,
          userAgent,
          ip,
          requestId,
          tokenLength: extractionResult.details.tokenLength,
          duration: Date.now() - startTime
        };
        
        logAuthEvent(logContext);
      } else {
        // Token was valid but user was not found (e.g., deleted)
        req.user = undefined;
        
        const logContext: AuthLogContext = {
          eventType: AuthEventType.USER_NOT_FOUND,
          userId: payload.userId, // Log the attempted user ID
          userAgent,
          ip,
          requestId,
          tokenLength: extractionResult.details.tokenLength,
          duration: Date.now() - startTime
        };
        
        logAuthEvent(logContext);
      }
    } catch (dbError) {
      // Database error - log but don't fail the request
      req.user = undefined;
      
      const logContext: AuthLogContext = {
        eventType: AuthEventType.DATABASE_ERROR,
        userId: payload.userId,
        userAgent,
        ip,
        requestId,
        error: dbError instanceof Error ? dbError.message : 'Unknown database error',
        tokenLength: extractionResult.details.tokenLength,
        duration: Date.now() - startTime
      };
      
      logAuthEvent(logContext);
    }

    // Always proceed to next handler (performance optimization: no early returns)
    next();
  } catch (error) {
    // Handle any unexpected errors gracefully
    const logContext: AuthLogContext = {
      eventType: AuthEventType.UNEXPECTED_ERROR,
      userAgent,
      ip,
      requestId,
      error: error instanceof Error ? error.message : 'Unknown error',
      duration: Date.now() - startTime
    };
    
    logAuthEvent(logContext);
    
    // Ensure req.user is undefined on error and proceed
    req.user = undefined;
    next();
  }
}
