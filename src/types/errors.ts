/**
 * Error Types for Veritasor Backend
 * 
 * Provides standardized error classes for consistent error handling
 * across the application. All errors follow the global error envelope
 * standard for API responses.
 * 
 * @module errors
 */

/**
 * ValidationError - Used when request validation fails
 * 
 * Assumptions:
 * - Status code is always 400
 * - Details contains array of validation issues
 * - Used by express-validator or custom validation logic
 */
export class ValidationError extends Error {
  public status: number;
  public details: any[];

  constructor(details: any[]) {
    super("Validation Error");
    this.name = "ValidationError";
    this.status = 400;
    this.details = details;
  }
}

/**
 * AppError - Base application error class
 * 
 * Assumptions:
 * - Default status is 500 for server errors
 * - Default code is INTERNAL_SERVER_ERROR
 * - Can be extended for specific error types
 * 
 * @param message - Human-readable error message
 * @param status - HTTP status code
 * @param code - Machine-readable error code
 */
export class AppError extends Error {
  public status: number;
  public code: string;

  constructor(message: string, status: number = 500, code: string = 'INTERNAL_SERVER_ERROR') {
    super(message);
    this.name = 'AppError';
    this.status = status;
    this.code = code;
  }
}

/**
 * AuthenticationError - Used for auth-related errors (401)
 * 
 * Assumptions:
 * - Status code is always 401
 * - Used for invalid credentials, expired tokens, etc.
 */
export class AuthenticationError extends AppError {
  constructor(message: string = 'Authentication required') {
    super(message, 401, 'AUTHENTICATION_ERROR');
    this.name = 'AuthenticationError';
  }
}

/**
 * AuthorizationError - Used when user lacks permissions (403)
 * 
 * Assumptions:
 * - Status code is always 403
 * - User is authenticated but not authorized for the resource
 */
export class AuthorizationError extends AppError {
  constructor(message: string = 'Access denied') {
    super(message, 403, 'AUTHORIZATION_ERROR');
    this.name = 'AuthorizationError';
  }
}

/**
 * NotFoundError - Used when resource doesn't exist (404)
 * 
 * Assumptions:
 * - Status code is always 404
 * - Used for missing users, businesses, attestations, etc.
 */
export class NotFoundError extends AppError {
  constructor(message: string = 'Resource not found') {
    super(message, 404, 'NOT_FOUND');
    this.name = 'NotFoundError';
  }
}

/**
 * ConflictError - Used for resource conflicts (409)
 * 
 * Assumptions:
 * - Status code is always 409
 * - Used for duplicate emails, write conflicts, etc.
 */
export class ConflictError extends AppError {
  constructor(message: string = 'Resource conflict') {
    super(message, 409, 'CONFLICT');
    this.name = 'ConflictError';
  }
}

/**
 * RateLimitError - Used when rate limit is exceeded (429)
 * 
 * Assumptions:
 * - Status code is always 429
 * - Used by rate limiter middleware
 */
export class RateLimitError extends AppError {
  constructor(message: string = 'Rate limit exceeded') {
    super(message, 429, 'RATE_LIMIT_EXCEEDED');
    this.name = 'RateLimitError';
  }
}

/**
 * DatabaseError - Used for database-related errors (500)
 * 
 * Assumptions:
 * - Status code is 500
 * - Message should not expose internal DB details
 * - Logs should contain detailed error info
 */
export class DatabaseError extends AppError {
  constructor(message: string = 'Database operation failed') {
    super(message, 500, 'DATABASE_ERROR');
    this.name = 'DatabaseError';
  }
}

/**
 * ExternalServiceError - Used when external service calls fail (502/503)
 * 
 * Assumptions:
 * - Status code is 502 (Bad Gateway) or 503 (Service Unavailable)
 * - Used for Stripe, Shopify, Razorpay API failures
 */
export class ExternalServiceError extends AppError {
  constructor(message: string = 'External service unavailable', status: number = 503) {
    super(message, status, 'EXTERNAL_SERVICE_ERROR');
    this.name = 'ExternalServiceError';
  }
}

/**
 * Error code constants for common errors
 */
export const ErrorCodes = {
  // Validation errors
  VALIDATION_ERROR: 'VALIDATION_ERROR',
  
  // Authentication errors
  AUTHENTICATION_ERROR: 'AUTHENTICATION_ERROR',
  INVALID_CREDENTIALS: 'INVALID_CREDENTIALS',
  TOKEN_EXPIRED: 'TOKEN_EXPIRED',
  TOKEN_INVALID: 'TOKEN_INVALID',
  
  // Authorization errors
  AUTHORIZATION_ERROR: 'AUTHORIZATION_ERROR',
  INSUFFICIENT_PERMISSIONS: 'INSUFFICIENT_PERMISSIONS',
  
  // Resource errors
  NOT_FOUND: 'NOT_FOUND',
  CONFLICT: 'CONFLICT',
  ALREADY_EXISTS: 'ALREADY_EXISTS',
  
  // Rate limiting
  RATE_LIMIT_EXCEEDED: 'RATE_LIMIT_EXCEEDED',
  
  // Server errors
  INTERNAL_SERVER_ERROR: 'INTERNAL_SERVER_ERROR',
  DATABASE_ERROR: 'DATABASE_ERROR',
  EXTERNAL_SERVICE_ERROR: 'EXTERNAL_SERVICE_ERROR',
  
  // Business logic errors
  INVALID_STATE: 'INVALID_STATE',
  BUSINESS_RULE_VIOLATION: 'BUSINESS_RULE_VIOLATION',
} as const;

/**
 * Type guard to check if error is an AppError
 */
export function isAppError(error: unknown): error is AppError {
  return error instanceof AppError;
}

/**
 * Type guard to check if error is a ValidationError
 */
export function isValidationError(error: unknown): error is ValidationError {
  return error instanceof ValidationError;
}
