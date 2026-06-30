/**
 * Error Types for Veritasor Backend with VRT-XXXX Taxonomy System
 *
 * Provides standardized error classes with machine-readable VRT-XXXX codes
 * for consistent error handling across the application.
 *
 * @module errors
 */

/**
 * Error Taxonomy System Codes
 */
export const VRTErrorCodes = {
  // Generic Internal Errors
  VRT_0001: "VRT-0001", // Unauthorized/Authentication Error
  VRT_0002: "VRT-0002", // Validation Error
  VRT_0003: "VRT-0003", // Authorization Error
  VRT_0004: "VRT-0004", // Not Found
  VRT_0005: "VRT-0005", // Conflict
  VRT_0006: "VRT-0006", // Rate Limit Exceeded
  VRT_0007: "VRT-0007", // Database Error
  VRT_0008: "VRT-0008", // External Service Error
  VRT_9999: "VRT-9999", // Internal Server Error (Fallback)
} as const;

export type VRTErrorCode = typeof VRTErrorCodes[keyof typeof VRTErrorCodes];

/**
 * Base Application Error
 *
 * All custom errors extend this base class which includes:
 * - statusCode: HTTP status code
 * - vrtCode: Machine-readable VRT-XXXX taxonomy code
 * - context: Optional context payload for debugging
 */
export class AppError extends Error {
  public status: number;
  public vrtCode: VRTErrorCode;
  public context?: Record<string, unknown>;

  constructor(
    message: string,
    status: number = 500,
    vrtCode: VRTErrorCode = VRTErrorCodes.VRT_9999,
    context?: Record<string, unknown>
  ) {
    super(message);
    this.name = "AppError";
    this.status = status;
    this.vrtCode = vrtCode;
    this.context = context;
    Object.setPrototypeOf(this, AppError.prototype);
  }
}

/**
 * ValidationError - Used when request validation fails
 */
export class ValidationError extends Error {
  public status: number;
  public vrtCode: VRTErrorCode;
  public details: any[];
  public context?: Record<string, unknown>;

  constructor(details: any[], context?: Record<string, unknown>) {
    super("Validation Error");
    this.name = "ValidationError";
    this.status = 400;
    this.vrtCode = VRTErrorCodes.VRT_0002;
    this.details = details;
    this.context = context;
  }
}

/**
 * UnauthorizedError - Used for auth-related errors (401)
 */
export class UnauthorizedError extends AppError {
  constructor(
    message: string = "Authentication required",
    context?: Record<string, unknown>
  ) {
    super(message, 401, VRTErrorCodes.VRT_0001, context);
    this.name = "UnauthorizedError";
  }
}

/**
 * AuthenticationError - Alias for UnauthorizedError (backward compatibility)
 *
 * @deprecated Use UnauthorizedError instead
 */
export class AuthenticationError extends UnauthorizedError {
  constructor(
    message: string = "Authentication required",
    context?: Record<string, unknown>
  ) {
    super(message, context);
    this.name = "AuthenticationError";
  }
}

/**
 * AuthorizationError - Used when user lacks permissions (403)
 */
export class AuthorizationError extends AppError {
  constructor(
    message: string = "Access denied",
    context?: Record<string, unknown>
  ) {
    super(message, 403, VRTErrorCodes.VRT_0003, context);
    this.name = "AuthorizationError";
  }
}

/**
 * NotFoundError - Used when resource doesn't exist (404)
 */
export class NotFoundError extends AppError {
  constructor(
    message: string = "Resource not found",
    context?: Record<string, unknown>
  ) {
    super(message, 404, VRTErrorCodes.VRT_0004, context);
    this.name = "NotFoundError";
  }
}

/**
 * ConflictError - Used for resource conflicts (409)
 */
export class ConflictError extends AppError {
  constructor(
    message: string = "Resource conflict",
    context?: Record<string, unknown>
  ) {
    super(message, 409, VRTErrorCodes.VRT_0005, context);
    this.name = "ConflictError";
  }
}

/**
 * RateLimitError - Used when rate limit is exceeded (429)
 */
export class RateLimitError extends AppError {
  constructor(
    message: string = "Rate limit exceeded",
    context?: Record<string, unknown>
  ) {
    super(message, 429, VRTErrorCodes.VRT_0006, context);
    this.name = "RateLimitError";
  }
}

/**
 * DatabaseError - Used for database-related errors (500)
 */
export class DatabaseError extends AppError {
  constructor(
    message: string = "Database operation failed",
    context?: Record<string, unknown>
  ) {
    super(message, 500, VRTErrorCodes.VRT_0007, context);
    this.name = "DatabaseError";
  }
}

/**
 * ExternalServiceError - Used when external service calls fail (502/503)
 */
export class ExternalServiceError extends AppError {
  constructor(
    message: string = "External service unavailable",
    status: number = 503,
    context?: Record<string, unknown>
  ) {
    super(message, status, VRTErrorCodes.VRT_0008, context);
    this.name = "ExternalServiceError";
  }
}

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
