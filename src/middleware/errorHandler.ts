/**
 * Global Error Handler Middleware
 * 
 * Provides standardized error responses across the entire API.
 * All errors are transformed into a consistent error envelope format.
 * 
 * Error Envelope Format:
 * {
 *   status: "error",
 *   code: string,        // Machine-readable error code
 *   message: string,     // Human-readable message
 *   details?: any,       // Additional error details (validation errors, etc.)
 *   timestamp: string,   // ISO 8601 timestamp
 *   requestId?: string   // Request ID for tracing (if available)
 * }
 * 
 * Assumptions:
 * - Express error-first middleware pattern
 * - All custom errors extend AppError or ValidationError
 * - Request ID is stored in res.locals.requestId by requestLogger
 * - Errors are logged to console for debugging
 * 
 * Security Considerations:
 * - Internal errors (500) return generic message to prevent info leakage
 * - Stack traces are never exposed in production
 * - Error codes are sanitized to prevent injection
 * 
 * @module errorHandler
 */

import { Request, Response, NextFunction } from "express";
import {
  ValidationError,
  AppError,
  AuthenticationError,
  AuthorizationError,
  NotFoundError,
  ConflictError,
  RateLimitError,
  DatabaseError,
  ExternalServiceError,
  isAppError,
  isValidationError,
} from "../types/errors.js";

/**
 * Generates the standardized error envelope
 * 
 * @param error - The error object
 * @param requestId - Optional request ID for tracing
 * @returns Standardized error response object
 */
function createErrorEnvelope(error: unknown, requestId?: string): Record<string, any> {
  const timestamp = new Date().toISOString();
  
  const baseEnvelope: Record<string, any> = {
    status: "error",
    timestamp,
  };
  
  // Add requestId if available
  if (requestId) {
    baseEnvelope.requestId = requestId;
  }
  
  // Handle ValidationError
  if (isValidationError(error)) {
    return {
      ...baseEnvelope,
      code: "VALIDATION_ERROR",
      message: error.message,
      details: error.details,
    };
  }
  
  // Handle AppError and subclasses
  if (isAppError(error)) {
    // For 5xx errors, use generic message to prevent info leakage
    if (error.status >= 500) {
      return {
        ...baseEnvelope,
        code: error.code,
        message: "An unexpected error occurred",
      };
    }
    return {
      ...baseEnvelope,
      code: error.code,
      message: error.message,
    };
  }
  
  // Handle standard Error objects
  if (error instanceof Error) {
    // Don't expose internal error messages for generic errors
    return {
      ...baseEnvelope,
      code: "INTERNAL_SERVER_ERROR",
      message: "An unexpected error occurred",
    };
  }
  
  // Handle unknown errors
  return {
    ...baseEnvelope,
    code: "UNKNOWN_ERROR",
    message: "An unknown error occurred",
  };
}

/**
 * Maps error types to appropriate HTTP status codes
 * 
 * @param error - The error object
 * @returns HTTP status code
 */
function getStatusCode(error: unknown): number {
  if (isValidationError(error)) {
    return 400;
  }
  
  if (isAppError(error)) {
    return error.status;
  }
  
  if (error instanceof Error) {
    // Check for common Node.js errors
    if (error.name === "JsonWebTokenError") {
      return 401;
    }
    if (error.name === "TokenExpiredError") {
      return 401;
    }
  }
  
  return 500;
}

/**
 * Express error handler middleware
 * 
 * Catches all errors from previous middleware/routes and returns
 * a standardized error response.
 * 
 * @param err - Error object (any type, but typically Error or AppError)
 * @param req - Express Request object
 * @param res - Express Response object
 * @param next - Express NextFunction (required for error middleware signature)
 */
export const errorHandler = (
  err: unknown,
  req: Request,
  res: Response,
  next: NextFunction,
): void => {
  // Extract request ID if available (set by requestLogger middleware)
  const requestId = res.locals.requestId;
  
  // Log the error for debugging (use console.error for server-side logging)
  // In production, this would go to a proper logging service
  console.error("[Error]", {
    message: err instanceof Error ? err.message : "Unknown error",
    stack: err instanceof Error ? err.stack : undefined,
    path: req.path,
    method: req.method,
    requestId,
    timestamp: new Date().toISOString(),
  });
  
  // Determine appropriate status code
  const statusCode = getStatusCode(err);
  
  // Create standardized error envelope
  const errorEnvelope = createErrorEnvelope(err, requestId);
  
  // Send the response
  res.status(statusCode).json(errorEnvelope);
};

/**
 * Async error wrapper for route handlers
 * 
 * Usage: Wrap async route handlers to automatically catch and forward errors
 * 
 * @example
 * router.get('/users', asyncErrorHandler(async (req, res) => {
 *   const users = await getUsers();
 *   res.json(users);
 * }));
 */
export const asyncErrorHandler = (
  fn: (req: Request, res: Response, next: NextFunction) => Promise<any>,
) => {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

/**
 * Not Found handler for unmatched routes
 * 
 * Returns a standardized 404 error envelope
 */
export const notFoundHandler = (req: Request, res: Response): void => {
  res.status(404).json({
    status: "error",
    code: "NOT_FOUND",
    message: `Cannot ${req.method} ${req.path}`,
    timestamp: new Date().toISOString(),
    requestId: res.locals.requestId,
  });
};
