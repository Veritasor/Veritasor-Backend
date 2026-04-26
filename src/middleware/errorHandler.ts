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
 *   errors?: any,        // Legacy validation details alias
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
import { z } from "zod";
import {
  ValidationError,
  AppError,
  ErrorCodes,
  isAppError,
  isValidationError,
} from "../types/errors.js";

type ErrorEnvelope = {
  status: "error";
  code: string;
  message: string;
  timestamp: string;
  requestId?: string;
  details?: unknown;
  errors?: unknown;
};

type PostgresError = Error & {
  code?: string;
  detail?: string;
  constraint?: string;
  table?: string;
  schema?: string;
};

const CLIENT_SAFE_POSTGRES_CONFLICT_CODES = new Set([
  "23503", // foreign_key_violation
  "23505", // unique_violation
]);

function sanitizeErrorCode(code: string | undefined, fallback: string): string {
  if (!code || !/^[A-Z0-9_]+$/.test(code)) {
    return fallback;
  }

  return code;
}

function isPostgresError(error: unknown): error is PostgresError {
  return (
    error instanceof Error &&
    typeof (error as PostgresError).code === "string" &&
    /^[0-9A-Z]{5}$/.test((error as PostgresError).code ?? "")
  );
}

function normalizeZodIssues(error: z.ZodError): Array<{ path: string[]; message: string; code: string }> {
  return error.issues.map((issue) => ({
    path: issue.path.map(String),
    message: issue.message,
    code: issue.code,
  }));
}

/**
 * Generates the standardized error envelope
 * 
 * @param error - The error object
 * @param requestId - Optional request ID for tracing
 * @returns Standardized error response object
 */
function createErrorEnvelope(error: unknown, requestId?: string): ErrorEnvelope {
  const timestamp = new Date().toISOString();
  
  const baseEnvelope: Omit<ErrorEnvelope, "code" | "message" | "details"> = {
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
      code: ErrorCodes.VALIDATION_ERROR,
      message: error.message,
      details: error.details,
      errors: error.details,
    };
  }

  if (error instanceof z.ZodError) {
    const details = normalizeZodIssues(error);

    return {
      ...baseEnvelope,
      code: ErrorCodes.VALIDATION_ERROR,
      message: "Validation Error",
      details,
      errors: details,
    };
  }
  
  // Handle AppError and subclasses
  if (isAppError(error)) {
    // For 5xx errors, use generic message to prevent info leakage
    if (error.status >= 500) {
      return {
        ...baseEnvelope,
        code: sanitizeErrorCode(error.code, ErrorCodes.INTERNAL_SERVER_ERROR),
        message: "An unexpected error occurred",
      };
    }
    return {
      ...baseEnvelope,
      code: sanitizeErrorCode(error.code, ErrorCodes.INTERNAL_SERVER_ERROR),
      message: error.message,
    };
  }

  if (isPostgresError(error)) {
    if (CLIENT_SAFE_POSTGRES_CONFLICT_CODES.has(error.code ?? "")) {
      return {
        ...baseEnvelope,
        code: ErrorCodes.CONFLICT,
        message: "Resource conflict",
      };
    }

    return {
      ...baseEnvelope,
      code: ErrorCodes.DATABASE_ERROR,
      message: "An unexpected error occurred",
    };
  }
  
  // Handle standard Error objects
  if (error instanceof Error) {
    // Don't expose internal error messages for generic errors
    return {
      ...baseEnvelope,
      code: ErrorCodes.INTERNAL_SERVER_ERROR,
      message: "An unexpected error occurred",
    };
  }
  
  // Handle unknown errors
  return {
    ...baseEnvelope,
    code: ErrorCodes.INTERNAL_SERVER_ERROR,
    message: "An unexpected error occurred",
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

  if (error instanceof z.ZodError) {
    return 400;
  }
  
  if (isAppError(error)) {
    return error.status;
  }

  if (isPostgresError(error)) {
    if (CLIENT_SAFE_POSTGRES_CONFLICT_CODES.has(error.code ?? "")) {
      return 409;
    }

    return 500;
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
  
  const statusCode = getStatusCode(err);
  
  // Log structured server-side context without leaking DB details or request bodies.
  console.error("[Error]", {
    level: "error",
    errorType: err instanceof Error ? err.name : typeof err,
    message: err instanceof Error ? err.message : "Non-Error throwable",
    stack: err instanceof Error ? err.stack : undefined,
    errorCode: isAppError(err)
      ? sanitizeErrorCode(err.code, ErrorCodes.INTERNAL_SERVER_ERROR)
      : isPostgresError(err)
        ? err.code
        : undefined,
    statusCode,
    path: req.path,
    method: req.method,
    requestId,
    timestamp: new Date().toISOString(),
  });
  
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
