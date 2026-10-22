/**
 * Global Error Handler Middleware with VRT-XXXX Taxonomy System
 *
 * Provides standardized error responses with machine-readable VRT-XXXX codes
 * across the entire API.
 *
 * Error Envelope Format:
 * {
 *   status: "error",
 *   vrtCode: string,     // Machine-readable VRT-XXXX taxonomy code
 *   message: string,     // Human-readable message
 *   details?: any,       // Additional error details (validation errors, etc.)
 *   timestamp: string,   // ISO 8601 timestamp
 *   requestId?: string   // Request ID for tracing (if available)
 * }
 *
 * @module errorHandler
 */

import { Request, Response, NextFunction } from "express";
import { z } from "zod";
import {
  ValidationError,
  AppError,
  VRTErrorCodes,
  isAppError,
  isValidationError,
} from "../types/errors.js";
import { logger } from "../utils/logger.js";

type ErrorEnvelope = {
  status: "error";
  vrtCode: string;
  code?: string;
  message: string;
  timestamp: string;
  requestId?: string;
  details?: unknown;
  errors?: unknown; // Legacy alias for details
};

type PostgresError = Error & {
  code?: string;
  detail?: string;
  constraint?: string;
  table?: string;
  schema?: string;
};

type BodyParserError = {
  status?: unknown;
  statusCode?: unknown;
  type?: unknown;
};

const CLIENT_SAFE_POSTGRES_CONFLICT_CODES = new Set([
  "23503", // foreign_key_violation
  "23505", // unique_violation
]);

function getBodyParserErrorType(error: unknown): string | undefined {
  if (typeof error !== "object" || error === null) {
    return undefined;
  }

  const type = (error as BodyParserError).type;
  return typeof type === "string" ? type : undefined;
}

function getClientErrorStatus(error: unknown): number | undefined {
  if (typeof error !== "object" || error === null) {
    return undefined;
  }

  const candidate = error as BodyParserError;
  for (const status of [candidate.status, candidate.statusCode]) {
    if (typeof status === "number" && Number.isInteger(status) && status >= 400 && status < 500) {
      return status;
    }
  }

  return undefined;
}

function isPostgresError(error: unknown): error is PostgresError {
  return (
    error instanceof Error &&
    typeof (error as PostgresError).code === "string" &&
    /^[0-9A-Z]{5}$/.test((error as PostgresError).code ?? "")
  );
}

function getBodyParserErrorType(error: unknown): string | undefined {
  if (typeof error !== "object" || error === null || !("type" in error)) {
    return undefined;
  }
  const type = (error as BodyParserError).type;
  return typeof type === "string" ? type : undefined;
}

function normalizeZodIssues(
  error: z.ZodError
): Array<{ path: string[]; message: string; code: string }> {
  return error.issues.map((issue) => ({
    path: issue.path.map(String),
    message: issue.message,
    code: issue.code,
  }));
}

/**
 * Generates the standardized error envelope with VRT-XXXX code
 *
 * @param error - The error object
 * @param requestId - Optional request ID for tracing
 * @returns Standardized error response object
 */
function createErrorEnvelope(
  error: unknown,
  requestId?: string
): ErrorEnvelope {
  const timestamp = new Date().toISOString();

  const baseEnvelope: Omit<ErrorEnvelope, "vrtCode" | "message" | "details"> = {
    status: "error",
    timestamp,
  };

  if (requestId) {
    baseEnvelope.requestId = requestId;
  }

  const bodyParserErrorType = getBodyParserErrorType(error);
  if (bodyParserErrorType === "entity.parse.failed") {
    return {
      ...baseEnvelope,
      vrtCode: "INVALID_JSON",
      message: "Invalid JSON payload",
    };
  }
  if (bodyParserErrorType === "entity.too.large") {
    return {
      ...baseEnvelope,
      vrtCode: "PAYLOAD_TOO_LARGE",
      message: "Payload too large",
    };
  }

  // Handle ValidationError
  if (isValidationError(error)) {
    return {
      ...baseEnvelope,
      vrtCode: VRTErrorCodes.VRT_0002,
      message: error.message,
      details: error.details,
      errors: error.details,
    };
  }

  if (error instanceof z.ZodError) {
    const details = normalizeZodIssues(error);

    return {
      ...baseEnvelope,
      vrtCode: VRTErrorCodes.VRT_0002,
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
        vrtCode: error.vrtCode,
        message: "An unexpected error occurred",
      };
    }
    return {
      ...baseEnvelope,
      vrtCode: error.vrtCode,
      message: error.message,
    };
  }

  if (isPostgresError(error)) {
    if (CLIENT_SAFE_POSTGRES_CONFLICT_CODES.has(error.code ?? "")) {
      return {
        ...baseEnvelope,
        vrtCode: VRTErrorCodes.VRT_0005,
        message: "Resource conflict",
      };
    }

    return {
      ...baseEnvelope,
      vrtCode: VRTErrorCodes.VRT_0007,
      message: "An unexpected error occurred",
    };
  }

  // Handle standard Error objects
  if (error instanceof Error) {
    if (error.name === "JsonWebTokenError" || error.name === "TokenExpiredError") {
      return {
        ...baseEnvelope,
        vrtCode: VRTErrorCodes.VRT_0001,
        message: "Authentication required",
      };
    }
  }

  // Fallback to VRT-9999 for any unknown/unhandled errors
  return {
    ...baseEnvelope,
    vrtCode: VRTErrorCodes.VRT_9999,
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
  if (typeof error === "object" && error !== null) {
    const httpError = error as BodyParserError;
    const clientStatus = [httpError.status, httpError.statusCode].find(
      (status): status is number =>
        typeof status === "number" &&
        Number.isInteger(status) &&
        status >= 400 &&
        status <= 499,
    );
    if (clientStatus !== undefined) return clientStatus;
  }

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
    if (error.name === "JsonWebTokenError" || error.name === "TokenExpiredError") {
      return 401;
    }
  }

  const clientErrorStatus = getClientErrorStatus(error);
  if (clientErrorStatus !== undefined) {
    return clientErrorStatus;
  }

  return 500;
}

/**
 * Express error handler middleware
 *
 * Catches all errors from previous middleware/routes and returns
 * a standardized error response with VRT-XXXX taxonomy code.
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
  next: NextFunction
): void => {
  if (res.headersSent) {
    return next(err);
  }

  const requestId = res.locals.requestId;
  const statusCode = getStatusCode(err);

  // Log structured server-side context
  logger.error({
    type: "request_error",
    errorType: err instanceof Error ? err.name : typeof err,
    message: err instanceof Error ? err.message : "Non-Error throwable",
    stack: err instanceof Error ? err.stack : undefined,
    vrtCode: isAppError(err)
      ? err.vrtCode
      : isValidationError(err)
        ? err.vrtCode
        : VRTErrorCodes.VRT_9999,
    statusCode,
    path: req.path,
    method: req.method,
    requestId,
  });

  // Set Retry-After header if present on the error or context
  if (isAppError(err) && err.status === 429) {
    const retryAfterMs =
      (err as any).retryAfterMs ??
      (typeof err.context?.retryAfterMs === "number" ? err.context.retryAfterMs : undefined);
    if (typeof retryAfterMs === "number" && retryAfterMs > 0 && !res.getHeader("Retry-After")) {
      res.setHeader("Retry-After", String(Math.ceil(retryAfterMs / 1000)));
    }
  }

  // Create standardized error envelope
  const errorEnvelope = createErrorEnvelope(err, requestId);

  // Send the response
  res.status(statusCode).json(errorEnvelope);
};

/**
 * Async error wrapper for route handlers
 *
 * Usage: Wrap async route handlers to automatically catch and forward errors
 */
export const asyncErrorHandler = (
  fn: (req: Request, res: Response, next: NextFunction) => Promise<any>
) => {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

/**
 * Not Found handler for unmatched routes
 *
 * Returns a standardized 404 error envelope with VRT-0004
 */
export const notFoundHandler = (req: Request, res: Response): void => {
  res.status(404).json({
    status: "error",
    vrtCode: VRTErrorCodes.VRT_0004,
    message: `Cannot ${req.method} ${req.path}`,
    timestamp: new Date().toISOString(),
    requestId: res.locals.requestId,
  });
};
