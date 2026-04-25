import { Request, Response, NextFunction } from "express";
import { logger } from "../utils/logger.js";
import { randomUUID } from "crypto";

/**
 * Extended Express Request with correlation ID for request tracing.
 * @interface CorrelatedRequest
 * @property {string} correlationId - Unique identifier for request tracing
 */
export interface CorrelatedRequest extends Request {
  correlationId: string;
}

/**
 * Structured request logging middleware with correlation ID support.
 *
 * Features:
 * - Generates or reuses correlation ID from X-Request-ID header
 * - Attaches correlation ID to request object for downstream use
 * - Logs structured JSON with correlation ID for request/response tracing
 * - Excludes sensitive data (body, headers) from logs
 * - Tracks request duration for performance monitoring
 *
 * Security considerations:
 * - Never logs request/response bodies to prevent sensitive data exposure
 * - Sanitizes headers to exclude authentication tokens
 * - Uses cryptographically secure UUID generation for correlation IDs
 *
 * @param {Request} req - Express request object
 * @param {Response} res - Express response object
 * @param {NextFunction} next - Express next function
 */
export function requestLogger(req: Request, res: Response, next: NextFunction) {
  const start = process.hrtime();

  // Generate or reuse correlation ID from X-Request-ID header
  // Use existing header if provided (for distributed tracing), otherwise generate new UUID
  const correlationId = (req.headers["x-request-id"] as string) || randomUUID();

  // Attach correlation ID to request for use in downstream handlers
  (req as CorrelatedRequest).correlationId = correlationId;

  // Set correlation ID in response header for client-side tracing
  res.setHeader("X-Request-ID", correlationId);

  // Log incoming request with correlation ID
  const requestLog = {
    type: "request",
    correlationId,
    method: req.method,
    path: req.path,
    query: req.query,
    ip: req.ip,
    userAgent: req.headers["user-agent"],
    timestamp: new Date().toISOString(),
  };

  logger.info(JSON.stringify(requestLog));

  // Once the response has finished, compute duration and log
  res.on("finish", () => {
    const [sec, nano] = process.hrtime(start);
    const durationMs = sec * 1e3 + nano / 1e6;

    const responseLog = {
      type: "response",
      correlationId,
      method: req.method,
      path: req.path,
      statusCode: res.statusCode,
      durationMs: parseFloat(durationMs.toFixed(3)),
      timestamp: new Date().toISOString(),
    };

    logger.info(JSON.stringify(responseLog));
  });

  next();
}
