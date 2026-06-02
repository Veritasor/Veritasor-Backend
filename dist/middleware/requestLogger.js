import { logger, runWithLoggerContext } from "../utils/logger.js";
import { randomUUID } from "crypto";
import { httpRequestDuration } from "../metrics.js";
const REDACTED = "[REDACTED]";
const CORRELATION_ID_HEADER = "x-correlation-id";
const LEGACY_REQUEST_ID_HEADER = "x-request-id";
const CORRELATION_ID_PATTERN = /^[a-zA-Z0-9._:/=@-]{8,128}$/;
/** Headers whose values must never appear in logs. */
export const REDACTED_HEADERS = new Set([
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
]);
/** Query parameter names whose values must never appear in logs. */
export const REDACTED_QUERY_PARAMS = new Set([
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "secret",
    "password",
    "reset_token",
    "code",
]);
export function sanitizeCorrelationId(value) {
    const candidate = Array.isArray(value) ? value[0] : value;
    if (typeof candidate !== "string") {
        return undefined;
    }
    const trimmed = candidate.trim();
    if (!CORRELATION_ID_PATTERN.test(trimmed)) {
        return undefined;
    }
    return trimmed;
}
function redactQuery(query) {
    const result = {};
    for (const [key, value] of Object.entries(query)) {
        result[key] = REDACTED_QUERY_PARAMS.has(key.toLowerCase()) ? REDACTED : value;
    }
    return result;
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
export function requestLogger(req, res, next) {
    const start = process.hrtime();
    const correlationId = sanitizeCorrelationId(req.headers[CORRELATION_ID_HEADER]) ??
        sanitizeCorrelationId(req.headers[LEGACY_REQUEST_ID_HEADER]) ??
        randomUUID();
    req.correlationId = correlationId;
    res.locals.requestId = correlationId;
    res.locals.correlationId = correlationId;
    res.setHeader("X-Correlation-ID", correlationId);
    res.setHeader("X-Request-ID", correlationId);
    return runWithLoggerContext({ correlationId }, () => {
        logger.info({
            type: "request",
            method: req.method,
            path: req.path,
            query: redactQuery(req.query),
            ip: req.ip,
            userAgent: req.headers["user-agent"],
        });
        res.on("finish", () => {
            const [sec, nano] = process.hrtime(start);
            const durationMs = sec * 1e3 + nano / 1e6;
            const durationSec = sec + nano / 1e9;
            const route = req.route?.path ?? req.path;
            httpRequestDuration.observe({ method: req.method, route, status_code: String(res.statusCode) }, durationSec);
            logger.info({
                type: "response",
                method: req.method,
                path: req.path,
                statusCode: res.statusCode,
                durationMs: parseFloat(durationMs.toFixed(3)),
            });
        });
        next();
    });
}
