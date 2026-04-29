/**
 * Signup Service with Abuse Prevention
 *
 * This service handles user registration with comprehensive abuse prevention
 * heuristics including:
 * - Email validation and disposable email blocking
 * - Password strength requirements
 * - Rate limiting per IP and email
 * - Timing attack prevention
 * - Suspicious pattern detection
 *
 * @module services/auth/signup
 */
import { createUser, findUserByEmail, } from "../../repositories/userRepository.js";
import { hashPassword } from "../../utils/password.js";
import { generateToken, generateRefreshToken } from "../../utils/jwt.js";
import { validateEmail, validatePassword, normalizeEmail, addTimingDelay, DEFAULT_ABUSE_PREVENTION_CONFIG, } from "../../utils/abusePrevention.js";
import { getSignupRateLimitStore, } from "../../utils/signupRateLimiter.js";
import { logger } from "../../utils/logger.js";
/**
 * Custom error class for signup-specific errors
 */
export class SignupError extends Error {
    type;
    statusCode;
    details;
    constructor(message, type, statusCode = 400, details) {
        super(message);
        this.name = "SignupError";
        this.type = type;
        this.statusCode = statusCode;
        this.details = details;
    }
}
/**
 * Default configuration for signup service
 */
export const DEFAULT_SIGNUP_SERVICE_CONFIG = {
    abusePrevention: DEFAULT_ABUSE_PREVENTION_CONFIG,
    rateLimit: {},
    minOperationTimeMs: 200, // Minimum 200ms for timing attack prevention
    enableHoneypot: true,
    enableSuspiciousActivityLogging: true,
};
/**
 * Validate signup request with comprehensive checks.
 *
 * @param request - The signup request to validate
 * @param config - Service configuration
 * @returns Validation result with normalized email and any errors
 */
function validateSignupRequest(request, config) {
    const errors = [];
    const warnings = [];
    let normalizedEmail = "";
    // Check honeypot field
    if (config.enableHoneypot && request.website) {
        errors.push(new SignupError("Invalid request", "HONEYPOT_TRIGGERED", 400, [
            "Honeypot field must be empty",
        ]));
        return { valid: false, normalizedEmail: "", errors, warnings };
    }
    // Validate presence and type of required fields before delegating to deeper
    // validators. This guards against null/undefined/non-string payloads that
    // would otherwise surface as opaque downstream errors and ensures every
    // SignupError carries actionable `details` for clients.
    const missingFields = [];
    if (request.email === undefined || request.email === null) {
        missingFields.push("email is required");
    }
    else if (typeof request.email !== "string") {
        missingFields.push("email must be a string");
    }
    else if (request.email.trim().length === 0) {
        missingFields.push("email must not be empty");
    }
    if (request.password === undefined || request.password === null) {
        missingFields.push("password is required");
    }
    else if (typeof request.password !== "string") {
        missingFields.push("password must be a string");
    }
    else if (request.password.length === 0) {
        missingFields.push("password must not be empty");
    }
    if (missingFields.length > 0) {
        errors.push(new SignupError("Missing or invalid required fields", "VALIDATION_ERROR", 400, missingFields));
        return { valid: false, normalizedEmail: "", errors, warnings };
    }
    // Validate email
    const emailValidation = validateEmail(request.email, config.abusePrevention);
    if (!emailValidation.isValid) {
        if (emailValidation.isDisposable) {
            errors.push(new SignupError("Disposable email addresses are not allowed", "EMAIL_DISPOSABLE", 400));
        }
        else {
            errors.push(new SignupError("Invalid email address", "EMAIL_INVALID", 400, emailValidation.errors));
        }
    }
    else {
        normalizedEmail = emailValidation.normalizedEmail;
        // Add warnings for suspicious patterns
        if (emailValidation.isSuspicious) {
            warnings.push(...emailValidation.warnings);
        }
    }
    // Validate password
    const passwordValidation = validatePassword(request.password, config.abusePrevention);
    if (!passwordValidation.isValid) {
        errors.push(new SignupError("Password does not meet security requirements", "PASSWORD_WEAK", 400, passwordValidation.errors));
    }
    // Add password warnings
    warnings.push(...passwordValidation.warnings);
    return {
        valid: errors.length === 0,
        normalizedEmail,
        errors,
        warnings,
    };
}
/**
 * Register a new user with comprehensive abuse prevention.
 *
 * This function implements multiple layers of protection:
 * 1. Input validation (email format, password strength)
 * 2. Disposable email blocking
 * 3. Rate limiting per IP and email
 * 4. Honeypot bot detection
 * 5. Timing attack prevention (constant response time)
 * 6. Suspicious activity detection
 *
 * @param request - The signup request containing email and password
 * @param config - Optional configuration overrides
 * @returns Signup response with tokens and user info
 * @throws {SignupError} When signup fails validation or rate limiting
 *
 * @example
 * ```typescript
 * try {
 *   const result = await signup({
 *     email: 'user@example.com',
 *     password: 'SecureP@ss123',
 *     ipAddress: '192.168.1.1'
 *   });
 *   console.log('User created:', result.user.id);
 * } catch (error) {
 *   if (error instanceof SignupError) {
 *     console.error('Signup failed:', error.type, error.message);
 *   }
 * }
 * ```
 */
export async function signup(request, config = {}) {
    const startTime = Date.now();
    const fullConfig = {
        ...DEFAULT_SIGNUP_SERVICE_CONFIG,
        ...config,
        abusePrevention: {
            ...DEFAULT_SIGNUP_SERVICE_CONFIG.abusePrevention,
            ...config.abusePrevention,
        },
    };
    // Get client IP (use placeholder if not provided - shouldn't happen in production)
    const clientIp = request.ipAddress || "unknown";
    // Get rate limiter
    const rateLimiter = getSignupRateLimitStore(fullConfig.rateLimit);
    // Phase 1: Validate request
    const validation = validateSignupRequest(request, fullConfig);
    if (!validation.valid) {
        // Apply timing delay before throwing to prevent timing attacks
        await addTimingDelay(fullConfig.minOperationTimeMs, startTime);
        // Best-effort failure recording: only attempt with a usable email so we
        // don't poison the rate limiter on payloads that never had a string email.
        const failureEmail = validation.normalizedEmail ||
            (typeof request.email === "string" ? normalizeEmail(request.email) : "");
        rateLimiter.recordFailure(clientIp, failureEmail);
        const firstError = validation.errors[0];
        logger.warn(JSON.stringify({
            event: "signup.validation_failed",
            type: firstError.type,
            clientIp,
        }));
        throw firstError;
    }
    const { normalizedEmail } = validation;
    // Phase 2: Check rate limits
    const rateLimitCheck = rateLimiter.checkLimit(clientIp, normalizedEmail);
    if (!rateLimitCheck.allowed) {
        // Apply progressive delay if configured
        if (rateLimitCheck.suggestedDelayMs > 0) {
            await new Promise((resolve) => setTimeout(resolve, rateLimitCheck.suggestedDelayMs));
        }
        await addTimingDelay(fullConfig.minOperationTimeMs, startTime);
        logger.warn(JSON.stringify({
            event: "signup.rate_limited",
            clientIp,
            reason: rateLimitCheck.blockReason || "Rate limit exceeded",
        }));
        throw new SignupError(rateLimitCheck.blockReason ||
            "Too many signup attempts. Please try again later.", "RATE_LIMITED", 429, [rateLimitCheck.blockReason || "Rate limit exceeded"]);
    }
    // Record the attempt
    rateLimiter.recordAttempt(clientIp, normalizedEmail);
    // Phase 3: Check for existing user
    // We do this after rate limiting to avoid database hits from rate-limited requests
    const existingUser = await findUserByEmail(normalizedEmail);
    if (existingUser) {
        // Apply timing delay to prevent timing attacks (don't reveal if email exists)
        await addTimingDelay(fullConfig.minOperationTimeMs, startTime);
        // Record failed attempt (for progressive delays)
        rateLimiter.recordFailure(clientIp, normalizedEmail);
        logger.info(JSON.stringify({
            event: "signup.duplicate_email_attempt",
            clientIp,
        }));
        // Don't reveal whether email exists - use same message as invalid credentials
        throw new SignupError("Unable to create account. Please check your information and try again.", "EMAIL_EXISTS", 400, // Use 400 instead of 409 to prevent email enumeration
        ["Account could not be created with the provided information"]);
    }
    // Phase 4: Create the user
    try {
        const passwordHash = await hashPassword(request.password);
        // Re-check for an existing user immediately before creation to close the
        // race window between the existence check and the insert. This makes
        // concurrent identical signups idempotent: only one succeeds and the
        // others receive the same generic EMAIL_EXISTS response.
        const raceCheck = await findUserByEmail(normalizedEmail);
        if (raceCheck) {
            await addTimingDelay(fullConfig.minOperationTimeMs, startTime);
            rateLimiter.recordFailure(clientIp, normalizedEmail);
            logger.info(JSON.stringify({
                event: "signup.duplicate_email_race",
                clientIp,
            }));
            throw new SignupError("Unable to create account. Please check your information and try again.", "EMAIL_EXISTS", 400, ["Account could not be created with the provided information"]);
        }
        const user = await createUser(normalizedEmail, passwordHash);
        // Generate tokens
        const accessToken = generateToken({
            userId: user.id,
            email: user.email,
        });
        const refreshToken = generateRefreshToken({
            userId: user.id,
            email: user.email,
        });
        // Record successful signup
        rateLimiter.recordSuccess(clientIp, normalizedEmail);
        // Apply timing delay to ensure consistent response time
        await addTimingDelay(fullConfig.minOperationTimeMs, startTime);
        logger.info(JSON.stringify({
            event: "signup.success",
            userId: user.id,
            clientIp,
        }));
        return {
            accessToken,
            refreshToken,
            user: {
                id: user.id,
                email: user.email,
            },
        };
    }
    catch (error) {
        // Record failed attempt
        rateLimiter.recordFailure(clientIp, normalizedEmail);
        // Apply timing delay
        await addTimingDelay(fullConfig.minOperationTimeMs, startTime);
        // Re-throw SignupError instances unchanged so callers can react on .type
        if (error instanceof SignupError) {
            throw error;
        }
        logger.error(JSON.stringify({
            event: "signup.unexpected_error",
            clientIp,
            message: error instanceof Error ? error.message : "unknown",
        }));
        throw new SignupError("An error occurred during signup. Please try again.", "VALIDATION_ERROR", 500, ["Unexpected internal error"]);
    }
}
/**
 * Check if signup is available for a given IP and email.
 * Useful for pre-validation before showing signup form.
 *
 * @param ipAddress - Client IP address
 * @param email - Email to check (optional)
 * @param config - Rate limit configuration
 * @returns Rate limit status
 */
export function checkSignupAvailability(ipAddress, email, config = {}) {
    const rateLimiter = getSignupRateLimitStore(config);
    const normalizedEmail = email ? normalizeEmail(email) : "";
    const result = rateLimiter.checkLimit(ipAddress, normalizedEmail);
    return {
        available: result.allowed && !result.isBlocked,
        remainingAttempts: result.remainingAttempts,
        resetIn: result.resetIn,
        message: result.blockReason,
    };
}
/**
 * Get signup rate limit headers for HTTP response.
 *
 * @param ipAddress - Client IP address
 * @param email - Email to check
 * @param config - Rate limit configuration
 * @returns Headers object for HTTP response
 */
export function getSignupRateLimitHeaders(ipAddress, email, config = {}) {
    const rateLimiter = getSignupRateLimitStore(config);
    const result = rateLimiter.checkLimit(ipAddress, normalizeEmail(email));
    return result.headers;
}
