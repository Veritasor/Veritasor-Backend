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
        errors.push(new SignupError("Invalid request", "HONEYPOT_TRIGGERED", 400));
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
        // Record failed attempt
        rateLimiter.recordFailure(clientIp, validation.normalizedEmail || normalizeEmail(request.email));
        // Return the first error
        throw validation.errors[0];
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
        // Don't reveal whether email exists - use same message as invalid credentials
        throw new SignupError("Unable to create account. Please check your information and try again.", "EMAIL_EXISTS", 400);
    }
    // Phase 4: Create the user
    try {
        const passwordHash = await hashPassword(request.password);
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
        // Re-throw with appropriate error type
        if (error instanceof SignupError) {
            throw error;
        }
        throw new SignupError("An error occurred during signup. Please try again.", "VALIDATION_ERROR", 500);
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
