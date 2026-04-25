/**
 * Signup Rate Limiter Store
 *
 * Specialized rate limiting for the signup endpoint that tracks:
 * - Signup attempts per IP address
 * - Failed signup attempts (for progressive delays)
 * - Global signup rate (to detect distributed attacks)
 *
 * @module signupRateLimiter
 */
/**
 * Default configuration for signup rate limiting
 */
export const DEFAULT_SIGNUP_RATE_LIMIT_CONFIG = {
    windowMs: 60 * 60 * 1000, // 1 hour
    maxAttemptsPerIp: 5,
    maxAttemptsPerEmail: 3,
    maxGlobalAttempts: 1000,
    blockDurationMs: 24 * 60 * 60 * 1000, // 24 hours
    progressiveDelayThreshold: 2,
    enableProgressiveDelay: true,
};
/**
 * In-memory store for signup rate limiting records.
 * In production, this should be replaced with Redis or similar.
 */
class SignupRateLimitStore {
    ipStore = new Map();
    emailStore = new Map();
    globalRecord = {
        attemptCount: 0,
        failedAttempts: 0,
        windowStart: Date.now(),
        expiresAt: Date.now() + DEFAULT_SIGNUP_RATE_LIMIT_CONFIG.windowMs,
        isBlocked: false,
    };
    config;
    cleanupInterval = null;
    constructor(config = {}) {
        this.config = { ...DEFAULT_SIGNUP_RATE_LIMIT_CONFIG, ...config };
        this.startCleanup();
    }
    /**
     * Start the cleanup interval to remove expired records
     */
    startCleanup() {
        // Clean up every 5 minutes
        this.cleanupInterval = setInterval(() => {
            this.cleanup();
        }, 5 * 60 * 1000);
        // Allow the process to exit even with the interval running
        if (this.cleanupInterval.unref) {
            this.cleanupInterval.unref();
        }
    }
    /**
     * Remove expired records from the stores
     */
    cleanup() {
        const now = Date.now();
        for (const [key, record] of this.ipStore.entries()) {
            if (record.expiresAt < now) {
                this.ipStore.delete(key);
            }
        }
        for (const [key, record] of this.emailStore.entries()) {
            if (record.expiresAt < now) {
                this.emailStore.delete(key);
            }
        }
        // Reset global record if expired
        if (this.globalRecord.expiresAt < now) {
            this.globalRecord = {
                attemptCount: 0,
                failedAttempts: 0,
                windowStart: now,
                expiresAt: now + this.config.windowMs,
                isBlocked: false,
            };
        }
    }
    /**
     * Get or create a rate limit record for an identifier
     */
    getOrCreateRecord(store, identifier) {
        const now = Date.now();
        let record = store.get(identifier);
        if (!record || record.expiresAt < now) {
            record = {
                attemptCount: 0,
                failedAttempts: 0,
                windowStart: now,
                expiresAt: now + this.config.windowMs,
                isBlocked: false,
            };
            store.set(identifier, record);
        }
        return record;
    }
    /**
     * Check if a signup attempt is allowed based on rate limits.
     *
     * @param ip - Client IP address
     * @param email - Email being registered (normalized)
     * @returns Rate limit check result with headers
     */
    checkLimit(ip, email) {
        const now = Date.now();
        const ipRecord = this.getOrCreateRecord(this.ipStore, ip);
        const emailRecord = this.getOrCreateRecord(this.emailStore, email);
        // Check if IP is blocked
        if (ipRecord.isBlocked) {
            return this.createBlockedResult(ipRecord, "IP is temporarily blocked");
        }
        // Check if email is blocked
        if (emailRecord.isBlocked) {
            return this.createBlockedResult(emailRecord, "Email is temporarily blocked");
        }
        // Check global rate limit
        if (this.globalRecord.attemptCount >= this.config.maxGlobalAttempts) {
            return {
                allowed: false,
                remainingAttempts: 0,
                resetIn: this.globalRecord.expiresAt - now,
                isBlocked: false,
                blockReason: "Global rate limit exceeded",
                suggestedDelayMs: this.globalRecord.expiresAt - now,
                headers: {
                    "X-RateLimit-Limit": String(this.config.maxGlobalAttempts),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": String(Math.ceil(this.globalRecord.expiresAt / 1000)),
                    "Retry-After": String(Math.ceil((this.globalRecord.expiresAt - now) / 1000)),
                },
            };
        }
        // Check IP rate limit
        if (ipRecord.attemptCount >= this.config.maxAttemptsPerIp) {
            return {
                allowed: false,
                remainingAttempts: 0,
                resetIn: ipRecord.expiresAt - now,
                isBlocked: false,
                blockReason: "Too many signup attempts from this IP",
                suggestedDelayMs: ipRecord.expiresAt - now,
                headers: {
                    "X-RateLimit-Limit": String(this.config.maxAttemptsPerIp),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": String(Math.ceil(ipRecord.expiresAt / 1000)),
                    "Retry-After": String(Math.ceil((ipRecord.expiresAt - now) / 1000)),
                },
            };
        }
        // Check email rate limit
        if (emailRecord.attemptCount >= this.config.maxAttemptsPerEmail) {
            return {
                allowed: false,
                remainingAttempts: 0,
                resetIn: emailRecord.expiresAt - now,
                isBlocked: false,
                blockReason: "Too many signup attempts for this email",
                suggestedDelayMs: emailRecord.expiresAt - now,
                headers: {
                    "X-RateLimit-Limit": String(this.config.maxAttemptsPerEmail),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": String(Math.ceil(emailRecord.expiresAt / 1000)),
                    "Retry-After": String(Math.ceil((emailRecord.expiresAt - now) / 1000)),
                },
            };
        }
        // Calculate remaining attempts (most restrictive)
        const ipRemaining = this.config.maxAttemptsPerIp - ipRecord.attemptCount;
        const emailRemaining = this.config.maxAttemptsPerEmail - emailRecord.attemptCount;
        const globalRemaining = this.config.maxGlobalAttempts - this.globalRecord.attemptCount;
        const remainingAttempts = Math.min(ipRemaining, emailRemaining, globalRemaining);
        // Calculate progressive delay
        let suggestedDelayMs = 0;
        if (this.config.enableProgressiveDelay &&
            ipRecord.failedAttempts >= this.config.progressiveDelayThreshold) {
            suggestedDelayMs = this.calculateProgressiveDelay(ipRecord.failedAttempts);
        }
        // Use the earliest reset time
        const resetIn = Math.min(ipRecord.expiresAt - now, emailRecord.expiresAt - now, this.globalRecord.expiresAt - now);
        return {
            allowed: true,
            remainingAttempts,
            resetIn,
            isBlocked: false,
            suggestedDelayMs,
            headers: {
                "X-RateLimit-Limit": String(this.config.maxAttemptsPerIp),
                "X-RateLimit-Remaining": String(remainingAttempts),
                "X-RateLimit-Reset": String(Math.ceil((now + resetIn) / 1000)),
            },
        };
    }
    /**
     * Create a result for blocked identifiers
     */
    createBlockedResult(record, reason) {
        const now = Date.now();
        return {
            allowed: false,
            remainingAttempts: 0,
            resetIn: record.expiresAt - now,
            isBlocked: true,
            blockReason: reason,
            suggestedDelayMs: record.expiresAt - now,
            headers: {
                "X-RateLimit-Limit": "0",
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": String(Math.ceil(record.expiresAt / 1000)),
                "Retry-After": String(Math.ceil((record.expiresAt - now) / 1000)),
            },
        };
    }
    /**
     * Calculate progressive delay based on failed attempts
     */
    calculateProgressiveDelay(failedAttempts) {
        // Exponential backoff: 1s, 2s, 4s, 8s, etc. (max 60s)
        const baseDelay = 1000;
        const maxDelay = 60000;
        return Math.min(baseDelay *
            Math.pow(2, failedAttempts - this.config.progressiveDelayThreshold), maxDelay);
    }
    /**
     * Record a signup attempt (called before processing signup).
     *
     * @param ip - Client IP address
     * @param email - Email being registered (normalized)
     */
    recordAttempt(ip, email) {
        const now = Date.now();
        // Update IP record
        const ipRecord = this.getOrCreateRecord(this.ipStore, ip);
        ipRecord.attemptCount++;
        ipRecord.expiresAt = now + this.config.windowMs;
        // Update email record
        const emailRecord = this.getOrCreateRecord(this.emailStore, email);
        emailRecord.attemptCount++;
        emailRecord.expiresAt = now + this.config.windowMs;
        // Update global record
        this.globalRecord.attemptCount++;
        if (this.globalRecord.expiresAt < now) {
            this.globalRecord = {
                attemptCount: 1,
                failedAttempts: 0,
                windowStart: now,
                expiresAt: now + this.config.windowMs,
                isBlocked: false,
            };
        }
    }
    /**
     * Record a failed signup attempt (for progressive delays).
     *
     * @param ip - Client IP address
     * @param email - Email being registered (normalized)
     * @param blockOnThreshold - Whether to block the identifier after threshold failures
     */
    recordFailure(ip, email, blockOnThreshold = false) {
        const now = Date.now();
        // Update IP record
        const ipRecord = this.getOrCreateRecord(this.ipStore, ip);
        ipRecord.failedAttempts++;
        if (blockOnThreshold &&
            ipRecord.failedAttempts >= this.config.maxAttemptsPerIp * 2) {
            ipRecord.isBlocked = true;
            ipRecord.blockReason = "Too many failed signup attempts";
            ipRecord.expiresAt = now + this.config.blockDurationMs;
        }
        // Update email record
        const emailRecord = this.getOrCreateRecord(this.emailStore, email);
        emailRecord.failedAttempts++;
        if (blockOnThreshold &&
            emailRecord.failedAttempts >= this.config.maxAttemptsPerEmail * 2) {
            emailRecord.isBlocked = true;
            emailRecord.blockReason = "Too many failed signup attempts";
            emailRecord.expiresAt = now + this.config.blockDurationMs;
        }
        // Update global failed attempts
        this.globalRecord.failedAttempts++;
    }
    /**
     * Record a successful signup (resets failure count but keeps attempt count).
     *
     * @param ip - Client IP address
     * @param email - Email being registered (normalized)
     */
    recordSuccess(ip, email) {
        const ipRecord = this.ipStore.get(ip);
        if (ipRecord) {
            ipRecord.failedAttempts = 0;
        }
        const emailRecord = this.emailStore.get(email);
        if (emailRecord) {
            emailRecord.failedAttempts = 0;
        }
    }
    /**
     * Manually block an identifier (e.g., for detected abuse).
     *
     * @param type - 'ip' or 'email'
     * @param identifier - The identifier to block
     * @param reason - Reason for blocking
     * @param durationMs - Block duration (defaults to config)
     */
    block(type, identifier, reason, durationMs) {
        const store = type === "ip" ? this.ipStore : this.emailStore;
        const record = this.getOrCreateRecord(store, identifier);
        record.isBlocked = true;
        record.blockReason = reason;
        record.expiresAt = Date.now() + (durationMs ?? this.config.blockDurationMs);
    }
    /**
     * Manually unblock an identifier.
     *
     * @param type - 'ip' or 'email'
     * @param identifier - The identifier to unblock
     */
    unblock(type, identifier) {
        const store = type === "ip" ? this.ipStore : this.emailStore;
        const record = store.get(identifier);
        if (record) {
            record.isBlocked = false;
            record.blockReason = undefined;
        }
    }
    /**
     * Get current statistics for monitoring.
     */
    getStats() {
        let blockedIps = 0;
        let blockedEmails = 0;
        for (const record of this.ipStore.values()) {
            if (record.isBlocked)
                blockedIps++;
        }
        for (const record of this.emailStore.values()) {
            if (record.isBlocked)
                blockedEmails++;
        }
        return {
            ipRecords: this.ipStore.size,
            emailRecords: this.emailStore.size,
            globalAttempts: this.globalRecord.attemptCount,
            globalFailedAttempts: this.globalRecord.failedAttempts,
            blockedIps,
            blockedEmails,
        };
    }
    /**
     * Reset all records (for testing).
     */
    reset() {
        this.ipStore.clear();
        this.emailStore.clear();
        this.globalRecord = {
            attemptCount: 0,
            failedAttempts: 0,
            windowStart: Date.now(),
            expiresAt: Date.now() + this.config.windowMs,
            isBlocked: false,
        };
    }
    /**
     * Stop the cleanup interval (for graceful shutdown).
     */
    stop() {
        if (this.cleanupInterval) {
            clearInterval(this.cleanupInterval);
            this.cleanupInterval = null;
        }
    }
}
// Singleton instance for the application
let signupRateLimitStore = null;
/**
 * Get the singleton signup rate limit store.
 * Creates a new instance if one doesn't exist.
 *
 * @param config - Optional configuration (used only on first call)
 * @returns The signup rate limit store instance
 */
export function getSignupRateLimitStore(config) {
    if (!signupRateLimitStore) {
        signupRateLimitStore = new SignupRateLimitStore(config);
    }
    return signupRateLimitStore;
}
/**
 * Reset the singleton instance (for testing).
 */
export function resetSignupRateLimitStore() {
    if (signupRateLimitStore) {
        signupRateLimitStore.stop();
        signupRateLimitStore = null;
    }
}
/**
 * Create a new signup rate limit store (for testing or isolated instances).
 *
 * @param config - Optional configuration
 * @returns A new signup rate limit store instance
 */
export function createSignupRateLimitStore(config) {
    return new SignupRateLimitStore(config);
}
export { SignupRateLimitStore };
