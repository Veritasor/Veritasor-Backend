/**
 * In-memory store for Stripe OAuth state tokens and integration records.
 * Implements CSRF protection for OAuth flow.
 * Tokens are never logged.
 */
/** Explicit error thrown when store inputs fail validation. */
export class StripeStoreValidationError extends Error {
    field;
    constructor(message, field) {
        super(message);
        this.field = field;
        this.name = 'StripeStoreValidationError';
    }
}
const stateStore = new Map();
/**
 * In-memory store for Stripe integrations.
 * Keyed by stripeUserId for idempotent upserts.
 */
const integrationStore = new Map();
// ── Validation ────────────────────────────────────────────────────────────────
function assertNonEmptyString(value, field) {
    if (typeof value !== 'string' || value.trim().length === 0) {
        throw new StripeStoreValidationError(`${field} must be a non-empty string`, field);
    }
}
// ── OAuth state store ─────────────────────────────────────────────────────────
/**
 * Store an OAuth state token with expiration timestamp.
 * @throws {StripeStoreValidationError} if state is empty or expiresAt is not a positive number.
 */
export function setOAuthState(state, expiresAt) {
    assertNonEmptyString(state, 'state');
    if (typeof expiresAt !== 'number' || !Number.isFinite(expiresAt)) {
        throw new StripeStoreValidationError('expiresAt must be a finite number', 'expiresAt');
    }
    stateStore.set(state, { expiresAt });
}
/**
 * Consume an OAuth state token (one-time use).
 * Returns true if valid and not expired, false otherwise.
 * Removes the token from storage after retrieval.
 */
export function consumeOAuthState(state) {
    const record = stateStore.get(state);
    stateStore.delete(state);
    if (!record)
        return false;
    if (record.expiresAt < Date.now())
        return false;
    return true;
}
// ── Integration store ─────────────────────────────────────────────────────────
/**
 * Performs an idempotent upsert of a Stripe integration.
 * If the stripeUserId already exists, updates the record and preserves createdAt.
 * @throws {StripeStoreValidationError} if any required field is missing or empty.
 */
export function upsertStripeIntegration(integration) {
    assertNonEmptyString(integration.stripeUserId, 'stripeUserId');
    assertNonEmptyString(integration.accessToken, 'accessToken');
    assertNonEmptyString(integration.businessId, 'businessId');
    const existing = integrationStore.get(integration.stripeUserId);
    const now = Date.now();
    const record = {
        ...integration,
        createdAt: existing ? existing.createdAt : now,
        updatedAt: now,
    };
    integrationStore.set(integration.stripeUserId, record);
    return record;
}
/**
 * Retrieves a Stripe integration by Stripe user ID.
 */
export function getStripeIntegration(stripeUserId) {
    return integrationStore.get(stripeUserId);
}
// ── Cleanup ───────────────────────────────────────────────────────────────────
/**
 * Clean up expired state tokens.
 * Called periodically to prevent memory leaks.
 */
function cleanupExpiredStates() {
    const now = Date.now();
    for (const [state, record] of stateStore.entries()) {
        if (record.expiresAt < now) {
            stateStore.delete(state);
        }
    }
}
// Run cleanup every 5 minutes
setInterval(cleanupExpiredStates, 5 * 60 * 1000);
/**
 * Clears all integration records and OAuth state tokens.
 * For test isolation only — do not call in production code.
 */
export function clearStripeIntegrationStore() {
    integrationStore.clear();
    stateStore.clear();
}
