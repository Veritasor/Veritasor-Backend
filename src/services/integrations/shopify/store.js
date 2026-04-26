/**
 * In-memory store for Shopify OAuth state tokens with expiration.
 * Implements CSRF protection for OAuth flow.
 * Tokens are never logged.
 */

/**
 * @typedef {Object} StateRecord
 * @property {string} shopHost - The shop hostname associated with the state.
 * @property {string} userId - The ID of the user who initiated the OAuth flow.
 * @property {string} integrationId - The ID of the integration (e.g., 'shopify').
 * @property {number} expiresAt - Unix timestamp when the state token expires.
 */

/** @type {Map<string, StateRecord>} */
let stateStore = new Map();

/**
 * In-memory store for Shopify integrations.
 * Keyed by shopHost for idempotent upserts.
 * @type {Map<string, Object>}
 */
let integrationStore = new Map(); // Placeholder, not directly used in this task

/**
 * Resets the in-memory stores. Intended for testing purposes only.
 */
export function resetStoresForTesting() {
  stateStore = new Map();
  integrationStore = new Map();
}

/**
 * Stores an OAuth state token with associated shop host, user ID, integration ID, and expiration timestamp.
 * @param {string} state - The unique state token.
 * @param {string} shopHost - The normalized shop hostname.
 * @param {string} userId - The ID of the user.
 * @param {string} integrationId - The ID of the integration (e.g., 'shopify').
 * @param {number} expiresAt - Unix timestamp when the state token expires.
 */
export function setOAuthState(state, shopHost, userId, integrationId, expiresAt) {
  stateStore.set(state, { shopHost, userId, integrationId, expiresAt });
}

/**
 * Consumes an OAuth state token (one-time use).
 * Returns the stored shopHost if valid, not expired, and matches userId/integrationId, otherwise undefined.
 * Removes the token from storage after retrieval.
 * @param {string} state - The state token to consume.
 * @param {string} userId - The ID of the user attempting to consume the state.
 * @param {string} integrationId - The ID of the integration attempting to consume the state.
 * @returns {string | undefined} The stored shopHost if valid, otherwise undefined.
 */
export function consumeOAuthState(state, userId, integrationId) {
  const record = stateStore.get(state);

  // Remove token immediately (one-time use)
  stateStore.delete(state);

  if (!record) {
    return undefined;
  }

  // Validate userId and integrationId match to prevent cross-user/cross-integration state theft
  if (record.userId !== userId || record.integrationId !== integrationId) {
    return undefined;
  }

  // Check for expiration
  if (record.expiresAt < Date.now()) {
    return undefined;
  }

  return record.shopHost;
}

// Placeholder for normalizeShop and isValidShopHost, as they are used in connect.ts
export function normalizeShop(shop) {
  return shop.toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
}

export function isValidShopHost(shopHost) {
  return /^[a-zA-Z0-9][a-zA-Z0-9\-]*\.myshopify\.com$/.test(shopHost);
}

/**
 * Clean up expired state tokens.
 * Should be called periodically to prevent memory leaks.
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