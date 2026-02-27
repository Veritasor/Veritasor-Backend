/**
 * In-memory store for Stripe OAuth state tokens with expiration.
 * Implements CSRF protection for OAuth flow.
 * Tokens are never logged.
 */

interface StateRecord {
  expiresAt: number
}

const stateStore = new Map<string, StateRecord>()

/**
 * Store an OAuth state token with expiration timestamp
 */
export function setOAuthState(state: string, expiresAt: number): void {
  stateStore.set(state, { expiresAt })
}

/**
 * Consume an OAuth state token (one-time use)
 * Returns true if valid and not expired, false otherwise
 * Removes the token from storage after retrieval
 */
export function consumeOAuthState(state: string): boolean {
  const record = stateStore.get(state)
  
  // Remove token immediately (one-time use)
  stateStore.delete(state)
  
  // Check if token existed and hasn't expired
  if (!record) {
    return false
  }
  
  if (record.expiresAt < Date.now()) {
    return false
  }
  
  return true
}

/**
 * Clean up expired state tokens
 * Should be called periodically to prevent memory leaks
 */
function cleanupExpiredStates(): void {
  const now = Date.now()
  for (const [state, record] of stateStore.entries()) {
    if (record.expiresAt < now) {
      stateStore.delete(state)
    }
  }
}

// Run cleanup every 5 minutes
setInterval(cleanupExpiredStates, 5 * 60 * 1000)
