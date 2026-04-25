/**
 * In-memory store for Stripe OAuth state tokens with expiration.
 * Implements CSRF protection for OAuth flow.
 * Tokens are never logged.
 */

interface StateRecord {
  expiresAt: number
}

interface StripeIntegration {
  stripeUserId: string
  accessToken: string
  businessId: string
  createdAt: number
  updatedAt: number
}

const stateStore = new Map<string, StateRecord>()
/**
 * In-memory store for Stripe integrations.
 * Keyed by stripeUserId for idempotent upserts.
 */
const integrationStore = new Map<string, StripeIntegration>()

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
 * Performs an idempotent upsert of a Stripe integration.
 * If the stripeUserId already exists, it updates the record.
 * Otherwise, it creates a new one.
 * * @param integration - The Stripe integration data to store
 */
export function upsertStripeIntegration(
  integration: Omit<StripeIntegration, 'createdAt' | 'updatedAt'>
): StripeIntegration {
  const existing = integrationStore.get(integration.stripeUserId)
  const now = Date.now()

  const record: StripeIntegration = {
    ...integration,
    createdAt: existing ? existing.createdAt : now,
    updatedAt: now,
  }

  integrationStore.set(integration.stripeUserId, record)
  return record
}

/**
 * Retrieves a Stripe integration by user ID.
 */
export function getStripeIntegration(stripeUserId: string): StripeIntegration | undefined {
  return integrationStore.get(stripeUserId)
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
