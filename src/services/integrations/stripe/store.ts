/**
 * Store for Stripe OAuth state tokens and integration records.
 * Implements CSRF protection for OAuth flow.
 * Tokens are never logged.
 *
 * OAuth state is stored in Redis for multi-pod deployments,
 * with in-memory fallback for tests and when Redis is not configured.
 */

import { getRedisClient, type RedisClient } from '../../redis.js'

// ── Types ─────────────────────────────────────────────────────────────────────

export interface StripeIntegration {
  stripeUserId: string
  accessToken: string
  businessId: string
  createdAt: number
  updatedAt: number
}

export type StripeIntegrationInput = Omit<StripeIntegration, 'createdAt' | 'updatedAt'>

/** Explicit error thrown when store inputs fail validation. */
export class StripeStoreValidationError extends Error {
  constructor(
    message: string,
    public readonly field: string,
  ) {
    super(message)
    this.name = 'StripeStoreValidationError'
  }
}

// ── Internal stores ───────────────────────────────────────────────────────────

interface StateRecord {
  expiresAt: number
}

let stateStore = new Map<string, StateRecord>()

/**
 * Check if Redis is configured and available.
 * Returns true if REDIS_URL or REDIS_CLUSTER_NODES is set.
 */
function isRedisConfigured(): boolean {
  return !!(process.env.REDIS_URL || process.env.REDIS_CLUSTER_NODES || process.env.REDIS_MODE)
}

/**
 * Get the Redis key for OAuth state storage.
 */
function getOAuthStateKey(state: string): string {
  return `oauth:state:${state}`
}


/**
 * In-memory store for Stripe integrations.
 * Keyed by stripeUserId for idempotent upserts.
 */
let integrationStore = new Map<string, StripeIntegration>()

/**
 * Resets the in-memory stores. Intended for testing purposes only.
 */
export function resetStoresForTesting(): void {
  stateStore = new Map<string, StateRecord>()
  integrationStore = new Map<string, StripeIntegration>()
}

// ── Validation ────────────────────────────────────────────────────────────────

function assertNonEmptyString(value: unknown, field: string): asserts value is string {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new StripeStoreValidationError(
      `${field} must be a non-empty string`,
      field,
    )
  }
}

// ── OAuth state store ─────────────────────────────────────────────────────────

/**
 * Store an OAuth state token with expiration timestamp.
 * Uses Redis when configured, falls back to in-memory storage.
 * @throws {StripeStoreValidationError} if state is empty or expiresAt is not a positive number.
 */
export async function setOAuthState(state: string, expiresAt: number): Promise<void> {
  assertNonEmptyString(state, 'state')
  if (typeof expiresAt !== 'number' || !Number.isFinite(expiresAt)) {
    throw new StripeStoreValidationError('expiresAt must be a finite number', 'expiresAt')
  }

  if (isRedisConfigured()) {
    const client = getRedisClient()
    const key = getOAuthStateKey(state)
    const ttlMs = expiresAt - Date.now()

    if (ttlMs <= 0) {
      throw new StripeStoreValidationError('expiresAt must be in the future', 'expiresAt')
    }

    // Store with TTL in milliseconds (converted to seconds for Redis)
    await client.set(key, JSON.stringify({ expiresAt }), 'PX', ttlMs)
  } else {
    // Fallback to in-memory storage
    stateStore.set(state, { expiresAt })
  }
}

/**
 * Consume an OAuth state token (one-time use).
 * Uses Redis when configured, falls back to in-memory storage.
 * Returns true if valid and not expired, false otherwise.
 * Removes the token from storage after retrieval (atomic in Redis).
 */
export async function consumeOAuthState(state: string): Promise<boolean> {
  if (isRedisConfigured()) {
    const client = getRedisClient()
    const key = getOAuthStateKey(state)

    // Use GETDEL for atomic get-and-delete (Redis 6.2+)
    // Fallback to Lua script for older versions
    try {
      const value = await client.getdel(key)
      if (!value) return false

      const record = JSON.parse(value) as StateRecord
      if (record.expiresAt < Date.now()) return false

      return true
    } catch (err) {
      // GETDEL might not be available in older Redis versions
      // Fall back to Lua script for atomic GET + DEL
      const script = `
        local value = redis.call('GET', KEYS[1])
        if not value then
          return nil
        end
        redis.call('DEL', KEYS[1])
        return value
      `
      const value = await client.eval(script, 1, key)
      if (!value) return false

      const record = JSON.parse(value as string) as StateRecord
      if (record.expiresAt < Date.now()) return false

      return true
    }
  } else {
    // Fallback to in-memory storage
    const record = stateStore.get(state)
    stateStore.delete(state)

    if (!record) return false
    if (record.expiresAt < Date.now()) return false

    return true
  }
}

// ── Integration store ─────────────────────────────────────────────────────────

/**
 * Performs an idempotent upsert of a Stripe integration.
 * If the stripeUserId already exists, updates the record and preserves createdAt.
 * @throws {StripeStoreValidationError} if any required field is missing or empty.
 */
export function upsertStripeIntegration(integration: StripeIntegrationInput): StripeIntegration {
  assertNonEmptyString(integration.stripeUserId, 'stripeUserId')
  assertNonEmptyString(integration.accessToken, 'accessToken')
  assertNonEmptyString(integration.businessId, 'businessId')

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
 * Retrieves a Stripe integration by Stripe user ID.
 */
export function getStripeIntegration(stripeUserId: string): StripeIntegration | undefined {
  return integrationStore.get(stripeUserId)
}

// ── Cleanup ───────────────────────────────────────────────────────────────────

/**
 * Clean up expired state tokens (in-memory only).
 * Called periodically to prevent memory leaks when Redis is not configured.
 */
function cleanupExpiredStates(): void {
  // Only run cleanup for in-memory storage
  if (isRedisConfigured()) return

  const now = Date.now()
  for (const [state, record] of stateStore.entries()) {
    if (record.expiresAt < now) {
      stateStore.delete(state)
    }
  }
}

// Run cleanup every 5 minutes (only for in-memory storage)
setInterval(cleanupExpiredStates, 5 * 60 * 1000).unref()

/**
 * Clears all integration records and OAuth state tokens.
 * For test isolation only — do not call in production code.
 */
export function clearStripeIntegrationStore(): void {
  integrationStore.clear()
  stateStore.clear()
}
