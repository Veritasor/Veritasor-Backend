/**
 * Distributed lock utility using Redis.
 *
 * Provides a simple distributed lock mechanism using Redis SET NX PX
 * for acquiring locks with expiration, and Lua script for safe release.
 * Falls back to no-op when Redis is not configured.
 */

import { getRedisClient, type RedisClient } from '../redis.js'

export interface DistributedLockOptions {
  /**
   * Lock key name
   */
  key: string

  /**
   * Lock time-to-live in milliseconds
   * Default: 30000 (30 seconds)
   */
  ttlMs?: number

  /**
   * Unique token for this lock attempt
   * Generated automatically if not provided
   */
  token?: string
}

export interface LockResult {
  /**
   * Whether the lock was acquired
   */
  acquired: boolean

  /**
   * The token used to acquire the lock
   */
  token: string
}

/**
 * Check if Redis is configured and available.
 */
function isRedisConfigured(): boolean {
  return !!(process.env.REDIS_URL || process.env.REDIS_CLUSTER_NODES || process.env.REDIS_MODE)
}

/**
 * Generate a unique lock token.
 */
function generateLockToken(): string {
  return `${Date.now()}-${Math.random().toString(36).substring(2)}`
}

/**
 * Acquire a distributed lock using Redis SET NX PX.
 *
 * @param options - Lock configuration
 * @returns Lock result with acquired status and token
 */
export async function acquireLock(options: DistributedLockOptions): Promise<LockResult> {
  const { key, ttlMs = 30000, token = generateLockToken() } = options

  if (!isRedisConfigured()) {
    // No Redis configured - simulate successful acquisition for fallback behavior
    return { acquired: true, token }
  }

  const client = getRedisClient()

  try {
    // SET key value NX PX ttlMs
    // NX: only set if key does not exist
    // PX: set expiration in milliseconds
    const result = await client.set(key, token, 'NX', 'PX', ttlMs)

    // Redis returns 'OK' when the key was set, null if it already existed
    const acquired = result === 'OK'

    return { acquired, token }
  } catch (err) {
    // If Redis fails, fall back to allowing the operation
    // This prevents blocking startup when Redis is unavailable
    return { acquired: true, token }
  }
}

/**
 * Release a distributed lock using a Lua script for atomic compare-and-delete.
 *
 * @param key - Lock key name
 * @param token - Token used when acquiring the lock
 * @returns true if the lock was released, false otherwise
 */
export async function releaseLock(key: string, token: string): Promise<boolean> {
  if (!isRedisConfigured()) {
    // No Redis configured - no-op
    return true
  }

  const client = getRedisClient()

  try {
    // Lua script for atomic compare-and-delete
    // Only deletes if the value matches the expected token
    const script = `
      if redis.call("GET", KEYS[1]) == ARGV[1] then
        return redis.call("DEL", KEYS[1])
      else
        return 0
      end
    `

    const result = await client.eval(script, 1, key, token)
    return result === 1
  } catch (err) {
    // If Redis fails, we can't reliably release the lock
    // The TTL will eventually expire it
    return false
  }
}

/**
 * Execute a function with a distributed lock.
 *
 * Acquires the lock, executes the function, and releases the lock.
 * If the lock cannot be acquired, the function is not executed.
 *
 * @param options - Lock configuration
 * @param fn - Function to execute while holding the lock
 * @returns Result of the function, or undefined if lock was not acquired
 */
export async function withLock<T>(
  options: DistributedLockOptions,
  fn: () => Promise<T>
): Promise<T | undefined> {
  const { key } = options
  const { acquired, token } = await acquireLock(options)

  if (!acquired) {
    return undefined
  }

  try {
    return await fn()
  } finally {
    // Best-effort release - if this fails, the TTL will expire the lock
    await releaseLock(key, token)
  }
}
