const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000
const DEFAULT_MAX_AGE_MS = 24 * 60 * 60 * 1000
const DEFAULT_MAX_FUTURE_SKEW_MS = 5 * 60 * 1000

const DEFAULT_MEMORY_MAX_ENTRIES = 10000

interface IdempotencyEntry {
  processedAt: number
  expiresAt: number
}

export interface WebhookIdempotencyStore {
  isProcessed(eventId: string): Promise<boolean> | boolean
  markProcessed(eventId: string, ttlMs?: number): Promise<void> | void
  reserve?(eventId: string, ttlMs?: number): Promise<boolean>
}

class MemoryWebhookIdempotencyStore implements WebhookIdempotencyStore {
  private store = new Map<string, IdempotencyEntry>()
  private maxEntries: number

  constructor(maxEntries = DEFAULT_MEMORY_MAX_ENTRIES) {
    this.maxEntries = maxEntries
    setInterval(() => {
      const now = Date.now()
      for (const [key, entry] of this.store) {
        if (entry.expiresAt < now) this.store.delete(key)
      }
    }, 60 * 60 * 1000).unref()
  }

  isProcessed(eventId: string): boolean {
    if (!eventId) return false
    const entry = this.store.get(eventId)
    if (!entry) return false
    if (entry.expiresAt < Date.now()) {
      this.store.delete(eventId)
      return false
    }
    return true
  }

  markProcessed(eventId: string, ttlMs = DEFAULT_TTL_MS): void {
    if (!eventId) return
    const now = Date.now()
    if (this.store.size >= this.maxEntries && !this.store.has(eventId)) {
      // Evict oldest entry by insertion order approximation (Map preserves insertion; we need LRU - move on access)
      // Simple LRU: find oldest by processedAt
      let oldestKey: string | null = null
      let oldestTime = Infinity
      for (const [key, entry] of this.store) {
        if (entry.processedAt < oldestTime) {
          oldestTime = entry.processedAt
          oldestKey = key
        }
      }
      if (oldestKey) {
        this.store.delete(oldestKey)
      }
    }
    this.store.set(eventId, { processedAt: now, expiresAt: now + ttlMs })
  }

  reserve(eventId: string, ttlMs = DEFAULT_TTL_MS): boolean {
    if (!eventId) return true // or treat as already processed? but need to be consistent
    if (this.isProcessed(eventId)) {
      return false
    }
    this.markProcessed(eventId, ttlMs)
    return true
  }

  clear(): void {
    this.store.clear()
  }
}

class RedisWebhookIdempotencyStore implements WebhookIdempotencyStore {
  private keyPrefix: string

  constructor(keyPrefix = 'webhook:razorpay:event:') {
    this.keyPrefix = keyPrefix
  }

  private key(eventId: string): string {
    return `${this.keyPrefix}${eventId}`
  }

  async reserve(eventId: string, ttlMs = DEFAULT_TTL_MS): Promise<boolean> {
    if (!eventId) return false
    try {
      const { getRedisClient, redisCircuitBreaker } = await import('../../redis.js')
      const client = getRedisClient()
      const result = await redisCircuitBreaker.execute(async () => {
        // SET key value NX PX ttl
        const res = await (client as any).set(this.key(eventId), '1', 'NX', 'PX', ttlMs)
        return res
      })
      // Redis returns 'OK' if set, null if not set
      if (result === null || result === undefined) {
        return false
      }
      return true
    } catch (err: any) {
      // Re-throw circuit breaker open errors so caller can decide to fail closed
      if (err?.name === 'RedisCircuitBreakerError') {
        throw err
      }
      throw err
    }
  }

  async isProcessed(eventId: string): Promise<boolean> {
    if (!eventId) return false
    try {
      const reserved = await this.reserve(eventId)
      if (!reserved) {
        // Already exists - mark as processed exists
        return true
      }
      // We just reserved it, meaning it wasn't processed. But caller might want to check only.
      // For check-only, we need to not mark. Better approach: GET first
    } catch (err: any) {
      if (err?.name === 'RedisCircuitBreakerError') {
        throw err
      }
      throw err
    }
    // Fallback: check with GET
    try {
      const { getRedisClient, redisCircuitBreaker } = await import('../../redis.js')
      const client = getRedisClient()
      const result = await redisCircuitBreaker.execute(async () => {
        return await (client as any).get(this.key(eventId))
      })
      return result !== null && result !== undefined
    } catch (err: any) {
      if (err?.name === 'RedisCircuitBreakerError') {
        throw err
      }
      throw err
    }
  }

  async markProcessed(eventId: string, ttlMs = DEFAULT_TTL_MS): Promise<void> {
    if (!eventId) return
    try {
      const { getRedisClient, redisCircuitBreaker } = await import('../../redis.js')
      const client = getRedisClient()
      await redisCircuitBreaker.execute(async () => {
        await (client as any).set(this.key(eventId), '1', 'PX', ttlMs)
      })
    } catch (err: any) {
      if (err?.name === 'RedisCircuitBreakerError') {
        throw err
      }
      throw err
    }
  }
}

function isRedisConfigured(): boolean {
  return !!(process.env.REDIS_URL || process.env.REDIS_CLUSTER_NODES || process.env.REDIS_SENTINELS)
}

function createStore(): WebhookIdempotencyStore {
  if (isRedisConfigured()) {
    try {
      return new RedisWebhookIdempotencyStore()
    } catch (err) {
      if (process.env.NODE_ENV === 'production') {
        // eslint-disable-next-line no-console
        console.warn('Failed to initialize Redis webhook idempotency store, falling back to memory', err)
      }
      return new MemoryWebhookIdempotencyStore()
    }
  }
  if (process.env.NODE_ENV === 'production') {
    // eslint-disable-next-line no-console
    console.warn('Redis not configured for webhook idempotency; using in-memory store (not suitable for multi-instance)')
  }
  return new MemoryWebhookIdempotencyStore()
}

const store: WebhookIdempotencyStore = createStore()

export function getWebhookIdempotencyStore(): WebhookIdempotencyStore {
  return store
}

export async function isEventProcessed(eventId: string): Promise<boolean> {
  if (!eventId) return false
  try {
    const result = store.isProcessed(eventId)
    if (result instanceof Promise) {
      return await result
    }
    return result
  } catch (err) {
    throw err
  }
}

export async function markEventProcessed(eventId: string, ttlMs = DEFAULT_TTL_MS): Promise<void> {
  if (!eventId) return
  try {
    const result = store.markProcessed(eventId, ttlMs)
    if (result instanceof Promise) {
      await result
    }
  } catch (err) {
    throw err
  }
}

export async function reserveWebhookEvent(eventId: string, ttlMs = DEFAULT_TTL_MS): Promise<boolean> {
  if (!eventId) return false
  if (typeof (store as any).reserve === 'function') {
    try {
      const result = (store as any).reserve(eventId, ttlMs)
      if (result instanceof Promise) {
        return await result
      }
      return result
    } catch (err) {
      throw err
    }
  }
  const already = await isEventProcessed(eventId)
  if (already) return false
  await markEventProcessed(eventId, ttlMs)
  return true
}

export function checkTimestampTolerance(
  createdAt: number | undefined,
  maxAgeMs = resolveMaxAgeMs(),
  maxFutureSkewMs = DEFAULT_MAX_FUTURE_SKEW_MS
): { valid: boolean; reason?: string } {
  if (createdAt === undefined) return { valid: true }
  const now = Date.now()
  const eventTimeMs = createdAt * 1000
  const age = now - eventTimeMs
  if (age > maxAgeMs) return { valid: false, reason: `Event too old: ${Math.round(age/1000)}s` }
  if (eventTimeMs - now > maxFutureSkewMs) return { valid: false, reason: 'Event timestamp too far in future' }
  return { valid: true }
}

export { DEFAULT_TTL_MS, DEFAULT_MAX_AGE_MS, DEFAULT_MAX_FUTURE_SKEW_MS, MemoryWebhookIdempotencyStore, RedisWebhookIdempotencyStore }
export { MemoryWebhookIdempotencyStore as InMemoryWebhookIdempotencyStore }
