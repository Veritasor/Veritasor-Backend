const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000
const DEFAULT_MAX_AGE_MS = 24 * 60 * 60 * 1000
const DEFAULT_MAX_FUTURE_SKEW_MS = 5 * 60 * 1000

function resolveMaxAgeMs(): number {
  const envVal = process.env.RAZORPAY_WEBHOOK_MAX_AGE_MS
  if (envVal) {
    const parsed = Number.parseInt(envVal, 10)
    if (Number.isFinite(parsed) && parsed > 0) {
      return parsed
    }
  }
  return DEFAULT_MAX_AGE_MS
}

interface IdempotencyEntry {
  processedAt: number
  expiresAt: number
}

const store = new Map<string, IdempotencyEntry>()

setInterval(() => {
  const now = Date.now()
  for (const [key, entry] of store) {
    if (entry.expiresAt < now) store.delete(key)
  }
}, 60 * 60 * 1000).unref()

export function resetIdempotencyStore(): void {
  store.clear()
}

export function isEventProcessed(eventId: string): boolean {
  if (!eventId) return false
  const entry = store.get(eventId)
  if (!entry) return false
  if (entry.expiresAt < Date.now()) { store.delete(eventId); return false }
  return true
}

export function markEventProcessed(eventId: string, ttlMs = DEFAULT_TTL_MS): void {
  const now = Date.now()
  store.set(eventId, { processedAt: now, expiresAt: now + ttlMs })
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

export { DEFAULT_TTL_MS, DEFAULT_MAX_AGE_MS, DEFAULT_MAX_FUTURE_SKEW_MS, resolveMaxAgeMs }
