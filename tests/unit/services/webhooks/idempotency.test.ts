/**
 * Focused behaviour coverage for `src/services/webhooks/idempotency.ts`.
 *
 * The module is the last line of defence against replayed provider webhooks
 * (Stripe/Razorpay retries, malicious replays), so its two boundaries matter:
 *
 *   * the replay window (`markEventProcessed` / `isEventProcessed`), including
 *     lazy eviction of expired entries, and
 *   * the timestamp tolerance window (`checkTimestampTolerance`), whose bounds
 *     are *inclusive* on both sides.
 *
 * Time is fully controlled with fake timers so every assertion is
 * deterministic rather than wall-clock dependent. The module keeps a
 * process-wide `Map`, so each test uses a unique event id.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import {
  DEFAULT_MAX_AGE_MS,
  DEFAULT_MAX_FUTURE_SKEW_MS,
  DEFAULT_TTL_MS,
  checkTimestampTolerance,
  isEventProcessed,
  markEventProcessed,
} from '../../../../src/services/webhooks/idempotency.js'

/** Fixed wall-clock origin used by every test in this file. */
const NOW = 1_800_000_000_000

let seq = 0
/** A unique event id per call so the module-level store cannot leak between tests. */
const nextEventId = () => `evt-${NOW}-${seq++}`

beforeEach(() => {
  vi.useFakeTimers()
  vi.setSystemTime(NOW)
})

afterEach(() => {
  vi.useRealTimers()
})

describe('idempotency – default constants', () => {
  it('exposes the documented retention and tolerance windows', () => {
    expect(DEFAULT_TTL_MS).toBe(24 * 60 * 60 * 1000)
    expect(DEFAULT_MAX_AGE_MS).toBe(5 * 60 * 1000)
    expect(DEFAULT_MAX_FUTURE_SKEW_MS).toBe(5 * 60 * 1000)
  })
})

describe('isEventProcessed / markEventProcessed', () => {
  it('reports an unseen event id as not processed', () => {
    expect(isEventProcessed(nextEventId())).toBe(false)
  })

  it.each(['', undefined, null])('treats the falsy id %p as never processed', (eventId) => {
    expect(isEventProcessed(eventId as unknown as string)).toBe(false)
  })

  it('reports a marked id as processed', () => {
    const eventId = nextEventId()
    markEventProcessed(eventId)
    expect(isEventProcessed(eventId)).toBe(true)
  })

  it('keeps distinct event ids independent', () => {
    const a = nextEventId()
    const b = nextEventId()

    markEventProcessed(a)

    expect(isEventProcessed(a)).toBe(true)
    expect(isEventProcessed(b)).toBe(false)
  })

  it('treats an id as processed right up to (and including) the expiry instant', () => {
    const eventId = nextEventId()
    markEventProcessed(eventId, 1000)

    vi.advanceTimersByTime(999)
    expect(isEventProcessed(eventId)).toBe(true)

    // Boundary: `expiresAt < now` is strict, so the deadline instant is still valid.
    vi.advanceTimersByTime(1)
    expect(isEventProcessed(eventId)).toBe(true)
  })

  it('expires an id one millisecond past its TTL and evicts it lazily', () => {
    const eventId = nextEventId()
    markEventProcessed(eventId, 1000)

    vi.advanceTimersByTime(1001)
    expect(isEventProcessed(eventId)).toBe(false)

    // The expired entry was evicted rather than merely masked: re-marking
    // starts a fresh window and the id is valid again.
    markEventProcessed(eventId, 1000)
    expect(isEventProcessed(eventId)).toBe(true)

    vi.advanceTimersByTime(1001)
    expect(isEventProcessed(eventId)).toBe(false)
  })

  it('treats a zero TTL as valid only at the same instant', () => {
    const eventId = nextEventId()
    markEventProcessed(eventId, 0)

    expect(isEventProcessed(eventId)).toBe(true)

    vi.advanceTimersByTime(1)
    expect(isEventProcessed(eventId)).toBe(false)
  })

  it('treats a negative TTL as already expired', () => {
    const eventId = nextEventId()
    markEventProcessed(eventId, -1)

    expect(isEventProcessed(eventId)).toBe(false)
  })

  it('extends the window when the same id is re-marked with a longer TTL', () => {
    const eventId = nextEventId()
    markEventProcessed(eventId, 1000)

    vi.advanceTimersByTime(900)
    markEventProcessed(eventId, 60_000)

    // Past the original deadline but inside the renewed window.
    vi.advanceTimersByTime(500)
    expect(isEventProcessed(eventId)).toBe(true)

    vi.advanceTimersByTime(60_000)
    expect(isEventProcessed(eventId)).toBe(false)
  })

  it('never expires an id marked with no explicit TTL inside the default window', () => {
    const eventId = nextEventId()
    markEventProcessed(eventId)

    vi.advanceTimersByTime(DEFAULT_TTL_MS - 1)
    expect(isEventProcessed(eventId)).toBe(true)

    vi.advanceTimersByTime(2)
    expect(isEventProcessed(eventId)).toBe(false)
  })
})

describe('checkTimestampTolerance – missing timestamp', () => {
  it('accepts an event with no timestamp', () => {
    expect(checkTimestampTolerance(undefined)).toEqual({ valid: true })
  })
})

describe('checkTimestampTolerance – age window (inclusive lower bound)', () => {
  it('accepts a timestamp aged exactly the maximum age', () => {
    const createdAt = (NOW - DEFAULT_MAX_AGE_MS) / 1000

    expect(checkTimestampTolerance(createdAt)).toEqual({ valid: true })
  })

  it('rejects a timestamp one millisecond past the maximum age', () => {
    const createdAt = (NOW - DEFAULT_MAX_AGE_MS - 1) / 1000

    const result = checkTimestampTolerance(createdAt)

    expect(result.valid).toBe(false)
    expect(result.reason).toMatch(/Event too old/)
  })

  it('rejects an epoch timestamp as far too old', () => {
    const result = checkTimestampTolerance(0)

    expect(result.valid).toBe(false)
    expect(result.reason).toMatch(/Event too old/)
  })

  it('honours a caller-supplied maximum age', () => {
    const createdAt = (NOW - 10_000) / 1000

    expect(checkTimestampTolerance(createdAt, 10_000).valid).toBe(true)
    expect(checkTimestampTolerance(createdAt, 9_999).valid).toBe(false)
  })
})

describe('checkTimestampTolerance – future-skew window (inclusive upper bound)', () => {
  it('accepts a timestamp exactly within the future-skew tolerance', () => {
    const createdAt = (NOW + DEFAULT_MAX_FUTURE_SKEW_MS) / 1000

    expect(checkTimestampTolerance(createdAt)).toEqual({ valid: true })
  })

  it('rejects a timestamp one millisecond beyond the future-skew tolerance', () => {
    const createdAt = (NOW + DEFAULT_MAX_FUTURE_SKEW_MS + 1) / 1000

    const result = checkTimestampTolerance(createdAt)

    expect(result.valid).toBe(false)
    expect(result.reason).toBe('Event timestamp too far in future')
  })

  it('honours a caller-supplied future skew', () => {
    const createdAt = (NOW + 10_000) / 1000

    expect(checkTimestampTolerance(createdAt, DEFAULT_MAX_AGE_MS, 10_000).valid).toBe(true)
    expect(checkTimestampTolerance(createdAt, DEFAULT_MAX_AGE_MS, 9_999).valid).toBe(false)
  })

  it('accepts the current instant', () => {
    expect(checkTimestampTolerance(NOW / 1000)).toEqual({ valid: true })
  })
})

describe('checkTimestampTolerance – non-finite input (documented behaviour)', () => {
  it('treats a NaN timestamp as valid because both comparisons are false', () => {
    // Documents the shipped contract: `NaN` fails `age > maxAgeMs` *and*
    // `eventTimeMs - now > maxFutureSkewMs`, so it slips through the window
    // checks instead of being rejected. Callers must validate finiteness
    // themselves; this test exists so a future tightening is a deliberate
    // change rather than a silent one.
    expect(checkTimestampTolerance(NaN)).toEqual({ valid: true })
  })

  it('rejects an infinite timestamp as too far in the future', () => {
    expect(checkTimestampTolerance(Infinity).valid).toBe(false)
    expect(checkTimestampTolerance(-Infinity).valid).toBe(false)
  })
})
