import { describe, it, expect, vi } from 'vitest'
import {
  calculateBackoffDelay,
  withBackoff,
  BackoffError,
  type BackoffOptions,
  DEFAULT_BACKOFF_OPTIONS,
} from '../../src/utils/backoff.js'

const FIXED_RANDOM = () => 0.5

describe('calculateBackoffDelay', () => {
  const opts: BackoffOptions = { baseDelayMs: 100, maxDelayMs: 1000, maxAttempts: 3 }

  it('returns a value between 1 and the capped exponential window', () => {
    const delay = calculateBackoffDelay(1, opts, FIXED_RANDOM)
    expect(delay).toBeGreaterThanOrEqual(1)
    expect(delay).toBeLessThanOrEqual(opts.maxDelayMs)
  })

  it('caps at maxDelayMs for large exponents', () => {
    const delay = calculateBackoffDelay(10, opts, FIXED_RANDOM)
    const expectedCap = Math.round(0.5 * opts.maxDelayMs)
    expect(delay).toBeLessThanOrEqual(expectedCap)
  })

  it('scales exponentially with attempt number', () => {
    const d1 = calculateBackoffDelay(1, opts, FIXED_RANDOM)
    const d2 = calculateBackoffDelay(2, opts, FIXED_RANDOM)
    expect(d2).toBeGreaterThanOrEqual(d1)
  })

  it('uses a custom random function', () => {
    const alwaysZero = () => 0
    const delay = calculateBackoffDelay(2, opts, alwaysZero)
    expect(delay).toBe(1)
  })

  it('never returns 0 even with random = 0', () => {
    const delay = calculateBackoffDelay(0, { ...opts, baseDelayMs: 1, maxDelayMs: 1 }, () => 0)
    expect(delay).toBe(1)
  })
})

describe('withBackoff', () => {
  const instantSleep = () => Promise.resolve()
  let attemptCount: number

  beforeEach(() => {
    attemptCount = 0
  })

  it('resolves on the first attempt when fn succeeds', async () => {
    const fn = vi.fn().mockResolvedValue('ok')
    const result = await withBackoff(fn, DEFAULT_BACKOFF_OPTIONS, undefined, instantSleep)
    expect(result).toBe('ok')
    expect(fn).toHaveBeenCalledTimes(1)
  })

  it('retries on failure and resolves on a later attempt', async () => {
    const fn = vi
      .fn()
      .mockRejectedValueOnce(new Error('fail1'))
      .mockRejectedValueOnce(new Error('fail2'))
      .mockResolvedValue('recovered')

    const onRetry = vi.fn()
    const result = await withBackoff(fn, { ...DEFAULT_BACKOFF_OPTIONS, maxAttempts: 3 }, onRetry, instantSleep)

    expect(result).toBe('recovered')
    expect(fn).toHaveBeenCalledTimes(3)
    expect(onRetry).toHaveBeenCalledTimes(2)
  })

  it('throws BackoffError after exhausting all attempts', async () => {
    const error = new Error('persistent failure')
    const fn = vi.fn().mockRejectedValue(error)

    await expect(
      withBackoff(fn, { ...DEFAULT_BACKOFF_OPTIONS, maxAttempts: 2 }, undefined, instantSleep),
    ).rejects.toThrow(BackoffError)

    expect(fn).toHaveBeenCalledTimes(2)
  })

  it('BackoffError contains attemptCount and the original cause', async () => {
    const cause = new Error('root cause')
    const fn = vi.fn().mockRejectedValue(cause)

    try {
      await withBackoff(fn, { ...DEFAULT_BACKOFF_OPTIONS, maxAttempts: 3 }, undefined, instantSleep)
      expect.unreachable()
    } catch (e) {
      expect(e).toBeInstanceOf(BackoffError)
      const be = e as BackoffError
      expect(be.attemptCount).toBe(3)
      expect(be.cause).toBe(cause)
      expect(be.message).toContain('3')
    }
  })

  it('calls onRetry with attempt number, delay, and error', async () => {
    const error = new Error('retry me')
    const fn = vi.fn().mockRejectedValue(error)
    const onRetry = vi.fn()

    await expect(
      withBackoff(fn, { baseDelayMs: 100, maxDelayMs: 500, maxAttempts: 2 }, onRetry, instantSleep, FIXED_RANDOM),
    ).rejects.toThrow(BackoffError)

    expect(onRetry).toHaveBeenCalledTimes(1)
    expect(onRetry).toHaveBeenCalledWith(1, expect.any(Number), error)
  })

  it('passes the attempt number to fn', async () => {
    const fn = vi.fn().mockResolvedValue('done')
    await withBackoff(fn, { ...DEFAULT_BACKOFF_OPTIONS, maxAttempts: 1 }, undefined, instantSleep)
    expect(fn).toHaveBeenCalledWith(1)
  })

  it('uses real sleep when no sleep fn is provided', async () => {
    vi.useFakeTimers()
    const fn = vi.fn().mockRejectedValueOnce(new Error('fail')).mockResolvedValue('ok')
    const promise = withBackoff(fn, { baseDelayMs: 50, maxDelayMs: 100, maxAttempts: 2 })

    await vi.advanceTimersToNextTimerAsync()
    const result = await promise
    expect(result).toBe('ok')
    vi.useRealTimers()
  })

  it('uses default backoff options when none provided', async () => {
    const fn = vi.fn().mockResolvedValue('defaults')
    const result = await withBackoff(fn, undefined, undefined, instantSleep)
    expect(result).toBe('defaults')
  })

  it('single attempt (maxAttempts = 1) rethrows original error directly', async () => {
    const original = new Error('no retry')
    const fn = vi.fn().mockRejectedValue(original)
    const onRetry = vi.fn()

    await expect(
      withBackoff(fn, { ...DEFAULT_BACKOFF_OPTIONS, maxAttempts: 1 }, onRetry, instantSleep),
    ).rejects.toThrow(original)

    expect(fn).toHaveBeenCalledTimes(1)
    expect(onRetry).not.toHaveBeenCalled()
  })

  it('maxAttempts = 0 never calls fn and throws BackoffError', async () => {
    const fn = vi.fn()

    await expect(
      withBackoff(fn, { ...DEFAULT_BACKOFF_OPTIONS, maxAttempts: 0 }, undefined, instantSleep),
    ).rejects.toThrow(BackoffError)

    expect(fn).not.toHaveBeenCalled()
  })
})
