import { beforeEach, describe, expect, it, vi, afterEach } from 'vitest'
import {
  hedgedRequest,
  setMaxConcurrentHedges,
  getMaxConcurrentHedges,
  sorobanHedgeWinsTotal,
  sorobanHedgeSkippedTotal,
  AbortError,
} from '../../../src/utils/hedged-request.js'

function never(): Promise<string> {
  return new Promise<string>(() => undefined)
}

describe('hedgedRequest', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    vi.useFakeTimers()
    setMaxConcurrentHedges(5)
    sorobanHedgeWinsTotal.reset()
    sorobanHedgeSkippedTotal.reset()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  // -----------------------------------------------------------------------
  // Happy path – primary wins
  // -----------------------------------------------------------------------

  it('resolves with the primary result when primary is faster than hedge delay', async () => {
    const primary = vi.fn().mockResolvedValue('primary-ok')
    const hedge = vi.fn().mockResolvedValue('hedge-ok')

    const promise = hedgedRequest({
      operationName: 'test-op',
      primary,
      hedge,
      hedgeDelayMs: 500,
    })

    await expect(promise).resolves.toBe('primary-ok')
    expect(hedge).not.toHaveBeenCalled()
  })

  it('does not call hedge when primary resolves within the delay window', async () => {
    const primary = vi.fn().mockImplementation(
      () => new Promise<string>((resolve) => setTimeout(() => resolve('primary-slow'), 200)),
    )
    const hedge = vi.fn().mockResolvedValue('hedge-ok')

    const promise = hedgedRequest({
      operationName: 'test-op-delayed',
      primary,
      hedge,
      hedgeDelayMs: 500,
    })

    await vi.advanceTimersByTimeAsync(300)
    await expect(promise).resolves.toBe('primary-slow')
    expect(hedge).not.toHaveBeenCalled()
  })

  // -----------------------------------------------------------------------
  // Hedge wins
  // -----------------------------------------------------------------------

  it('fires hedge after delay and resolves with hedge if hedge wins', async () => {
    const primary = vi.fn().mockImplementation(never)
    const hedge = vi.fn().mockResolvedValue('hedge-won')

    const promise = hedgedRequest({
      operationName: 'test-op',
      primary,
      hedge,
      hedgeDelayMs: 500,
    })

    await vi.advanceTimersByTimeAsync(600)
    expect(hedge).toHaveBeenCalledTimes(1)
    await expect(promise).resolves.toBe('hedge-won')
  })

  it('increments the hedge-win counter when hedge wins', async () => {
    const primary = vi.fn().mockImplementation(never)
    const hedge = vi.fn().mockResolvedValue('hedge-won')
    const incSpy = vi.spyOn(sorobanHedgeWinsTotal, 'inc')

    const promise = hedgedRequest({
      operationName: 'win-op',
      primary,
      hedge,
      hedgeDelayMs: 100,
    })

    await vi.advanceTimersByTimeAsync(200)
    await expect(promise).resolves.toBe('hedge-won')
    expect(incSpy).toHaveBeenCalledWith({ operation: 'win-op' })
  })

  // -----------------------------------------------------------------------
  // Concurrency cap (verified with never-resolving promises)
  // -----------------------------------------------------------------------

  it('skips hedge when global concurrency cap is reached', async () => {
    setMaxConcurrentHedges(1)

    const hedge1 = vi.fn().mockImplementation(never) // keeps cap occupied
    const hedge2 = vi.fn().mockResolvedValue('hedge-2')
    const skipSpy = vi.spyOn(sorobanHedgeSkippedTotal, 'inc')

    hedgedRequest({
      operationName: 'op-1',
      primary: never,
      hedge: hedge1,
      hedgeDelayMs: 50,
    })

    await vi.advanceTimersByTimeAsync(60)
    expect(hedge1).toHaveBeenCalledTimes(1)

    hedgedRequest({
      operationName: 'op-2',
      primary: never,
      hedge: hedge2,
      hedgeDelayMs: 50,
    })

    await vi.advanceTimersByTimeAsync(60)
    expect(hedge2).not.toHaveBeenCalled()
    expect(skipSpy).toHaveBeenCalledWith({ operation: 'op-2' })
  })

  // -----------------------------------------------------------------------
  // Error propagation
  // -----------------------------------------------------------------------

  it('propagates primary error when primary fails before hedge fires', async () => {
    const primary = vi.fn().mockRejectedValue(new Error('primary-failure'))
    const hedge = vi.fn().mockResolvedValue('hedge-ok')

    await expect(
      hedgedRequest({
        operationName: 'error-op',
        primary,
        hedge,
        hedgeDelayMs: 100,
      }),
    ).rejects.toThrow('primary-failure')

    expect(hedge).not.toHaveBeenCalled()
  })

  it('waits for primary when hedge fails first and primary is still running', async () => {
    const primary = vi.fn().mockImplementation(
      () => new Promise<string>((resolve) => setTimeout(() => resolve('primary-ok'), 1000)),
    )
    const hedge = vi.fn().mockRejectedValue(new Error('hedge-failure'))

    const promise = hedgedRequest({
      operationName: 'both-fail-op',
      primary,
      hedge,
      hedgeDelayMs: 100,
    })

    await vi.advanceTimersByTimeAsync(200)
    expect(hedge).toHaveBeenCalledTimes(1)

    await vi.advanceTimersByTimeAsync(1000)
    await expect(promise).resolves.toBe('primary-ok')
  })

  // -----------------------------------------------------------------------
  // AbortSignal
  // -----------------------------------------------------------------------

  it('rejects with AbortError when signal is already aborted', async () => {
    const controller = new AbortController()
    controller.abort()

    const primary = vi.fn().mockResolvedValue('ok')
    const hedge = vi.fn().mockResolvedValue('ok')

    await expect(
      hedgedRequest({
        operationName: 'aborted',
        primary,
        hedge,
        signal: controller.signal,
      }),
    ).rejects.toBeInstanceOf(AbortError)
  })

  it('rejects with AbortError when signal aborts during delay window', async () => {
    const controller = new AbortController()
    const primary = vi.fn().mockImplementation(never)
    const hedge = vi.fn().mockResolvedValue('hedge')

    const promise = hedgedRequest({
      operationName: 'abort-during-delay',
      primary,
      hedge,
      hedgeDelayMs: 500,
      signal: controller.signal,
    })

    controller.abort()

    await expect(promise).rejects.toBeInstanceOf(AbortError)
    expect(hedge).not.toHaveBeenCalled()
  })

  // -----------------------------------------------------------------------
  // setMaxConcurrentHedges / getMaxConcurrentHedges
  // -----------------------------------------------------------------------

  it('enforces a minimum concurrent hedge limit of 1', () => {
    setMaxConcurrentHedges(0)
    expect(getMaxConcurrentHedges()).toBe(1)

    setMaxConcurrentHedges(-5)
    expect(getMaxConcurrentHedges()).toBe(1)

    setMaxConcurrentHedges(10)
    expect(getMaxConcurrentHedges()).toBe(10)
  })
})
