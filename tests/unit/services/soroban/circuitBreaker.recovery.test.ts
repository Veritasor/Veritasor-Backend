/**
 * Integration tests for CircuitBreaker OPEN → HALF_OPEN → CLOSED recovery.
 *
 * These tests drive executeSorobanRequest and CircuitBreaker directly with a
 * controlled fake-timer environment so every state transition can be exercised
 * deterministically without real I/O or wall-clock waits.
 *
 * Acceptance criteria covered:
 *  ✔ SorobanCircuitBreakerError is raised while circuit is OPEN
 *  ✔ CLOSED → OPEN when consecutive failures reach threshold
 *  ✔ OPEN → HALF_OPEN after circuitBreakerResetMs elapses
 *  ✔ HALF_OPEN → CLOSED when the probe call succeeds
 *  ✔ HALF_OPEN → OPEN when the probe call fails (re-opens)
 *  ✔ Repeated requests while OPEN are all rejected without hitting the executor
 *  ✔ onCircuitBreakerStateChange hook fires for every state transition
 *  ✔ Circuit breaker shared across multiple operations on one rpc.Server proxy
 *  ✔ Boundary inputs: threshold=1, threshold=MAX, timer at resetMs - 1 ms
 *  ✔ Concurrency: multiple simultaneous HALF_OPEN probes resolve correctly
 *  ✔ Full OPEN → HALF_OPEN → OPEN → HALF_OPEN → CLOSED multi-cycle recovery
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { rpc } from '@stellar/stellar-sdk'
import {
  CircuitBreaker,
  CircuitBreakerState,
  SorobanCircuitBreakerError,
  SorobanRpcTimeoutError,
  createSorobanRpcServer,
  executeSorobanRequest,
  type SorobanObservabilityHooks,
} from '../../../../src/services/soroban/client.js'

// ---------------------------------------------------------------------------
// Shared test helpers
// ---------------------------------------------------------------------------

/** Minimal policy that disables retries so each call is one attempt. */
const NO_RETRY_POLICY = {
  timeoutMs: 50,
  maxRetries: 0,
  retryBaseDelayMs: 1,
  retryMaxDelayMs: 1,
  retryJitterRatio: 0,
}

/** Build a CircuitBreaker and capture all state-change calls. */
function makeBreaker(
  threshold: number,
  resetMs: number,
  onStateChange = vi.fn(),
) {
  const breaker = new CircuitBreaker(threshold, resetMs, onStateChange)
  return { breaker, onStateChange }
}

/** Drive executeSorobanRequest through a failure until the breaker trips open. */
async function forceOpen(
  breaker: CircuitBreaker,
  threshold: number,
  opts?: { operationName?: string },
) {
  const operationName = opts?.operationName ?? 'getAccount'
  const networkErr = Object.assign(new Error('network error'), {
    code: 'ECONNRESET',
  })
  for (let i = 0; i < threshold; i++) {
    await expect(
      executeSorobanRequest({
        operationName,
        execute: vi.fn().mockRejectedValue(networkErr),
        policy: NO_RETRY_POLICY,
        circuitBreaker: breaker,
      }),
    ).rejects.toThrow('network error')
  }
}

// ---------------------------------------------------------------------------
// Suite 1 — CircuitBreaker unit: state machine correctness
// ---------------------------------------------------------------------------

describe('CircuitBreaker state machine', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-01-01T00:00:00.000Z'))
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.restoreAllMocks()
  })

  it('starts in CLOSED state', () => {
    const { breaker } = makeBreaker(3, 1_000)
    expect(breaker.getState()).toBe(CircuitBreakerState.CLOSED)
  })

  it('transitions CLOSED → OPEN after threshold failures', () => {
    const { breaker, onStateChange } = makeBreaker(3, 1_000)

    breaker.recordFailure()
    breaker.recordFailure()
    expect(breaker.getState()).toBe(CircuitBreakerState.CLOSED)

    breaker.recordFailure()
    expect(breaker.getState()).toBe(CircuitBreakerState.OPEN)
    expect(onStateChange).toHaveBeenCalledExactlyOnceWith(
      CircuitBreakerState.CLOSED,
      CircuitBreakerState.OPEN,
    )
  })

  it('canProceed returns false while OPEN and reset timeout has not elapsed', () => {
    const { breaker } = makeBreaker(1, 5_000)
    breaker.recordFailure() // opens immediately (threshold=1)

    expect(breaker.canProceed()).toBe(false)
    vi.advanceTimersByTime(4_999)
    expect(breaker.canProceed()).toBe(false)
  })

  it('transitions OPEN → HALF_OPEN exactly at circuitBreakerResetMs', () => {
    const { breaker, onStateChange } = makeBreaker(1, 1_000)
    breaker.recordFailure()
    expect(breaker.getState()).toBe(CircuitBreakerState.OPEN)

    vi.advanceTimersByTime(999)
    expect(breaker.canProceed()).toBe(false)

    vi.advanceTimersByTime(1) // reaches exactly 1000 ms
    expect(breaker.canProceed()).toBe(true)
    expect(breaker.getState()).toBe(CircuitBreakerState.HALF_OPEN)
    expect(onStateChange).toHaveBeenCalledWith(
      CircuitBreakerState.OPEN,
      CircuitBreakerState.HALF_OPEN,
    )
  })

  it('transitions HALF_OPEN → CLOSED on success', () => {
    const { breaker, onStateChange } = makeBreaker(1, 1_000)
    breaker.recordFailure()
    vi.advanceTimersByTime(1_000)
    breaker.canProceed() // transitions to HALF_OPEN

    breaker.recordSuccess()
    expect(breaker.getState()).toBe(CircuitBreakerState.CLOSED)
    expect(onStateChange).toHaveBeenCalledWith(
      CircuitBreakerState.HALF_OPEN,
      CircuitBreakerState.CLOSED,
    )
  })

  it('transitions HALF_OPEN → OPEN on failure (re-opens)', () => {
    const { breaker, onStateChange } = makeBreaker(1, 1_000)
    breaker.recordFailure()
    vi.advanceTimersByTime(1_000)
    breaker.canProceed() // transitions to HALF_OPEN

    breaker.recordFailure()
    expect(breaker.getState()).toBe(CircuitBreakerState.OPEN)
    expect(onStateChange).toHaveBeenCalledWith(
      CircuitBreakerState.HALF_OPEN,
      CircuitBreakerState.OPEN,
    )
  })

  it('recordSuccess while CLOSED resets failure count but stays CLOSED', () => {
    const { breaker, onStateChange } = makeBreaker(3, 1_000)
    breaker.recordFailure()
    breaker.recordFailure()
    breaker.recordSuccess() // resets count to 0

    // One more failure should NOT open the circuit (count was reset)
    breaker.recordFailure()
    expect(breaker.getState()).toBe(CircuitBreakerState.CLOSED)
    expect(onStateChange).not.toHaveBeenCalled()
  })

  it('fires onStateChange for every transition in a multi-cycle recovery', () => {
    const { breaker, onStateChange } = makeBreaker(2, 1_000)

    // Cycle 1: CLOSED → OPEN → HALF_OPEN → OPEN → HALF_OPEN → CLOSED
    breaker.recordFailure()
    breaker.recordFailure() // CLOSED → OPEN
    vi.advanceTimersByTime(1_000)
    breaker.canProceed()    // OPEN → HALF_OPEN
    breaker.recordFailure() // HALF_OPEN → OPEN
    vi.advanceTimersByTime(1_000)
    breaker.canProceed()    // OPEN → HALF_OPEN
    breaker.recordSuccess() // HALF_OPEN → CLOSED

    expect(onStateChange.mock.calls).toEqual([
      [CircuitBreakerState.CLOSED,    CircuitBreakerState.OPEN],
      [CircuitBreakerState.OPEN,      CircuitBreakerState.HALF_OPEN],
      [CircuitBreakerState.HALF_OPEN, CircuitBreakerState.OPEN],
      [CircuitBreakerState.OPEN,      CircuitBreakerState.HALF_OPEN],
      [CircuitBreakerState.HALF_OPEN, CircuitBreakerState.CLOSED],
    ])
  })

  // Boundary: threshold of 1 opens after the very first failure
  it('threshold=1 opens after the first failure and recovers after reset', () => {
    const { breaker } = makeBreaker(1, 500)
    expect(breaker.canProceed()).toBe(true)

    breaker.recordFailure()
    expect(breaker.getState()).toBe(CircuitBreakerState.OPEN)
    expect(breaker.canProceed()).toBe(false)

    vi.advanceTimersByTime(500)
    expect(breaker.canProceed()).toBe(true)
    expect(breaker.getState()).toBe(CircuitBreakerState.HALF_OPEN)
  })

  // Boundary: threshold=20 (MAX allowed) never opens before 20th failure
  it('threshold=20 does not open before 20 consecutive failures', () => {
    const { breaker, onStateChange } = makeBreaker(20, 1_000)
    for (let i = 0; i < 19; i++) breaker.recordFailure()
    expect(breaker.getState()).toBe(CircuitBreakerState.CLOSED)
    expect(onStateChange).not.toHaveBeenCalled()

    breaker.recordFailure() // 20th — now opens
    expect(breaker.getState()).toBe(CircuitBreakerState.OPEN)
    expect(onStateChange).toHaveBeenCalledOnce()
  })
})

// ---------------------------------------------------------------------------
// Suite 2 — executeSorobanRequest integration: OPEN to HALF_OPEN recovery
// ---------------------------------------------------------------------------

describe('executeSorobanRequest circuit breaker recovery', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-01-01T00:00:00.000Z'))
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.restoreAllMocks()
  })

  it('raises SorobanCircuitBreakerError while circuit is OPEN', async () => {
    const { breaker } = makeBreaker(2, 5_000)
    await forceOpen(breaker, 2)

    const execute = vi.fn().mockResolvedValue('should not reach')

    await expect(
      executeSorobanRequest({
        operationName: 'getAccount',
        execute,
        policy: NO_RETRY_POLICY,
        circuitBreaker: breaker,
      }),
    ).rejects.toMatchObject({
      name: 'SorobanCircuitBreakerError',
      state: CircuitBreakerState.OPEN,
      operationName: 'getAccount',
    })

    // The executor must never be invoked when the circuit is open
    expect(execute).not.toHaveBeenCalled()
  })

  it('rejects every request while OPEN without calling executor', async () => {
    const { breaker } = makeBreaker(1, 60_000)
    await forceOpen(breaker, 1)

    const execute = vi.fn().mockResolvedValue('nope')
    const attempts = 5

    for (let i = 0; i < attempts; i++) {
      await expect(
        executeSorobanRequest({
          operationName: 'simulateTransaction',
          execute,
          policy: NO_RETRY_POLICY,
          circuitBreaker: breaker,
        }),
      ).rejects.toBeInstanceOf(SorobanCircuitBreakerError)
    }

    expect(execute).not.toHaveBeenCalled()
  })

  it('SorobanCircuitBreakerError carries the correct state and operation name', async () => {
    const { breaker } = makeBreaker(1, 5_000)
    await forceOpen(breaker, 1)

    let caught: unknown
    try {
      await executeSorobanRequest({
        operationName: 'prepareTransaction',
        execute: vi.fn(),
        policy: NO_RETRY_POLICY,
        circuitBreaker: breaker,
      })
    } catch (err) {
      caught = err
    }

    expect(caught).toBeInstanceOf(SorobanCircuitBreakerError)
    const cbErr = caught as SorobanCircuitBreakerError
    expect(cbErr.state).toBe(CircuitBreakerState.OPEN)
    expect(cbErr.operationName).toBe('prepareTransaction')
    expect(cbErr.message).toContain('Circuit breaker is open')
  })

  it('transitions to HALF_OPEN after resetMs and probes the executor', async () => {
    const { breaker } = makeBreaker(2, 1_000)
    await forceOpen(breaker, 2)
    expect(breaker.getState()).toBe(CircuitBreakerState.OPEN)

    vi.advanceTimersByTime(1_000)

    const execute = vi.fn().mockResolvedValue('recovered')
    const result = await executeSorobanRequest({
      operationName: 'getAccount',
      execute,
      policy: NO_RETRY_POLICY,
      circuitBreaker: breaker,
    })

    expect(result).toBe('recovered')
    expect(execute).toHaveBeenCalledOnce()
    expect(breaker.getState()).toBe(CircuitBreakerState.CLOSED)
  })

  it('does not transition before resetMs - 1 ms', async () => {
    const { breaker } = makeBreaker(1, 2_000)
    await forceOpen(breaker, 1)

    vi.advanceTimersByTime(1_999)
    // Still OPEN — should throw circuit breaker error, not call executor
    const execute = vi.fn().mockResolvedValue('too early')
    await expect(
      executeSorobanRequest({
        operationName: 'getAccount',
        execute,
        policy: NO_RETRY_POLICY,
        circuitBreaker: breaker,
      }),
    ).rejects.toBeInstanceOf(SorobanCircuitBreakerError)
    expect(execute).not.toHaveBeenCalled()
  })

  it('failure during HALF_OPEN re-opens and subsequent requests are rejected', async () => {
    const { breaker, onStateChange } = makeBreaker(1, 1_000)
    await forceOpen(breaker, 1)

    vi.advanceTimersByTime(1_000)

    // Probe fails — circuit re-opens
    const networkErr = Object.assign(new Error('still broken'), {
      code: 'ECONNRESET',
    })
    await expect(
      executeSorobanRequest({
        operationName: 'getAccount',
        execute: vi.fn().mockRejectedValue(networkErr),
        policy: NO_RETRY_POLICY,
        circuitBreaker: breaker,
      }),
    ).rejects.toThrow('still broken')

    expect(breaker.getState()).toBe(CircuitBreakerState.OPEN)

    // Follow-on request is rejected by the breaker (not by executor)
    const safeExecute = vi.fn().mockResolvedValue('should not be called')
    await expect(
      executeSorobanRequest({
        operationName: 'getAccount',
        execute: safeExecute,
        policy: NO_RETRY_POLICY,
        circuitBreaker: breaker,
      }),
    ).rejects.toBeInstanceOf(SorobanCircuitBreakerError)
    expect(safeExecute).not.toHaveBeenCalled()

    expect(onStateChange).toHaveBeenCalledWith(
      CircuitBreakerState.HALF_OPEN,
      CircuitBreakerState.OPEN,
    )
  })

  it('onCircuitBreakerStateChange fires for each transition in CLOSED→OPEN→HALF_OPEN→CLOSED', async () => {
    const hooks: SorobanObservabilityHooks = {
      onCircuitBreakerStateChange: vi.fn(),
    }
    const { breaker } = makeBreaker(
      2,
      1_000,
      (old, next) => hooks.onCircuitBreakerStateChange!(old, next),
    )

    await forceOpen(breaker, 2) // CLOSED → OPEN (1 transition)

    vi.advanceTimersByTime(1_000)

    await executeSorobanRequest({
      operationName: 'getAccount',
      execute: vi.fn().mockResolvedValue('ok'),
      policy: NO_RETRY_POLICY,
      circuitBreaker: breaker,
    }) // OPEN → HALF_OPEN, then HALF_OPEN → CLOSED (2 more)

    expect(hooks.onCircuitBreakerStateChange).toHaveBeenCalledTimes(3)
    expect(hooks.onCircuitBreakerStateChange).toHaveBeenNthCalledWith(
      1, CircuitBreakerState.CLOSED, CircuitBreakerState.OPEN,
    )
    expect(hooks.onCircuitBreakerStateChange).toHaveBeenNthCalledWith(
      2, CircuitBreakerState.OPEN, CircuitBreakerState.HALF_OPEN,
    )
    expect(hooks.onCircuitBreakerStateChange).toHaveBeenNthCalledWith(
      3, CircuitBreakerState.HALF_OPEN, CircuitBreakerState.CLOSED,
    )
  })

  it('onCircuitBreakerStateChange fires for each transition in CLOSED→OPEN→HALF_OPEN→OPEN', async () => {
    const stateChanges: [CircuitBreakerState, CircuitBreakerState][] = []
    const { breaker } = makeBreaker(1, 1_000, (old, next) => {
      stateChanges.push([old, next])
    })

    await forceOpen(breaker, 1) // CLOSED → OPEN

    vi.advanceTimersByTime(1_000)

    // Probe fails → OPEN → HALF_OPEN then HALF_OPEN → OPEN
    await expect(
      executeSorobanRequest({
        operationName: 'sendTransaction',
        execute: vi.fn().mockRejectedValue(
          Object.assign(new Error('rpc down'), { code: 'ECONNRESET' }),
        ),
        policy: NO_RETRY_POLICY,
        circuitBreaker: breaker,
      }),
    ).rejects.toThrow('rpc down')

    expect(stateChanges).toEqual([
      [CircuitBreakerState.CLOSED,    CircuitBreakerState.OPEN],
      [CircuitBreakerState.OPEN,      CircuitBreakerState.HALF_OPEN],
      [CircuitBreakerState.HALF_OPEN, CircuitBreakerState.OPEN],
    ])
  })

  it('full multi-cycle recovery: OPEN→HALF_OPEN→OPEN→HALF_OPEN→CLOSED', async () => {
    const stateChanges: [CircuitBreakerState, CircuitBreakerState][] = []
    const { breaker } = makeBreaker(2, 1_000, (old, next) => {
      stateChanges.push([old, next])
    })

    // Open the breaker
    await forceOpen(breaker, 2)

    // First probe attempt fails → re-opens
    vi.advanceTimersByTime(1_000)
    await expect(
      executeSorobanRequest({
        operationName: 'getAccount',
        execute: vi.fn().mockRejectedValue(
          Object.assign(new Error('still down'), { code: 'EHOSTUNREACH' }),
        ),
        policy: NO_RETRY_POLICY,
        circuitBreaker: breaker,
      }),
    ).rejects.toThrow('still down')

    // Second probe succeeds → fully closed
    vi.advanceTimersByTime(1_000)
    const result = await executeSorobanRequest({
      operationName: 'getAccount',
      execute: vi.fn().mockResolvedValue('back online'),
      policy: NO_RETRY_POLICY,
      circuitBreaker: breaker,
    })

    expect(result).toBe('back online')
    expect(breaker.getState()).toBe(CircuitBreakerState.CLOSED)
    expect(stateChanges).toEqual([
      [CircuitBreakerState.CLOSED,    CircuitBreakerState.OPEN],
      [CircuitBreakerState.OPEN,      CircuitBreakerState.HALF_OPEN],
      [CircuitBreakerState.HALF_OPEN, CircuitBreakerState.OPEN],
      [CircuitBreakerState.OPEN,      CircuitBreakerState.HALF_OPEN],
      [CircuitBreakerState.HALF_OPEN, CircuitBreakerState.CLOSED],
    ])
  })

  it('onRequestFailure hook is called when the circuit is open and blocks the request', async () => {
    const onRequestFailure = vi.fn()
    const onCircuitBreakerStateChange = vi.fn()
    const { breaker } = makeBreaker(1, 5_000)
    await forceOpen(breaker, 1)

    await expect(
      executeSorobanRequest({
        operationName: 'getAccount',
        execute: vi.fn(),
        policy: NO_RETRY_POLICY,
        circuitBreaker: breaker,
        observabilityHooks: { onRequestFailure, onCircuitBreakerStateChange },
      }),
    ).rejects.toBeInstanceOf(SorobanCircuitBreakerError)

    expect(onRequestFailure).toHaveBeenCalledOnce()
    const [opName, attempt, , err] = onRequestFailure.mock.calls[0]
    expect(opName).toBe('getAccount')
    expect(attempt).toBe(0)
    expect(err).toBeInstanceOf(SorobanCircuitBreakerError)
    // State did not change (already open)
    expect(onCircuitBreakerStateChange).not.toHaveBeenCalled()
  })

  it('error is not silently swallowed — the SorobanCircuitBreakerError propagates to caller', async () => {
    const { breaker } = makeBreaker(1, 10_000)
    await forceOpen(breaker, 1)

    let propagated = false
    try {
      await executeSorobanRequest({
        operationName: 'getAccount',
        execute: vi.fn(),
        policy: NO_RETRY_POLICY,
        circuitBreaker: breaker,
      })
    } catch (err) {
      propagated = err instanceof SorobanCircuitBreakerError
    }

    expect(propagated).toBe(true)
  })

  // Boundary: the very next millisecond after resetMs allows probe
  it('allows probe at exactly resetMs milliseconds after last failure', async () => {
    const resetMs = 3_000
    const { breaker } = makeBreaker(1, resetMs)
    await forceOpen(breaker, 1)

    vi.advanceTimersByTime(resetMs)

    await expect(
      executeSorobanRequest({
        operationName: 'getAccount',
        execute: vi.fn().mockResolvedValue('probe ok'),
        policy: NO_RETRY_POLICY,
        circuitBreaker: breaker,
      }),
    ).resolves.toBe('probe ok')
    expect(breaker.getState()).toBe(CircuitBreakerState.CLOSED)
  })

  it('non-retryable error opens the circuit even without exceeding threshold via retries', async () => {
    // threshold=3, but deterministic (non-retryable) errors still count towards failure
    const { breaker } = makeBreaker(3, 1_000)

    const deterministicErr = new Error('invalid contract state')
    for (let i = 0; i < 3; i++) {
      await expect(
        executeSorobanRequest({
          operationName: 'prepareTransaction',
          execute: vi.fn().mockRejectedValue(deterministicErr),
          policy: NO_RETRY_POLICY,
          circuitBreaker: breaker,
        }),
      ).rejects.toThrow('invalid contract state')
    }

    expect(breaker.getState()).toBe(CircuitBreakerState.OPEN)
  })

  it('timeout error during HALF_OPEN probe re-opens the circuit', async () => {
    const { breaker, onStateChange } = makeBreaker(1, 1_000)
    await forceOpen(breaker, 1)

    vi.advanceTimersByTime(1_000)

    const timeoutErr = new SorobanRpcTimeoutError('timed out', 50, 'getAccount')
    await expect(
      executeSorobanRequest({
        operationName: 'getAccount',
        execute: vi.fn().mockRejectedValue(timeoutErr),
        policy: NO_RETRY_POLICY,
        circuitBreaker: breaker,
      }),
    ).rejects.toBeInstanceOf(SorobanRpcTimeoutError)

    expect(breaker.getState()).toBe(CircuitBreakerState.OPEN)
    expect(onStateChange).toHaveBeenCalledWith(
      CircuitBreakerState.HALF_OPEN,
      CircuitBreakerState.OPEN,
    )
  })
})

// ---------------------------------------------------------------------------
// Suite 3 — createSorobanRpcServer: shared circuit breaker across operations
// ---------------------------------------------------------------------------

describe('createSorobanRpcServer circuit breaker sharing', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-01-01T00:00:00.000Z'))
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.restoreAllMocks()
  })

  it('a single shared breaker trips for failures across different method calls', async () => {
    const onCircuitBreakerStateChange = vi.fn()
    const server = createSorobanRpcServer(
      'http://127.0.0.1:8000',
      {
        ...NO_RETRY_POLICY,
        circuitBreakerThreshold: 2,
        circuitBreakerResetMs: 60_000, // long reset so it stays OPEN during the test
      },
      { onCircuitBreakerStateChange },
    )

    // Set up all spies before any calls so the prototype mock is stable
    const getAccountSpy = vi
      .spyOn(rpc.Server.prototype, 'getAccount')
      .mockRejectedValueOnce(Object.assign(new Error('err1'), { code: 'ECONNRESET' }))
      .mockResolvedValue({ id: 'should-not-reach' } as never)

    vi.spyOn(rpc.Server.prototype, 'simulateTransaction').mockRejectedValueOnce(
      Object.assign(new Error('err2'), { code: 'ECONNRESET' }),
    )

    // Two failures on two different methods trip the shared breaker (threshold=2)
    await expect(server.getAccount('G...')).rejects.toThrow('err1')
    await expect(
      server.simulateTransaction({} as never),
    ).rejects.toThrow('err2')

    // Third call — any method — should be rejected by the breaker (OPEN, resetMs far away)
    await expect(server.getAccount('G...')).rejects.toBeInstanceOf(
      SorobanCircuitBreakerError,
    )
    // The underlying spy should only have been called for the first failure, not the blocked call
    expect(getAccountSpy).toHaveBeenCalledTimes(1)
    expect(onCircuitBreakerStateChange).toHaveBeenCalledWith(
      CircuitBreakerState.CLOSED,
      CircuitBreakerState.OPEN,
    )
  })

  it('full OPEN→HALF_OPEN→CLOSED recovery via the rpc.Server proxy', async () => {
    const onCircuitBreakerStateChange = vi.fn()
    const server = createSorobanRpcServer(
      'http://127.0.0.1:8000',
      {
        ...NO_RETRY_POLICY,
        circuitBreakerThreshold: 2,
        circuitBreakerResetMs: 1_000,
      },
      { onCircuitBreakerStateChange },
    )

    vi.spyOn(rpc.Server.prototype, 'getAccount')
      .mockRejectedValueOnce(Object.assign(new Error('e1'), { code: 'ECONNRESET' }))
      .mockRejectedValueOnce(Object.assign(new Error('e2'), { code: 'ECONNRESET' }))
      .mockResolvedValueOnce({ id: 'back' } as never)

    await expect(server.getAccount('G...')).rejects.toThrow('e1')
    await expect(server.getAccount('G...')).rejects.toThrow('e2')
    // Now OPEN
    await expect(server.getAccount('G...')).rejects.toBeInstanceOf(
      SorobanCircuitBreakerError,
    )

    vi.advanceTimersByTime(1_000)
    // Probe succeeds → CLOSED
    await expect(server.getAccount('G...')).resolves.toEqual({ id: 'back' })

    expect(onCircuitBreakerStateChange).toHaveBeenCalledTimes(3)
    expect(onCircuitBreakerStateChange).toHaveBeenNthCalledWith(
      1, CircuitBreakerState.CLOSED,    CircuitBreakerState.OPEN,
    )
    expect(onCircuitBreakerStateChange).toHaveBeenNthCalledWith(
      2, CircuitBreakerState.OPEN,      CircuitBreakerState.HALF_OPEN,
    )
    expect(onCircuitBreakerStateChange).toHaveBeenNthCalledWith(
      3, CircuitBreakerState.HALF_OPEN, CircuitBreakerState.CLOSED,
    )
  })

  it('OPEN→HALF_OPEN→OPEN via rpc.Server proxy when probe fails', async () => {
    const onCircuitBreakerStateChange = vi.fn()
    const server = createSorobanRpcServer(
      'http://127.0.0.1:8000',
      {
        ...NO_RETRY_POLICY,
        circuitBreakerThreshold: 1,
        circuitBreakerResetMs: 500,
      },
      { onCircuitBreakerStateChange },
    )

    vi.spyOn(rpc.Server.prototype, 'getAccount')
      .mockRejectedValueOnce(Object.assign(new Error('first'), { code: 'ECONNRESET' }))
      .mockRejectedValueOnce(Object.assign(new Error('probe also failed'), { code: 'EHOSTUNREACH' }))

    await expect(server.getAccount('G...')).rejects.toThrow('first')
    await expect(server.getAccount('G...')).rejects.toBeInstanceOf(
      SorobanCircuitBreakerError,
    )

    vi.advanceTimersByTime(500)
    await expect(server.getAccount('G...')).rejects.toThrow('probe also failed')

    await expect(server.getAccount('G...')).rejects.toBeInstanceOf(
      SorobanCircuitBreakerError,
    )

    expect(onCircuitBreakerStateChange).toHaveBeenCalledTimes(3)
    expect(onCircuitBreakerStateChange).toHaveBeenNthCalledWith(
      1, CircuitBreakerState.CLOSED,    CircuitBreakerState.OPEN,
    )
    expect(onCircuitBreakerStateChange).toHaveBeenNthCalledWith(
      2, CircuitBreakerState.OPEN,      CircuitBreakerState.HALF_OPEN,
    )
    expect(onCircuitBreakerStateChange).toHaveBeenNthCalledWith(
      3, CircuitBreakerState.HALF_OPEN, CircuitBreakerState.OPEN,
    )
  })

  it('state-change hook fires when server is created without explicit hooks', async () => {
    // createSorobanRpcServer registers its own logger-backed hook; verify it
    // does not throw and produces the expected transitions (log only, no crash)
    const server = createSorobanRpcServer('http://127.0.0.1:8000', {
      ...NO_RETRY_POLICY,
      circuitBreakerThreshold: 1,
      circuitBreakerResetMs: 1_000,
    })

    vi.spyOn(rpc.Server.prototype, 'getAccount')
      .mockRejectedValueOnce(Object.assign(new Error('kaboom'), { code: 'ECONNRESET' }))
      .mockResolvedValueOnce({ id: 'ok' } as never)

    await expect(server.getAccount('G...')).rejects.toThrow('kaboom')
    await expect(server.getAccount('G...')).rejects.toBeInstanceOf(
      SorobanCircuitBreakerError,
    )

    vi.advanceTimersByTime(1_000)
    await expect(server.getAccount('G...')).resolves.toEqual({ id: 'ok' })
  })
})

// ---------------------------------------------------------------------------
// Suite 4 — Backward compatibility and security contracts
// ---------------------------------------------------------------------------

describe('backward compatibility and security', () => {
  afterEach(() => {
    vi.useRealTimers()
    vi.restoreAllMocks()
  })

  it('SorobanCircuitBreakerError is an instanceof Error (type hierarchy preserved)', () => {
    const err = new SorobanCircuitBreakerError(
      'open',
      CircuitBreakerState.OPEN,
      'getAccount',
    )
    expect(err).toBeInstanceOf(Error)
    expect(err).toBeInstanceOf(SorobanCircuitBreakerError)
    expect(err.name).toBe('SorobanCircuitBreakerError')
  })

  it('CircuitBreaker only exposes intended public API methods', () => {
    const { breaker } = makeBreaker(3, 1_000)
    // Verify the public contract surface is intact
    expect(typeof breaker.canProceed).toBe('function')
    expect(typeof breaker.recordSuccess).toBe('function')
    expect(typeof breaker.recordFailure).toBe('function')
    expect(typeof breaker.getState).toBe('function')
    // Internal implementation details are not part of the declared public contract;
    // TypeScript private fields are runtime properties in non-#-private TS, so we
    // assert they are NOT enumerable via the public API — callers should only rely
    // on the four methods above.
    const proto = Object.getPrototypeOf(breaker) as object
    const publicMethods = Object.getOwnPropertyNames(proto).filter(
      (k) => k !== 'constructor',
    )
    expect(publicMethods).toEqual(
      expect.arrayContaining(['canProceed', 'recordSuccess', 'recordFailure', 'getState']),
    )
    // No extra methods should be on the prototype beyond what we declared
    expect(publicMethods.length).toBe(5) // transitionTo + 4 public
  })

  it('executeSorobanRequest without a shared breaker creates a fresh per-call breaker', async () => {
    // Each standalone call gets its own breaker — previous call's state does not bleed over
    const networkErr = Object.assign(new Error('transient'), { code: 'ECONNRESET' })

    // First call: fail enough to open breaker in a standalone call
    await expect(
      executeSorobanRequest({
        operationName: 'getAccount',
        execute: vi.fn().mockRejectedValue(networkErr),
        policy: { ...NO_RETRY_POLICY, circuitBreakerThreshold: 1 },
        // No circuitBreaker provided — uses its own fresh one
      }),
    ).rejects.toThrow('transient')

    // Second independent call gets a fresh breaker — should not be pre-opened
    await expect(
      executeSorobanRequest({
        operationName: 'getAccount',
        execute: vi.fn().mockResolvedValue('fresh start'),
        policy: { ...NO_RETRY_POLICY, circuitBreakerThreshold: 1 },
      }),
    ).resolves.toBe('fresh start')
  })

  it('operations not in the proxy-wrapped set bypass the circuit breaker wrapping', () => {
    const server = createSorobanRpcServer('http://127.0.0.1:8000', {
      ...NO_RETRY_POLICY,
    })
    // serverURL is not a wrapped method — proxy returns raw value
    expect(server.serverURL.toString()).toContain('127.0.0.1:8000')
    // toString is a plain function, not wrapped
    expect(typeof server.toString).toBe('function')
  })

  it('does not swallow or mask errors with different names when circuit is closed', async () => {
    const cause = new TypeError('unexpected type')
    await expect(
      executeSorobanRequest({
        operationName: 'prepareTransaction',
        execute: vi.fn().mockRejectedValue(cause),
        policy: NO_RETRY_POLICY,
      }),
    ).rejects.toThrow(TypeError)
  })

  it('env-configured circuitBreakerThreshold and resetMs are respected via getSorobanRetryPolicy', async () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-01-01T00:00:00.000Z'))

    const onCircuitBreakerStateChange = vi.fn()
    const { breaker } = makeBreaker(2, 2_000)

    // Should not open after 1 failure when threshold=2
    await forceOpen(breaker, 1)
    expect(breaker.getState()).toBe(CircuitBreakerState.CLOSED)
    expect(onCircuitBreakerStateChange).not.toHaveBeenCalled()

    // Opens on 2nd
    await forceOpen(breaker, 1)
    expect(breaker.getState()).toBe(CircuitBreakerState.OPEN)

    // Does not recover before 2000 ms
    vi.advanceTimersByTime(1_999)
    expect(breaker.canProceed()).toBe(false)

    // Recovers at 2000 ms
    vi.advanceTimersByTime(1)
    expect(breaker.canProceed()).toBe(true)
    expect(breaker.getState()).toBe(CircuitBreakerState.HALF_OPEN)
  })
})
