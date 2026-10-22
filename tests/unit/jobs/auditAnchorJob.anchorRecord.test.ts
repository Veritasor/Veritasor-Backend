/**
 * tests/unit/jobs/auditAnchorJob.anchorRecord.test.ts
 *
 * Focused behaviour coverage for the `AnchorRecord` contract emitted by
 * src/jobs/auditAnchorJob.ts, plus the scheduling guarantees around it.
 *
 * The existing `auditAnchorJob.test.ts` exercises the log-level branches with a
 * fully mocked repository.  What it does *not* pin down — and what a downstream
 * off-system sink actually depends on — is:
 *
 *   • the exact shape of the anchored payload (a sink that persists these
 *     records must never see an unexpected key, and must always see all four),
 *   • that the root/count on each record are the ones reported by the chain
 *     verifier at *that* anchor, including for a broken chain,
 *   • that anchoring re-reads the chain every cycle instead of caching the
 *     first root it ever saw,
 *   • that every anchor produces a fresh record rather than reusing one object,
 *   • that the interval is scheduled with the requested delay, is `unref()`'d
 *     so it cannot keep the process alive, and that `stop()` clears that exact
 *     handle.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

vi.mock('../../../src/repositories/auditLogRepository.js', () => ({
  getCurrentChainRoot: vi.fn(),
  verifyChain: vi.fn(),
}))

vi.mock('../../../src/utils/logger.js', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}))

import {
  anchorChainRoot,
  createAuditAnchorJob,
  type AnchorRecord,
} from '../../../src/jobs/auditAnchorJob.js'
import * as repo from '../../../src/repositories/auditLogRepository.js'
import { logger } from '../../../src/utils/logger.js'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const ANCHOR_RECORD_KEYS = ['anchoredAt', 'chainRoot', 'chainValid', 'entryCount'] as const

const ROOT_A = 'a'.repeat(64)
const ROOT_B = 'b'.repeat(64)
const ROOT_C = 'c'.repeat(64)

/** `verifyChain()` result for an intact chain. */
function validChain(chainRoot: string | null, checkedCount: number) {
  return {
    valid: true,
    checkedCount,
    brokenAtIndex: null,
    brokenAtId: null,
    chainRoot,
  }
}

/** `verifyChain()` result for a chain that broke at `brokenAtIndex`. */
function brokenChain(chainRoot: string | null, checkedCount: number, brokenAtIndex = checkedCount) {
  return {
    valid: false,
    checkedCount,
    brokenAtIndex,
    brokenAtId: 'broken-entry-id',
    chainRoot,
  }
}

/** Typed accessor for the context object handed to the logger. */
function logContext(spy: unknown, callIndex = 0): Record<string, unknown> {
  return vi.mocked(spy as (...args: unknown[]) => unknown).mock.calls[callIndex][0] as Record<string, unknown>
}

beforeEach(() => {
  vi.clearAllMocks()
})

// ---------------------------------------------------------------------------
// AnchorRecord shape
// ---------------------------------------------------------------------------

describe('AnchorRecord shape', () => {
  it('emits exactly the four documented keys and nothing else', () => {
    vi.mocked(repo.verifyChain).mockReturnValue(validChain(ROOT_A, 3))

    const record = anchorChainRoot()

    expect(Object.keys(record).sort()).toEqual([...ANCHOR_RECORD_KEYS].sort())
  })

  it('never leaks the verifier diagnostics (brokenAtIndex/brokenAtId) onto the record', () => {
    vi.mocked(repo.verifyChain).mockReturnValue(brokenChain(ROOT_C, 2, 2))

    const record = anchorChainRoot()

    expect(record).not.toHaveProperty('brokenAtIndex')
    expect(record).not.toHaveProperty('brokenAtId')
  })

  it('keeps all four fields on every branch (valid, broken, empty)', () => {
    const cases = [
      validChain(ROOT_A, 4),
      brokenChain(ROOT_C, 2, 2),
      validChain(null, 0),
    ]

    for (const verification of cases) {
      vi.mocked(repo.verifyChain).mockReturnValue(verification)
      const record = anchorChainRoot()

      expect(Object.keys(record).sort()).toEqual([...ANCHOR_RECORD_KEYS].sort())
      expect(typeof record.anchoredAt).toBe('string')
      expect(typeof record.chainValid).toBe('boolean')
      expect(typeof record.entryCount).toBe('number')
      expect(record.chainRoot === null || typeof record.chainRoot === 'string').toBe(true)
    }
  })
})

// ---------------------------------------------------------------------------
// AnchorRecord values mirror the verifier snapshot
// ---------------------------------------------------------------------------

describe('AnchorRecord values mirror the verifier snapshot', () => {
  it('copies chainRoot and entryCount from the intact-chain verification', () => {
    vi.mocked(repo.verifyChain).mockReturnValue(validChain(ROOT_B, 12))

    const record = anchorChainRoot()

    expect(record.chainRoot).toBe(ROOT_B)
    expect(record.entryCount).toBe(12)
    expect(record.chainValid).toBe(true)
  })

  it('still anchors the last known root when the chain is broken', () => {
    vi.mocked(repo.verifyChain).mockReturnValue(brokenChain(ROOT_C, 2, 2))

    const record = anchorChainRoot()

    expect(record.chainRoot).toBe(ROOT_C)
    expect(record.chainValid).toBe(false)
  })

  it('reports entries actually verified, not a fabricated total, for a broken chain', () => {
    // Verification aborts at the first mismatch, so `checkedCount` is the number
    // of entries proven correct. The anchor must surface that number verbatim.
    vi.mocked(repo.verifyChain).mockReturnValue(brokenChain(ROOT_C, 7, 7))

    const record = anchorChainRoot()

    expect(record.entryCount).toBe(7)
  })

  it('treats an empty chain as valid with a null root and zero count', () => {
    vi.mocked(repo.verifyChain).mockReturnValue(validChain(null, 0))

    const record = anchorChainRoot()

    expect(record).toMatchObject({ chainRoot: null, entryCount: 0, chainValid: true })
  })

  it('agrees with getCurrentChainRoot() on the empty-chain sentinel', () => {
    vi.mocked(repo.verifyChain).mockReturnValue(validChain(null, 0))
    vi.mocked(repo.getCurrentChainRoot).mockReturnValue(null)

    expect(anchorChainRoot().chainRoot).toBe(repo.getCurrentChainRoot())
  })
})

// ---------------------------------------------------------------------------
// Freshness / re-read semantics
// ---------------------------------------------------------------------------

describe('AnchorRecord freshness', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('returns a distinct record object on every call', () => {
    vi.mocked(repo.verifyChain).mockReturnValue(validChain(ROOT_A, 1))

    const first = anchorChainRoot()
    const second = anchorChainRoot()

    expect(first).not.toBe(second)
    expect(first).toEqual(second)
  })

  it('stamps each record with the clock at anchor time', () => {
    vi.mocked(repo.verifyChain).mockReturnValue(validChain(ROOT_A, 1))

    vi.setSystemTime(new Date('2026-01-01T00:00:00.000Z'))
    const first = anchorChainRoot()

    vi.setSystemTime(new Date('2026-01-01T01:00:00.000Z'))
    const second = anchorChainRoot()

    expect(first.anchoredAt).toBe('2026-01-01T00:00:00.000Z')
    expect(second.anchoredAt).toBe('2026-01-01T01:00:00.000Z')
    expect(second.anchoredAt >= first.anchoredAt).toBe(true)
  })

  it('re-reads the chain on every anchor instead of caching the first root', () => {
    vi.mocked(repo.verifyChain).mockReturnValue(validChain(ROOT_A, 1))
    expect(anchorChainRoot().chainRoot).toBe(ROOT_A)

    vi.mocked(repo.verifyChain).mockReturnValue(validChain(ROOT_B, 2))
    expect(anchorChainRoot().chainRoot).toBe(ROOT_B)

    vi.mocked(repo.verifyChain).mockReturnValue(validChain(ROOT_C, 3))
    expect(anchorChainRoot().chainRoot).toBe(ROOT_C)

    expect(repo.verifyChain).toHaveBeenCalledTimes(3)
  })
})

// ---------------------------------------------------------------------------
// Logger payload mirrors the record
// ---------------------------------------------------------------------------

describe('anchor log payload mirrors the record', () => {
  it('logs the same chainRoot/entryCount that it returns (intact chain)', () => {
    vi.mocked(repo.verifyChain).mockReturnValue(validChain(ROOT_B, 5))

    const record = anchorChainRoot()
    const context = logContext(logger.info)

    expect(context.chainRoot).toBe(record.chainRoot)
    expect(context.entryCount).toBe(record.entryCount)
    expect(context.chainValid).toBe(true)
    expect(context.event).toBe('audit_chain_anchor')
  })

  it('logs the same chainRoot/entryCount that it returns (broken chain)', () => {
    vi.mocked(repo.verifyChain).mockReturnValue(brokenChain(ROOT_C, 2, 2))

    const record = anchorChainRoot()
    const context = logContext(logger.error)

    expect(context.chainRoot).toBe(record.chainRoot)
    expect(context.entryCount).toBe(record.entryCount)
    expect(context.chainValid).toBe(false)
    expect(context.brokenAtIndex).toBe(2)
    expect(context.brokenAtId).toBe('broken-entry-id')
  })
})

// ---------------------------------------------------------------------------
// Scheduling guarantees
// ---------------------------------------------------------------------------

describe('createAuditAnchorJob scheduling', () => {
  /** Install a spyable, manually-driven interval. */
  function stubInterval() {
    const unref = vi.fn()
    const handle = { unref } as unknown as ReturnType<typeof setInterval>
    const setIntervalSpy = vi.spyOn(globalThis, 'setInterval').mockReturnValue(handle)
    const clearIntervalSpy = vi.spyOn(globalThis, 'clearInterval').mockImplementation(() => {})
    const tick = () => (setIntervalSpy.mock.calls[0][0] as () => void)()
    return { unref, handle, setIntervalSpy, clearIntervalSpy, tick }
  }

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('schedules with the requested delay and unrefs the timer', () => {
    vi.mocked(repo.verifyChain).mockReturnValue(validChain(ROOT_A, 1))
    const { unref, setIntervalSpy } = stubInterval()

    const job = createAuditAnchorJob({ intervalMs: 5000 })

    expect(setIntervalSpy).toHaveBeenCalledTimes(1)
    expect(setIntervalSpy).toHaveBeenCalledWith(expect.any(Function), 5000)
    expect(unref).toHaveBeenCalledOnce()

    job.stop()
  })

  it('defaults to a one-hour interval and unrefs it', () => {
    vi.mocked(repo.verifyChain).mockReturnValue(validChain(ROOT_A, 1))
    const { unref, setIntervalSpy } = stubInterval()

    const job = createAuditAnchorJob()

    expect(setIntervalSpy).toHaveBeenCalledWith(expect.any(Function), 60 * 60 * 1000)
    expect(unref).toHaveBeenCalledOnce()

    job.stop()
  })

  it('does not throw when the host returns a timer without unref()', () => {
    vi.mocked(repo.verifyChain).mockReturnValue(validChain(ROOT_A, 1))
    vi.spyOn(globalThis, 'setInterval').mockReturnValue(42 as unknown as ReturnType<typeof setInterval>)
    vi.spyOn(globalThis, 'clearInterval').mockImplementation(() => {})

    expect(() => {
      const job = createAuditAnchorJob({ intervalMs: 1000 })
      job.stop()
    }).not.toThrow()
  })

  it('anchors with the latest root on each tick', () => {
    const { tick } = stubInterval()
    vi.mocked(repo.verifyChain).mockReturnValue(validChain(ROOT_A, 1))

    const job = createAuditAnchorJob({ intervalMs: 1000 })

    vi.mocked(repo.verifyChain).mockReturnValue(validChain(ROOT_B, 2))
    tick()

    vi.mocked(repo.verifyChain).mockReturnValue(validChain(ROOT_C, 3))
    tick()

    const roots = vi.mocked(logger.info).mock.calls.map(c => (c[0] as Record<string, unknown>).chainRoot)
    expect(roots).toEqual([ROOT_B, ROOT_C])

    job.stop()
  })

  it('does not anchor at creation unless runImmediately is set, then anchors exactly once', () => {
    const { tick } = stubInterval()
    vi.mocked(repo.verifyChain).mockReturnValue(validChain(ROOT_A, 1))

    const lazy = createAuditAnchorJob({ intervalMs: 1000 })
    expect(logger.info).not.toHaveBeenCalled()
    lazy.stop()

    const eager = createAuditAnchorJob({ intervalMs: 1000, runImmediately: true })
    expect(logger.info).toHaveBeenCalledTimes(1)

    // The immediate anchor must not be re-run when the first tick arrives.
    tick()
    expect(logger.info).toHaveBeenCalledTimes(2)
    eager.stop()
  })

  it('clears the exact timer handle it created on stop()', () => {
    vi.mocked(repo.verifyChain).mockReturnValue(validChain(ROOT_A, 1))
    const { handle, clearIntervalSpy } = stubInterval()

    const job = createAuditAnchorJob({ intervalMs: 1000 })
    job.stop()

    expect(clearIntervalSpy).toHaveBeenCalledWith(handle)
  })

  it('flush() keeps working after stop() and returns a fresh record each time', () => {
    vi.mocked(repo.verifyChain).mockReturnValue(validChain(ROOT_A, 4))
    const { clearIntervalSpy } = stubInterval()

    const job = createAuditAnchorJob({ intervalMs: 60_000 })
    job.stop()

    const first: AnchorRecord = job.flush()
    const second: AnchorRecord = job.flush()

    expect(first).not.toBe(second)
    expect(first).toMatchObject({ chainRoot: ROOT_A, entryCount: 4, chainValid: true })
    expect(second).toMatchObject({ chainRoot: ROOT_A, entryCount: 4, chainValid: true })

    // stop() only disarms the interval; flush must not touch the timer again.
    expect(clearIntervalSpy).toHaveBeenCalledTimes(1)
  })
})
