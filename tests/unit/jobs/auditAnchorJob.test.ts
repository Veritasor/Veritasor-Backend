/**
 * tests/unit/jobs/auditAnchorJob.test.ts
 *
 * Tests for src/jobs/auditAnchorJob.ts
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

// We use vi.mock so the repository's in-memory state is under our control.
vi.mock('../../../src/repositories/auditLogRepository.js', () => ({
  getCurrentChainRoot: vi.fn(),
  verifyChain: vi.fn(),
}))

vi.mock('../../../src/utils/logger.js', () => ({
  logger: {
    info:  vi.fn(),
    warn:  vi.fn(),
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

function mockValidChain(root: string | null, count: number) {
  vi.mocked(repo.verifyChain).mockReturnValue({
    valid:          true,
    checkedCount:   count,
    brokenAtIndex:  null,
    brokenAtId:     null,
    chainRoot:      root,
  })
}

function mockBrokenChain(root: string | null, brokenAt: number) {
  vi.mocked(repo.verifyChain).mockReturnValue({
    valid:          false,
    checkedCount:   brokenAt,
    brokenAtIndex:  brokenAt,
    brokenAtId:     'broken-entry-id',
    chainRoot:      root,
  })
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

beforeEach(() => {
  vi.clearAllMocks()
  vi.useFakeTimers()
})

afterEach(() => {
  vi.useRealTimers()
  vi.restoreAllMocks()
})

// ---------------------------------------------------------------------------
// anchorChainRoot
// ---------------------------------------------------------------------------

describe('anchorChainRoot', () => {
  it('returns an AnchorRecord with valid=true when chain is intact', () => {
    mockValidChain('abc'.repeat(21) + 'a', 5)

    const record = anchorChainRoot()

    expect(record.chainValid).toBe(true)
    expect(record.entryCount).toBe(5)
    expect(record.anchoredAt).toBeTruthy()
    expect(new Date(record.anchoredAt).getTime()).not.toBeNaN()
  })

  it('logs at info level when chain is valid', () => {
    mockValidChain('a'.repeat(64), 3)
    anchorChainRoot()
    expect(logger.info).toHaveBeenCalledOnce()
    expect(logger.error).not.toHaveBeenCalled()
  })

  it('returns chainValid=false and logs at error level when chain is broken', () => {
    mockBrokenChain('b'.repeat(64), 2)

    const record = anchorChainRoot()

    expect(record.chainValid).toBe(false)
    expect(logger.error).toHaveBeenCalledOnce()
    expect(logger.info).not.toHaveBeenCalled()
  })

  it('returns chainRoot=null and entryCount=0 for empty log', () => {
    mockValidChain(null, 0)

    const record = anchorChainRoot()

    expect(record.chainRoot).toBeNull()
    expect(record.entryCount).toBe(0)
    expect(record.chainValid).toBe(true)
  })

  it('anchor record contains an ISO 8601 timestamp', () => {
    mockValidChain('f'.repeat(64), 1)
    const record = anchorChainRoot()
    expect(record.anchoredAt).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/)
  })

  it('info log includes chainRoot and entryCount', () => {
    const root = 'c'.repeat(64)
    mockValidChain(root, 7)
    anchorChainRoot()

    const logArg = vi.mocked(logger.info).mock.calls[0][0] as Record<string, unknown>
    expect(logArg.chainRoot).toBe(root)
    expect(logArg.entryCount).toBe(7)
  })

  it('error log includes brokenAtIndex when chain is broken', () => {
    mockBrokenChain('d'.repeat(64), 3)
    anchorChainRoot()

    const logArg = vi.mocked(logger.error).mock.calls[0][0] as Record<string, unknown>
    expect(logArg.brokenAtIndex).toBe(3)
    expect(logArg.brokenAtId).toBe('broken-entry-id')
  })
})

// ---------------------------------------------------------------------------
// createAuditAnchorJob
// ---------------------------------------------------------------------------

describe('createAuditAnchorJob', () => {
  it('does not call anchorChainRoot immediately when runImmediately is false (default)', () => {
    mockValidChain('a'.repeat(64), 1)
    const job = createAuditAnchorJob({ intervalMs: 1000 })
    expect(logger.info).not.toHaveBeenCalled()
    job.stop()
  })

  it('calls anchorChainRoot immediately when runImmediately=true', () => {
    mockValidChain('a'.repeat(64), 1)
    const job = createAuditAnchorJob({ intervalMs: 1000, runImmediately: true })
    expect(logger.info).toHaveBeenCalledOnce()
    job.stop()
  })

  it('fires on the interval', () => {
    mockValidChain('a'.repeat(64), 1)
    const job = createAuditAnchorJob({ intervalMs: 1000 })

    vi.advanceTimersByTime(3000)

    // Should have fired 3 times (at 1 s, 2 s, 3 s).
    expect(logger.info).toHaveBeenCalledTimes(3)
    job.stop()
  })

  it('stop() prevents further firings', () => {
    mockValidChain('a'.repeat(64), 1)
    const job = createAuditAnchorJob({ intervalMs: 1000 })

    vi.advanceTimersByTime(2000)
    job.stop()
    vi.advanceTimersByTime(5000)

    expect(logger.info).toHaveBeenCalledTimes(2)
  })

  it('flush() fires anchor immediately and returns an AnchorRecord', () => {
    mockValidChain('e'.repeat(64), 4)
    const job = createAuditAnchorJob({ intervalMs: 60_000 })

    const record = job.flush()

    expect(record.chainValid).toBe(true)
    expect(record.entryCount).toBe(4)
    job.stop()
  })

  it('uses 1-hour default when no intervalMs provided', () => {
    mockValidChain('a'.repeat(64), 1)
    const job = createAuditAnchorJob()

    vi.advanceTimersByTime(60 * 60 * 1000)
    expect(logger.info).toHaveBeenCalledOnce()

    vi.advanceTimersByTime(60 * 60 * 1000)
    expect(logger.info).toHaveBeenCalledTimes(2)

    job.stop()
  })
})
