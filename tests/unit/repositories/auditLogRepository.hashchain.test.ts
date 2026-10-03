/**
 * tests/unit/repositories/auditLogRepository.hashchain.test.ts
 *
 * Tests for the tamper-evident hash-chain implementation in
 * src/repositories/auditLogRepository.ts
 *
 * Coverage targets
 * ─────────────────
 * • canonicaliseEntry – field ordering, undefined optional fields
 * • computeChainHash  – determinism, changes with different prevHash / data
 * • createAuditLog    – chain wiring (GENESIS, prev→next), contentHash
 * • verifyChain       – intact chain, tampered field, deleted entry,
 *                       re-ordered entries, empty log, single-entry log
 * • getCurrentChainRoot – empty, single, multiple
 * • concurrent-insert ordering (sequential inserts produce stable seq)
 * • false-positive guard: metadata change is detected
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import crypto from 'node:crypto'
import {
  createAuditLog,
  getAllAuditLogs,
  getAuditLogsByUser,
  queryAuditLogs,
  verifyChain,
  getCurrentChainRoot,
  clearAllAuditLogs,
  canonicaliseEntry,
  computeChainHash,
  GENESIS_SENTINEL,
  type AuditLog,
} from '../../../src/repositories/auditLogRepository.js'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Build a minimal log input. */
function logInput(overrides: Partial<Omit<AuditLog, 'id' | 'timestamp' | 'chainHash' | 'seq'>> = {}) {
  return {
    userId:   'user-1',
    action:   'CREATE_ATTESTATION',
    resource: 'attestation',
    ...overrides,
  }
}

/** Insert N entries and return them in the order returned by createAuditLog. */
async function insertN(n: number): Promise<AuditLog[]> {
  const results: AuditLog[] = []
  for (let i = 0; i < n; i++) {
    results.push(await createAuditLog(logInput({ userId: `user-${i}`, action: 'CREATE_ATTESTATION' })))
  }
  return results
}

// ---------------------------------------------------------------------------
// Setup / teardown
// ---------------------------------------------------------------------------

// Ensure AUDIT_CHAIN_SECRET is set to the test fallback path (no env var).
const originalSecret = process.env.AUDIT_CHAIN_SECRET
beforeEach(() => {
  delete process.env.AUDIT_CHAIN_SECRET
  clearAllAuditLogs()
})
afterEach(() => {
  if (originalSecret !== undefined) {
    process.env.AUDIT_CHAIN_SECRET = originalSecret
  } else {
    delete process.env.AUDIT_CHAIN_SECRET
  }
  clearAllAuditLogs()
  vi.restoreAllMocks()
})

// ---------------------------------------------------------------------------
// canonicaliseEntry
// ---------------------------------------------------------------------------

describe('canonicaliseEntry', () => {
  it('includes all required fields in a pipe-delimited string', () => {
    const entry: Omit<AuditLog, 'chainHash'> = {
      id: 'abc123',
      userId: 'user-1',
      action: 'DELETE_USER',
      resource: 'user',
      resourceId: 'u-99',
      contentHash: 'hash',
      metadata: { reason: 'test' },
      timestamp: new Date('2026-01-01T00:00:00.000Z'),
      seq: 0,
    }
    const result = canonicaliseEntry(entry)
    expect(result).toContain('abc123')
    expect(result).toContain('user-1')
    expect(result).toContain('DELETE_USER')
    expect(result).toContain('user')
    expect(result).toContain('u-99')
    expect(result).toContain('2026-01-01T00:00:00.000Z')
    // metadata is hashed, not embedded verbatim
    const parts = result.split('|')
    expect(parts).toHaveLength(9)
  })

  it('produces empty strings for optional undefined fields', () => {
    const entry: Omit<AuditLog, 'chainHash'> = {
      id: 'abc',
      userId: 'u',
      action: 'READ',
      resource: 'report',
      timestamp: new Date('2026-01-01T00:00:00.000Z'),
      seq: 0,
    }
    const result = canonicaliseEntry(entry)
    const parts = result.split('|')
    // Format: seq|id|userId|action|resource|resourceId|contentHash|timestamp|metaHash
    // index:  [0] [1] [2]   [3]    [4]      [5]         [6]          [7]       [8]
    expect(parts[5]).toBe('')  // resourceId
    expect(parts[6]).toBe('')  // contentHash
    expect(parts[8]).toBe('')  // metaHash
  })

  it('produces a different string when metadata changes', () => {
    const base: Omit<AuditLog, 'chainHash'> = {
      id: 'abc',
      userId: 'u',
      action: 'READ',
      resource: 'r',
      timestamp: new Date('2026-01-01T00:00:00.000Z'),
      seq: 0,
      metadata: { role: 'admin' },
    }
    const modified = { ...base, metadata: { role: 'superadmin' } }
    expect(canonicaliseEntry(base)).not.toBe(canonicaliseEntry(modified))
  })

  it('includes seq in the canonical string', () => {
    const e1: Omit<AuditLog, 'chainHash'> = { id: 'a', userId: 'u', action: 'A', resource: 'r', timestamp: new Date(), seq: 0 }
    const e2: Omit<AuditLog, 'chainHash'> = { ...e1, seq: 1 }
    expect(canonicaliseEntry(e1)).not.toBe(canonicaliseEntry(e2))
  })
})

// ---------------------------------------------------------------------------
// computeChainHash
// ---------------------------------------------------------------------------

describe('computeChainHash', () => {
  const entry: Omit<AuditLog, 'chainHash'> = {
    id: 'test-id',
    userId: 'user-1',
    action: 'CREATE_ATTESTATION',
    resource: 'attestation',
    timestamp: new Date('2026-01-01T00:00:00.000Z'),
    seq: 0,
  }

  it('is deterministic for the same inputs', () => {
    const h1 = computeChainHash(entry, GENESIS_SENTINEL)
    const h2 = computeChainHash(entry, GENESIS_SENTINEL)
    expect(h1).toBe(h2)
  })

  it('changes when prevHash changes', () => {
    const h1 = computeChainHash(entry, GENESIS_SENTINEL)
    const h2 = computeChainHash(entry, 'a'.repeat(64))
    expect(h1).not.toBe(h2)
  })

  it('changes when entry data changes', () => {
    const h1 = computeChainHash(entry, GENESIS_SENTINEL)
    const h2 = computeChainHash({ ...entry, action: 'DELETE_USER' }, GENESIS_SENTINEL)
    expect(h1).not.toBe(h2)
  })

  it('returns a 64-char hex string (SHA-256)', () => {
    const h = computeChainHash(entry, GENESIS_SENTINEL)
    expect(h).toMatch(/^[0-9a-f]{64}$/)
  })

  it('produces different hashes with different AUDIT_CHAIN_SECRET', () => {
    delete process.env.AUDIT_CHAIN_SECRET
    const h1 = computeChainHash(entry, GENESIS_SENTINEL)

    process.env.AUDIT_CHAIN_SECRET = 'completely-different-secret-key-32-chars!!'
    const h2 = computeChainHash(entry, GENESIS_SENTINEL)

    expect(h1).not.toBe(h2)
  })
})

// ---------------------------------------------------------------------------
// createAuditLog – chain wiring
// ---------------------------------------------------------------------------

describe('createAuditLog – chain wiring', () => {
  it('first entry chains from GENESIS_SENTINEL', async () => {
    const entry = await createAuditLog(logInput())
    const expected = computeChainHash(
      { id: entry.id, userId: entry.userId, action: entry.action, resource: entry.resource, timestamp: entry.timestamp, seq: entry.seq, contentHash: entry.contentHash },
      GENESIS_SENTINEL
    )
    expect(entry.chainHash).toBe(expected)
  })

  it('second entry chains from first entry\'s chainHash', async () => {
    const first  = await createAuditLog(logInput())
    const second = await createAuditLog(logInput({ userId: 'user-2' }))

    const expected = computeChainHash(
      { id: second.id, userId: second.userId, action: second.action, resource: second.resource, timestamp: second.timestamp, seq: second.seq, contentHash: second.contentHash },
      first.chainHash
    )
    expect(second.chainHash).toBe(expected)
  })

  it('assigns ascending seq values', async () => {
    const entries = await insertN(5)
    for (let i = 0; i < entries.length; i++) {
      expect(entries[i].seq).toBe(i)
    }
  })

  it('sets contentHash when content is provided', async () => {
    const entry = await createAuditLog(logInput(), { amount: 100, currency: 'USD' })
    expect(entry.contentHash).toBeTruthy()
    expect(entry.contentHash).toMatch(/^[0-9a-f]{64}$/)
  })

  it('preserves provided contentHash when no content arg given', async () => {
    const entry = await createAuditLog(logInput({ contentHash: 'preset-hash' }))
    expect(entry.contentHash).toBe('preset-hash')
  })
})

// ---------------------------------------------------------------------------
// verifyChain – intact chain
// ---------------------------------------------------------------------------

describe('verifyChain – intact chain', () => {
  it('returns valid=true for an empty log', async () => {
    const result = verifyChain()
    expect(result.valid).toBe(true)
    expect(result.checkedCount).toBe(0)
    expect(result.chainRoot).toBeNull()
    expect(result.brokenAtIndex).toBeNull()
  })

  it('returns valid=true for a single entry', async () => {
    await createAuditLog(logInput())
    const result = verifyChain()
    expect(result.valid).toBe(true)
    expect(result.checkedCount).toBe(1)
    expect(result.chainRoot).toMatch(/^[0-9a-f]{64}$/)
  })

  it('returns valid=true for 10 sequential entries', async () => {
    await insertN(10)
    const result = verifyChain()
    expect(result.valid).toBe(true)
    expect(result.checkedCount).toBe(10)
  })

  it('chainRoot matches getCurrentChainRoot()', async () => {
    await insertN(3)
    const result = verifyChain()
    expect(result.chainRoot).toBe(getCurrentChainRoot())
  })
})

// ---------------------------------------------------------------------------
// verifyChain – tampered entries
// ---------------------------------------------------------------------------

describe('verifyChain – tampered entries', () => {
  it('detects a tampered action field', async () => {
    const entries = await insertN(3)

    // Tamper with the second entry's action field.
    const tampered = entries.map(e => ({ ...e }))
    tampered[1] = { ...tampered[1], action: 'MALICIOUS_ACTION' }

    const result = verifyChain(tampered)
    expect(result.valid).toBe(false)
    expect(result.brokenAtIndex).toBe(1)
    expect(result.brokenAtId).toBe(tampered[1].id)
    expect(result.checkedCount).toBe(1) // verified before the break
  })

  it('detects a tampered userId field', async () => {
    const entries = await insertN(4)
    const tampered = entries.map(e => ({ ...e }))
    tampered[2] = { ...tampered[2], userId: 'attacker' }

    const result = verifyChain(tampered)
    expect(result.valid).toBe(false)
    expect(result.brokenAtIndex).toBe(2)
  })

  it('detects a tampered metadata field', async () => {
    const e = await createAuditLog(logInput({ metadata: { reason: 'original' } }))
    const tampered = [{ ...e, metadata: { reason: 'tampered' } }]

    const result = verifyChain(tampered)
    expect(result.valid).toBe(false)
    expect(result.brokenAtIndex).toBe(0)
  })

  it('detects a tampered chainHash (direct hash alteration)', async () => {
    const entries = await insertN(3)
    const tampered = entries.map(e => ({ ...e }))
    // An attacker tries to substitute a plausible-looking hash.
    tampered[1] = { ...tampered[1], chainHash: 'b'.repeat(64) }

    const result = verifyChain(tampered)
    expect(result.valid).toBe(false)
    expect(result.brokenAtIndex).toBe(1)
  })

  it('detects a deleted entry (gap in seq)', async () => {
    const entries = await insertN(5)
    // Remove entry at index 2.
    const withGap = [...entries.slice(0, 2), ...entries.slice(3)]

    const result = verifyChain(withGap)
    // The entry at position 2 (original seq=3) will not chain correctly
    // because prevHash is the hash of seq=1, not seq=2.
    expect(result.valid).toBe(false)
    expect(result.brokenAtIndex).not.toBeNull()
  })

  it('detects re-ordered entries', async () => {
    const entries = await insertN(4)
    // Swap entries 1 and 2, also swapping their seq so verifyChain sorts them
    // in the swapped order and detects the hash mismatch.
    const reordered = [
      { ...entries[0] },
      { ...entries[2], seq: 1 },   // was seq=2, now occupies position 1
      { ...entries[1], seq: 2 },   // was seq=1, now occupies position 2
      { ...entries[3] },
    ]

    const result = verifyChain(reordered)
    expect(result.valid).toBe(false)
  })

  it('detects a tampered timestamp', async () => {
    const entries = await insertN(2)
    const tampered = entries.map(e => ({ ...e }))
    tampered[0] = { ...tampered[0], timestamp: new Date('2000-01-01T00:00:00.000Z') }

    const result = verifyChain(tampered)
    expect(result.valid).toBe(false)
    expect(result.brokenAtIndex).toBe(0)
  })

  it('breaks cascade: tampering at index 1 means entries 2+ also fail', async () => {
    const entries = await insertN(5)
    const tampered = entries.map(e => ({ ...e }))
    tampered[1] = { ...tampered[1], action: 'TAMPERED' }

    const result = verifyChain(tampered)
    // Break detected at index 1; entries after that are not checked.
    expect(result.brokenAtIndex).toBe(1)
    expect(result.checkedCount).toBe(1)
  })
})

// ---------------------------------------------------------------------------
// getCurrentChainRoot
// ---------------------------------------------------------------------------

describe('getCurrentChainRoot', () => {
  it('returns null for an empty log', () => {
    expect(getCurrentChainRoot()).toBeNull()
  })

  it('returns the chainHash of the last inserted entry', async () => {
    const e1 = await createAuditLog(logInput())
    expect(getCurrentChainRoot()).toBe(e1.chainHash)

    const e2 = await createAuditLog(logInput({ userId: 'user-2' }))
    expect(getCurrentChainRoot()).toBe(e2.chainHash)
    expect(getCurrentChainRoot()).not.toBe(e1.chainHash)
  })

  it('root changes after each insert', async () => {
    const roots = new Set<string>()
    for (let i = 0; i < 5; i++) {
      await createAuditLog(logInput({ userId: `user-${i}` }))
      const root = getCurrentChainRoot()
      expect(root).not.toBeNull()
      roots.add(root!)
    }
    // Every root should be unique.
    expect(roots.size).toBe(5)
  })
})

// ---------------------------------------------------------------------------
// getAllAuditLogs & getAuditLogsByUser – smoke tests
// ---------------------------------------------------------------------------

describe('getAllAuditLogs', () => {
  it('returns entries in reverse-chronological order', async () => {
    await insertN(3)
    const logs = await getAllAuditLogs()
    expect(logs).toHaveLength(3)
    for (let i = 0; i < logs.length - 1; i++) {
      expect(logs[i].timestamp.getTime()).toBeGreaterThanOrEqual(logs[i + 1].timestamp.getTime())
    }
  })

  it('each returned entry has a chainHash', async () => {
    await insertN(3)
    const logs = await getAllAuditLogs()
    logs.forEach(l => {
      expect(l.chainHash).toMatch(/^[0-9a-f]{64}$/)
    })
  })
})

describe('getAuditLogsByUser', () => {
  it('returns only entries for the requested userId', async () => {
    await createAuditLog(logInput({ userId: 'alice' }))
    await createAuditLog(logInput({ userId: 'bob' }))
    await createAuditLog(logInput({ userId: 'alice' }))

    const aliceLogs = await getAuditLogsByUser('alice')
    expect(aliceLogs).toHaveLength(2)
    aliceLogs.forEach(l => expect(l.userId).toBe('alice'))
  })
})

// ---------------------------------------------------------------------------
// queryAuditLogs – smoke tests (pagination and filtering inherited from base)
// ---------------------------------------------------------------------------

describe('queryAuditLogs', () => {
  it('paginates with limit', async () => {
    await insertN(5)
    const result = await queryAuditLogs({ limit: 2 })
    expect(result.data).toHaveLength(2)
    expect(result.hasMore).toBe(true)
    expect(result.nextCursor).toBeTruthy()
  })

  it('filters by actorId', async () => {
    await createAuditLog(logInput({ userId: 'alice' }))
    await createAuditLog(logInput({ userId: 'bob' }))
    const result = await queryAuditLogs({ actorId: 'alice' })
    expect(result.data).toHaveLength(1)
    expect(result.data[0].userId).toBe('alice')
  })
})

// ---------------------------------------------------------------------------
// Concurrent-insert ordering
// ---------------------------------------------------------------------------

describe('concurrent insert ordering', () => {
  it('sequential inserts with same millisecond timestamp produce valid chain', async () => {
    // Freeze time to force the same timestamp on all entries.
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-01-01T00:00:00.000Z'))

    try {
      // Insert 5 entries "at the same time".
      for (let i = 0; i < 5; i++) {
        await createAuditLog(logInput({ userId: `user-${i}` }))
      }

      const result = verifyChain()
      expect(result.valid).toBe(true)
      expect(result.checkedCount).toBe(5)
    } finally {
      vi.useRealTimers()
    }
  })

  it('insertions assign strictly increasing seq values', async () => {
    const entries = await insertN(10)
    const seqs = entries.map(e => e.seq)
    expect(seqs).toEqual([0, 1, 2, 3, 4, 5, 6, 7, 8, 9])
  })
})

// ---------------------------------------------------------------------------
// clearAllAuditLogs resets chain state
// ---------------------------------------------------------------------------

describe('clearAllAuditLogs', () => {
  it('resets the chain so the first entry after clear uses GENESIS_SENTINEL again', async () => {
    await insertN(3)
    clearAllAuditLogs()

    const fresh = await createAuditLog(logInput())
    const expected = computeChainHash(
      { id: fresh.id, userId: fresh.userId, action: fresh.action, resource: fresh.resource, timestamp: fresh.timestamp, seq: fresh.seq, contentHash: fresh.contentHash },
      GENESIS_SENTINEL
    )
    expect(fresh.chainHash).toBe(expected)
    expect(fresh.seq).toBe(0)
  })
})
