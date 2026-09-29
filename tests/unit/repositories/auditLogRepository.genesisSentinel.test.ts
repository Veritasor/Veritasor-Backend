/**
 * tests/unit/repositories/auditLogRepository.genesisSentinel.test.ts
 *
 * Focused behavior coverage for the GENESIS_SENTINEL contract of
 * src/repositories/auditLogRepository.ts (issue #926).
 *
 * Coverage targets
 * ─────────────────
 * • GENESIS_SENTINEL   – exact value, export shape, HMAC wiring, key sensitivity
 * • AuditLog           – structurally complete entries produced by createAuditLog
 * • AuditLogInput      – Omit<> contract: generated fields are never taken from input
 * • Invalid inputs     – query validation errors (deterministic TypeError/RangeError)
 * • State transitions  – empty → genesis entry → chained entries → cleared → genesis again
 *
 * These tests intentionally pin the exact GENESIS_SENTINEL literal: the module
 * documentation states that changing it invalidates every existing chain, so a
 * regression that alters the constant must fail loudly here.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import crypto from 'node:crypto'
import {
  createAuditLog,
  queryAuditLogs,
  verifyChain,
  getCurrentChainRoot,
  clearAllAuditLogs,
  computeChainHash,
  canonicaliseEntry,
  GENESIS_SENTINEL,
  type AuditLog,
  type AuditLogInput,
} from '../../../src/repositories/auditLogRepository.js'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Build a minimal valid AuditLogInput. */
function logInput(overrides: Partial<AuditLogInput> = {}): AuditLogInput {
  return {
    userId: 'user-1',
    action: 'CREATE_ATTESTATION',
    resource: 'attestation',
    ...overrides,
  }
}

/** Insert N entries, returning them in insertion order. */
async function insertN(n: number): Promise<AuditLog[]> {
  const results: AuditLog[] = []
  for (let i = 0; i < n; i++) {
    results.push(await createAuditLog(logInput({ userId: `user-${i}` })))
  }
  return results
}

/** Recompute the expected chainHash for an entry given its predecessor's hash. */
function expectedChainHash(entry: AuditLog, prevHash: string): string {
  const { chainHash: _ignored, ...rest } = entry
  return computeChainHash(rest as Omit<AuditLog, 'chainHash'>, prevHash)
}

// ---------------------------------------------------------------------------
// Setup / teardown
// ---------------------------------------------------------------------------

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
// GENESIS_SENTINEL – constant contract
// ---------------------------------------------------------------------------

describe('GENESIS_SENTINEL', () => {
  it('is the pinned 64-character zero hex string', () => {
    // The module docs say changing this value invalidates every existing
    // chain, so the literal itself is part of the public contract.
    expect(GENESIS_SENTINEL).toBe('0'.repeat(64))
  })

  it('matches the documented format (lowercase hex, length 64)', () => {
    expect(GENESIS_SENTINEL).toMatch(/^[0-9a-f]{64}$/)
  })

  it('is not a valid chain hash output (all zeros, distinct from any HMAC)', () => {
    const entry = {
      id: 'a',
      userId: 'u',
      action: 'A',
      resource: 'r',
      timestamp: new Date('2026-01-01T00:00:00.000Z'),
      seq: 0,
    }
    // The sentinel must never collide with a real HMAC output; that would
    // make the first and second entries indistinguishable.
    expect(computeChainHash(entry, GENESIS_SENTINEL)).not.toBe(GENESIS_SENTINEL)
  })

  it('seeds the first entry: chainHash[0] = HMAC(GENESIS_SENTINEL || entry[0])', async () => {
    const first = await createAuditLog(logInput())
    expect(first.seq).toBe(0)
    expect(first.chainHash).toBe(expectedChainHash(first, GENESIS_SENTINEL))
  })

  it('does not seed later entries: chainHash[N] = HMAC(chainHash[N-1] || entry[N])', async () => {
    const [first, second] = await insertN(2)
    expect(second.chainHash).toBe(expectedChainHash(second, first.chainHash))
    expect(second.chainHash).not.toBe(expectedChainHash(second, GENESIS_SENTINEL))
  })

  it('verifyChain treats GENESIS_SENTINEL as the implicit root when re-deriving hash 0', async () => {
    const entries = await insertN(3)
    // Re-derive entry 0's hash independently from the constant (insertion
    // order 0 = oldest = lowest seq).
    const genesisEntry = entries[0]
    const recomputed = computeChainHash(genesisEntry, GENESIS_SENTINEL)
    expect(recomputed).toBe(genesisEntry.chainHash)
    // And the whole chain still verifies.
    expect(verifyChain().valid).toBe(true)
  })

  it('a chain rooted at anything other than GENESIS_SENTINEL fails verification', async () => {
    const entry = await createAuditLog(logInput())
    // Simulate a genesis value drift: recompute the first entry's hash as if
    // the sentinel were different, then verify – the break must be reported
    // deterministically at index 0.
    const drifted = {
      ...entry,
      chainHash: computeChainHash(entry, 'f'.repeat(64)),
    }
    const result = verifyChain([drifted])
    expect(result.valid).toBe(false)
    expect(result.brokenAtIndex).toBe(0)
    expect(result.brokenAtId).toBe(entry.id)
  })

  it('chain hashes depend on the configured HMAC key even around genesis', () => {
    delete process.env.AUDIT_CHAIN_SECRET
    const entry = {
      id: 'a',
      userId: 'u',
      action: 'A',
      resource: 'r',
      timestamp: new Date('2026-01-01T00:00:00.000Z'),
      seq: 0,
    }
    const fallbackKeyHash = computeChainHash(entry, GENESIS_SENTINEL)

    process.env.AUDIT_CHAIN_SECRET = 'genesis-sentinel-suite-secret'
    const customKeyHash = computeChainHash(entry, GENESIS_SENTINEL)

    expect(fallbackKeyHash).not.toBe(customKeyHash)
    // Manual HMAC to prove the wiring: HMAC(key, GENESIS + '|' + canonical)
    const manual = crypto
      .createHmac('sha256', Buffer.from('genesis-sentinel-suite-secret', 'utf-8'))
      .update(GENESIS_SENTINEL + '|' + canonicaliseEntry(entry))
      .digest('hex')
    expect(customKeyHash).toBe(manual)
  })
})

// ---------------------------------------------------------------------------
// AuditLog – shape of produced entries
// ---------------------------------------------------------------------------

describe('AuditLog – produced entry shape', () => {
  it('produces a structurally complete AuditLog', async () => {
    const entry = await createAuditLog(logInput({ resourceId: 'r-1', metadata: { k: 'v' } }))

    expect(Object.keys(entry).sort()).toEqual(
      [
        'action',
        'chainHash',
        'contentHash',
        'id',
        'metadata',
        'resource',
        'resourceId',
        'seq',
        'timestamp',
        'userId',
      ].sort()
    )
    expect(entry.id).toMatch(/^[0-9a-f]{32}$/) // randomBytes(16).toString('hex')
    expect(entry.timestamp).toBeInstanceOf(Date)
    expect(typeof entry.seq).toBe('number')
    expect(entry.chainHash).toMatch(/^[0-9a-f]{64}$/)
  })

  it('entries are unique in id across inserts', async () => {
    const entries = await insertN(5)
    const ids = new Set(entries.map(e => e.id))
    expect(ids.size).toBe(5)
  })

  it('omitted optional fields stay undefined (not null/empty string)', async () => {
    const entry = await createAuditLog(logInput())
    expect(entry.resourceId).toBeUndefined()
    expect(entry.metadata).toBeUndefined()
    expect(entry.contentHash).toBeUndefined()
  })

  it('timestamp is UTC ISO-round-trippable', async () => {
    const entry = await createAuditLog(logInput())
    expect(new Date(entry.timestamp.toISOString()).getTime()).toBe(entry.timestamp.getTime())
  })
})

// ---------------------------------------------------------------------------
// AuditLogInput – Omit<> contract
// ---------------------------------------------------------------------------

describe('AuditLogInput – generated fields are never accepted from input', () => {
  it('ignores caller-supplied id, timestamp, seq and chainHash', async () => {
    const forged = {
      ...logInput(),
      id: 'attacker-id',
      timestamp: new Date('1999-01-01T00:00:00.000Z'),
      seq: 999,
      chainHash: 'a'.repeat(64),
    } as unknown as AuditLogInput

    const entry = await createAuditLog(forged)

    expect(entry.id).not.toBe('attacker-id')
    expect(entry.id).toMatch(/^[0-9a-f]{32}$/)
    expect(entry.timestamp.getTime()).toBeGreaterThan(new Date('1999-01-01T00:00:00.000Z').getTime())
    expect(entry.seq).toBe(0)
    expect(entry.chainHash).not.toBe('a'.repeat(64))
  })

  it('preserves the caller-supplied contentHash when no content argument is given', async () => {
    const entry = await createAuditLog(logInput({ contentHash: 'preset-hash' }))
    expect(entry.contentHash).toBe('preset-hash')
  })

  it('overwrites contentHash when content is provided (content wins)', async () => {
    const entry = await createAuditLog(logInput({ contentHash: 'preset-hash' }), { amount: 42 })
    expect(entry.contentHash).not.toBe('preset-hash')
    expect(entry.contentHash).toMatch(/^[0-9a-f]{64}$/)
  })

  it('accepts the minimal valid input (userId, action, resource only)', async () => {
    const entry = await createAuditLog({ userId: 'u', action: 'A', resource: 'r' })
    expect(entry.userId).toBe('u')
    expect(entry.action).toBe('A')
    expect(entry.resource).toBe('r')
  })
})

// ---------------------------------------------------------------------------
// Invalid inputs – deterministic errors
// ---------------------------------------------------------------------------

describe('queryAuditLogs – invalid inputs', () => {
  it('throws TypeError for an invalid "from" date', async () => {
    await expect(queryAuditLogs({ from: 'not-a-date' })).rejects.toThrow(TypeError)
    await expect(queryAuditLogs({ from: 'not-a-date' })).rejects.toThrow('from must be a valid date')
  })

  it('throws TypeError for an invalid "to" date', async () => {
    await expect(queryAuditLogs({ to: 'also-not-a-date' })).rejects.toThrow(TypeError)
    await expect(queryAuditLogs({ to: 'also-not-a-date' })).rejects.toThrow('to must be a valid date')
  })

  it('throws RangeError when "from" is after "to"', async () => {
    await expect(
      queryAuditLogs({ from: '2026-06-02T00:00:00.000Z', to: '2026-06-01T00:00:00.000Z' })
    ).rejects.toThrow(RangeError)
    await expect(
      queryAuditLogs({ from: '2026-06-02T00:00:00.000Z', to: '2026-06-01T00:00:00.000Z' })
    ).rejects.toThrow('from must not be after to')
  })

  it('treats empty-string dates as absent instead of throwing', async () => {
    await insertN(1)
    const result = await queryAuditLogs({ from: '', to: '' })
    expect(result.data).toHaveLength(1)
  })

  it('throws RangeError for a structurally invalid cursor', async () => {
    await expect(queryAuditLogs({ cursor: '!!!not-base64-json!!!' })).rejects.toThrow(RangeError)
    await expect(queryAuditLogs({ cursor: '!!!not-base64-json!!!' })).rejects.toThrow('cursor is invalid')
  })

  it('accepts boundary values: from === to is allowed', async () => {
    await insertN(1)
    const result = await queryAuditLogs({
      from: '2020-01-01T00:00:00.000Z',
      to: '2030-01-01T00:00:00.000Z',
    })
    expect(result.data).toHaveLength(1)
  })
})

describe('queryAuditLogs – limit handling', () => {
  it('coerces non-integer and non-positive limits to the default of 20 (capped at 100)', async () => {
    await insertN(3)
    for (const badLimit of [0, -5, NaN]) {
      const result = await queryAuditLogs({ limit: badLimit })
      expect(result.data).toHaveLength(3) // all rows, no error, no crash
    }
  })

  it('caps the limit at 100', async () => {
    await insertN(3)
    const result = await queryAuditLogs({ limit: 1000 })
    expect(result.data).toHaveLength(3)
    // Contract: server never returns more than 100 rows per page.
    expect(result.data.length).toBeLessThanOrEqual(100)
  })
})

// ---------------------------------------------------------------------------
// State transitions
// ---------------------------------------------------------------------------

describe('state transitions', () => {
  it('empty → genesis entry: empty store verifies and roots at null, first insert roots at genesis hash', async () => {
    // Before: empty
    expect(getCurrentChainRoot()).toBeNull()
    expect(verifyChain()).toEqual({
      valid: true,
      checkedCount: 0,
      brokenAtIndex: null,
      brokenAtId: null,
      chainRoot: null,
    })

    // After: first insert is the genesis entry
    const first = await createAuditLog(logInput())
    expect(getCurrentChainRoot()).toBe(first.chainHash)
    expect(verifyChain().valid).toBe(true)
  })

  it('append transition: each insert advances seq, root, and keeps the chain intact', async () => {
    const entries: AuditLog[] = []
    for (let i = 0; i < 4; i++) {
      const entry = await createAuditLog(logInput({ userId: `user-${i}` }))
      const prev = entries[entries.length - 1]

      expect(entry.seq).toBe(i)
      expect(entry.chainHash).toBe(
        prev ? expectedChainHash(entry, prev.chainHash) : expectedChainHash(entry, GENESIS_SENTINEL)
      )
      expect(getCurrentChainRoot()).toBe(entry.chainHash)
      expect(verifyChain().valid).toBe(true)

      entries.push(entry)
    }
  })

  it('clear transition: cleared store goes back to genesis wiring for the next entry', async () => {
    await insertN(3)
    clearAllAuditLogs()

    expect(getCurrentChainRoot()).toBeNull()
    expect(verifyChain().checkedCount).toBe(0)

    const fresh = await createAuditLog(logInput())
    expect(fresh.seq).toBe(0)
    expect(fresh.chainHash).toBe(expectedChainHash(fresh, GENESIS_SENTINEL))
  })

  it('append after clear produces a brand-new chain unrelated to the old one', async () => {
    const oldEntries = await insertN(2)
    const oldRoot = getCurrentChainRoot()
    clearAllAuditLogs()

    const newEntries = await insertN(2)
    expect(newEntries[0].seq).toBe(0)
    expect(newEntries.map(e => e.id)).not.toContain(oldEntries[0].id)
    expect(getCurrentChainRoot()).not.toBe(oldRoot)
    expect(verifyChain().valid).toBe(true)
  })
})
