/**
 * Regression coverage for the in-memory attestation repository
 * (`src/repositories/attestation.ts`).
 *
 * The behaviour this suite pins down is the explicit failure/empty-result
 * branch inside `attestationRepository.update()`:
 *
 *   const idx = attestationStore.findIndex((a) => a.id === id);
 *   if (idx === -1) return null;
 *
 * `update()` is a *total* function on the miss path: it returns the `null`
 * sentinel — it never throws and never returns `undefined` — and it leaves the
 * backing store untouched. Callers (`revokeAttestation`, the analytics reports,
 * `submitAttestation`) branch on that sentinel, so a silent behaviour change in
 * this branch would only surface far away from the repository. These tests make
 * the contract observable and deterministic.
 *
 * Isolation strategy: the module keeps a module-level `attestationStore`, so
 * every test re-imports the module after `vi.resetModules()` to start from an
 * empty store. Tests that need the historical fixtures opt in explicitly via
 * `seedForTests()`; `reset()` tears them down again. That keeps the assertions
 * order-independent and prevents one test's writes from leaking into the next.
 *
 * @module tests/unit/repositories/attestation
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Attestation } from '../../../src/repositories/attestation.js';

type AttestationRepository = {
  seedForTests(): void;
  reset(): void;
  listByBusiness(businessId: string): Attestation[];
  listByBusinessIds(businessIds: readonly string[]): Attestation[][];
  create(data: Omit<Attestation, 'id' | 'attestedAt'>): Attestation;
  findById(id: string): Attestation | null;
  update(id: string, data: Partial<Attestation>): Attestation | null;
};

// ── Seed facts (src/repositories/attestation.ts) ──────────────────────────────
// biz_1 → att_1 (2025-11-01), att_2 (2025-12-01), att_4 (2025-12-15)
// biz_2 → att_3 (2026-01-05)
// `listByBusiness()` sorts newest-first, so the biz_1 expectation is
// att_4 → att_2 → att_1.
// att_2 and att_4 share period 2025-11: att_2 is revoked and att_4 is its
// active reissue.
const SEEDED_FIRST_ID = 'att_1';
const SEEDED_BUSINESS_ID = 'biz_1';
const SEEDED_BUSINESS_IDS = ['att_4', 'att_2', 'att_1'];
const SEEDED_REISSUE_PERIOD = '2025-11';
const SEEDED_REVOKED_ID = 'att_2';
const SEEDED_REISSUED_ID = 'att_4';
const UNKNOWN_ID = 'att_does_not_exist';
const ORIGINAL_NODE_ENV = process.env.NODE_ENV;

let attestationRepository: AttestationRepository;
let seedForTests: () => void;
let reset: () => void;

beforeEach(async () => {
  vi.resetModules();
  const mod = (await import('../../../src/repositories/attestation.js')) as {
    attestationRepository: AttestationRepository;
    seedForTests: () => void;
    reset: () => void;
  };
  attestationRepository = mod.attestationRepository;
  seedForTests = mod.seedForTests;
  reset = mod.reset;
});

afterEach(() => {
  reset?.();
  process.env.NODE_ENV = ORIGINAL_NODE_ENV;
  vi.restoreAllMocks();
});

// ─────────────────────────────────────────────────────────────────────────────
// Default state — no fixtures may be shipped with the module
// ─────────────────────────────────────────────────────────────────────────────

describe('attestationRepository — default state', () => {
  it('starts with an empty store, so fixture businesses return no rows', () => {
    expect(attestationRepository.listByBusiness(SEEDED_BUSINESS_ID)).toEqual([]);
    expect(attestationRepository.listByBusiness('biz_2')).toEqual([]);
  });

  it('does not expose any historical fixture ids before seeding', () => {
    for (const id of ['att_1', 'att_2', 'att_3', 'att_4']) {
      expect(attestationRepository.findById(id)).toBeNull();
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Test seeding helpers
// ─────────────────────────────────────────────────────────────────────────────

describe('attestationRepository — seedForTests / reset helpers', () => {
  it('seedForTests populates every expected fixture', () => {
    seedForTests();

    expect(attestationRepository.listByBusiness(SEEDED_BUSINESS_ID).map((a) => a.id)).toEqual(
      SEEDED_BUSINESS_IDS,
    );
    expect(attestationRepository.listByBusiness('biz_2').map((a) => a.id)).toEqual(['att_3']);
    expect(attestationRepository.findById(SEEDED_FIRST_ID)).toMatchObject({
      businessId: SEEDED_BUSINESS_ID,
      period: '2025-10',
      status: 'active',
    });
  });

  it('models the duplicate 2025-11 fixture as a revoked-then-reissued pair', () => {
    seedForTests();

    const novemberRows = attestationRepository
      .listByBusiness(SEEDED_BUSINESS_ID)
      .filter((a) => a.period === SEEDED_REISSUE_PERIOD);

    expect(novemberRows).toHaveLength(2);
    expect(novemberRows.filter((a) => a.status === 'revoked')).toHaveLength(1);
    expect(novemberRows.filter((a) => a.status === 'active')).toHaveLength(1);
    expect(attestationRepository.findById(SEEDED_REVOKED_ID)).toMatchObject({
      status: 'revoked',
      revokedAt: expect.any(String),
      revokeReason: expect.any(String),
    });
    expect(attestationRepository.findById(SEEDED_REISSUED_ID)).toMatchObject({
      status: 'active',
    });
  });

  it('is idempotent: repeated seeding does not duplicate rows', () => {
    seedForTests();
    seedForTests();

    expect(attestationRepository.listByBusiness(SEEDED_BUSINESS_ID)).toHaveLength(
      SEEDED_BUSINESS_IDS.length,
    );
  });

  it('reset clears every fixture row', () => {
    seedForTests();
    expect(attestationRepository.listByBusiness(SEEDED_BUSINESS_ID)).not.toEqual([]);

    reset();

    expect(attestationRepository.listByBusiness(SEEDED_BUSINESS_ID)).toEqual([]);
    expect(attestationRepository.listByBusiness('biz_2')).toEqual([]);
    expect(attestationRepository.findById(SEEDED_FIRST_ID)).toBeNull();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Production guard
// ─────────────────────────────────────────────────────────────────────────────

describe('attestationRepository — production guard', () => {
  it('starts empty and warns when the in-memory repository is used in production', () => {
    process.env.NODE_ENV = 'production';
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    expect(attestationRepository.listByBusiness(SEEDED_BUSINESS_ID)).toEqual([]);
    expect(attestationRepository.listByBusiness('biz_2')).toEqual([]);
    expect(attestationRepository.findById(SEEDED_FIRST_ID)).toBeNull();

    expect(warnSpy).toHaveBeenCalled();
    const warnings = warnSpy.mock.calls.map((call) => call.join(' ')).join('\n');
    expect(warnings).toContain('In-memory attestation repository');
    expect(warnings).toContain('production');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Failure path — the branch named in the issue (src/repositories/attestation.ts:70)
// ─────────────────────────────────────────────────────────────────────────────

describe('attestationRepository.update — failure path (id not found)', () => {
  beforeEach(() => {
    seedForTests();
  });

  it('returns null — never undefined — for an unknown id', () => {
    const result = attestationRepository.update(UNKNOWN_ID, { status: 'revoked' });

    expect(result).toBeNull();
    expect(result).not.toBeUndefined();
  });

  it('resolves the miss without throwing', () => {
    expect(() =>
      attestationRepository.update(UNKNOWN_ID, { status: 'revoked' }),
    ).not.toThrow();
  });

  it('is deterministic across repeated misses', () => {
    const first = attestationRepository.update(UNKNOWN_ID, { status: 'revoked' });
    const second = attestationRepository.update(UNKNOWN_ID, { status: 'revoked' });
    const third = attestationRepository.update(UNKNOWN_ID, {});

    expect(first).toBeNull();
    expect(second).toBeNull();
    expect(third).toBeNull();
  });

  it('isolates the miss — the seeded record stays untouched', () => {
    const before = attestationRepository.findById(SEEDED_FIRST_ID);
    expect(before).not.toBeNull();
    const snapshot = { ...before! };

    const result = attestationRepository.update(UNKNOWN_ID, {
      status: 'revoked',
      revokeReason: 'should never be applied',
    });

    expect(result).toBeNull();
    expect(attestationRepository.findById(SEEDED_FIRST_ID)).toEqual(snapshot);
    expect(attestationRepository.findById(SEEDED_FIRST_ID)?.status).toBe('active');
  });

  it('does not grow or shrink the store on a miss', () => {
    const before = attestationRepository.listByBusiness(SEEDED_BUSINESS_ID);
    expect(before).toHaveLength(SEEDED_BUSINESS_IDS.length);

    attestationRepository.update(UNKNOWN_ID, { status: 'revoked' });

    expect(
      attestationRepository.listByBusiness(SEEDED_BUSINESS_ID).map((a) => a.id),
    ).toEqual(SEEDED_BUSINESS_IDS);
  });

  // Boundary inputs must be treated as plain misses — no trimming, no case
  // folding, no prefix/substring matching, no crash on pathological ids.
  it.each<[string, string]>([
    ['empty string', ''],
    ['whitespace only', '   '],
    ['unknown prefix of a seeded id', 'att_'],
    ['superset of a seeded id', 'att_1_extra'],
    ['padded seeded id', ' att_1 '],
    ['upper-cased seeded id', 'ATT_1'],
    ['very long id', `att_${'x'.repeat(4096)}`],
    ['non-ascii id', 'att_💥'],
  ])('returns null for boundary id (%s)', (_label, id) => {
    const result = attestationRepository.update(id, { status: 'revoked' });

    expect(result).toBeNull();
    // …and the near-miss never leaked into the seeded record.
    expect(attestationRepository.findById(SEEDED_FIRST_ID)?.status).toBe('active');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Neighbouring normal path — the success branch of update()
// ─────────────────────────────────────────────────────────────────────────────

describe('attestationRepository.update — neighbouring success path', () => {
  beforeEach(() => {
    seedForTests();
  });

  it('returns the merged record for a known id', () => {
    const updated = attestationRepository.update(SEEDED_FIRST_ID, { status: 'revoked' });

    expect(updated).not.toBeNull();
    expect(updated).toMatchObject({
      id: SEEDED_FIRST_ID,
      businessId: SEEDED_BUSINESS_ID,
      period: '2025-10',
      attestedAt: '2025-11-01T12:00:00.000Z',
      status: 'revoked',
    });
  });

  it('persists the patch so later reads observe it', () => {
    const updated = attestationRepository.update(SEEDED_FIRST_ID, {
      status: 'revoked',
      revokedAt: '2026-02-01T00:00:00.000Z',
      revokeReason: 'audit failed',
    });

    expect(updated).not.toBeNull();
    expect(attestationRepository.findById(SEEDED_FIRST_ID)).toEqual(updated);
    expect(attestationRepository.findById(SEEDED_FIRST_ID)).toMatchObject({
      status: 'revoked',
      revokedAt: '2026-02-01T00:00:00.000Z',
      revokeReason: 'audit failed',
    });
  });

  it('leaves fields that were not part of the patch intact', () => {
    const updated = attestationRepository.update(SEEDED_FIRST_ID, {
      revokeReason: 'reason only',
    });

    expect(updated).toMatchObject({
      id: SEEDED_FIRST_ID,
      businessId: SEEDED_BUSINESS_ID,
      period: '2025-10',
      attestedAt: '2025-11-01T12:00:00.000Z',
      status: 'active',
      revokeReason: 'reason only',
    });
  });

  it('treats an empty patch as a no-op that still returns the record', () => {
    const before = { ...attestationRepository.findById(SEEDED_FIRST_ID)! };

    const updated = attestationRepository.update(SEEDED_FIRST_ID, {});

    expect(updated).toEqual(before);
    expect(attestationRepository.findById(SEEDED_FIRST_ID)).toEqual(before);
  });

  it('layers successive patches instead of replacing the record', () => {
    attestationRepository.update(SEEDED_FIRST_ID, { status: 'revoked' });
    const second = attestationRepository.update(SEEDED_FIRST_ID, {
      revokeReason: 'second patch',
    });

    expect(second).toMatchObject({
      id: SEEDED_FIRST_ID,
      businessId: SEEDED_BUSINESS_ID,
      status: 'revoked',
      revokeReason: 'second patch',
    });
  });

  it('updates a record created at runtime (create → update round trip)', () => {
    const created = attestationRepository.create({
      businessId: SEEDED_BUSINESS_ID,
      period: '2026-05',
      status: 'active',
    });

    expect(created.id).toMatch(/^att_[0-9a-f-]{36}$/);
    expect(new Date(created.attestedAt).toISOString()).toBe(created.attestedAt);

    const updated = attestationRepository.update(created.id, { status: 'revoked' });

    expect(updated).toEqual({ ...created, status: 'revoked' });
    expect(attestationRepository.findById(created.id)).toEqual({
      ...created,
      status: 'revoked',
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Sibling failure / empty-result contracts of the same module
// ─────────────────────────────────────────────────────────────────────────────

describe('attestationRepository — sibling not-found and empty-result contracts', () => {
  beforeEach(() => {
    seedForTests();
  });

  it('findById returns null (not undefined) for an unknown id', () => {
    expect(attestationRepository.findById(UNKNOWN_ID)).toBeNull();
    expect(attestationRepository.findById('')).toBeNull();
  });

  it('listByBusiness returns an empty array for a business with no attestations', () => {
    const result = attestationRepository.listByBusiness('biz_unknown');

    expect(result).toEqual([]);
    expect(Array.isArray(result)).toBe(true);
  });

  it('listByBusiness returns records newest-first', () => {
    expect(attestationRepository.listByBusiness(SEEDED_BUSINESS_ID).map((a) => a.id)).toEqual(
      SEEDED_BUSINESS_IDS,
    );
  });

  it('listByBusiness hands back a detached array, so caller mutation cannot corrupt the store', () => {
    const result = attestationRepository.listByBusiness(SEEDED_BUSINESS_ID);
    result.pop();

    expect(attestationRepository.listByBusiness(SEEDED_BUSINESS_ID)).toHaveLength(
      SEEDED_BUSINESS_IDS.length,
    );
  });

  it('listByBusinessIds preserves order, duplicates and empty input', () => {
    expect(attestationRepository.listByBusinessIds([])).toEqual([]);

    const grouped = attestationRepository.listByBusinessIds(['biz_2', 'biz_unknown', 'biz_2']);

    expect(grouped).toHaveLength(3);
    expect(grouped[0].map((a) => a.id)).toEqual(['att_3']);
    expect(grouped[1]).toEqual([]);
    expect(grouped[2].map((a) => a.id)).toEqual(['att_3']);
  });

  it('keeps the store intact when a lookup misses', () => {
    const missing = attestationRepository.findById(UNKNOWN_ID);
    expect(missing).toBeNull();

    // The miss sentinel stays null and never becomes a mutable store entry.
    expect(attestationRepository.findById(UNKNOWN_ID)).toBeNull();
    expect(attestationRepository.listByBusiness(SEEDED_BUSINESS_ID)).toHaveLength(
      SEEDED_BUSINESS_IDS.length,
    );
  });
});
