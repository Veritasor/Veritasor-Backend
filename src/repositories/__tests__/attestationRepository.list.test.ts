/**
 * Unit tests for attestationRepository.list() – period and status filters.
 *
 * Uses a minimal mock DbClient to capture SQL + params without a real DB.
 *
 * Covers (from issue #1224 acceptance criteria):
 *  - Repository unit test checks the SQL parameters for the period filter.
 *  - Repository unit test checks the SQL parameters for the status filter.
 *  - COALESCE(status, 'submitted') is used for the status clause.
 *  - Both filters can be combined with businessId.
 *  - Both count query and data query receive the same filter params so totals
 *    are always consistent.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ---------------------------------------------------------------------------
// Stub soroban service so attestationRepository can be imported without a real
// network or environment variable.
// ---------------------------------------------------------------------------
vi.mock('../../services/soroban/getAttestation.js', () => ({
  getAttestation: vi.fn(),
}));
vi.mock('../../utils/logger.js', () => ({
  logger: { warn: vi.fn(), info: vi.fn(), error: vi.fn() },
}));

import { list } from '../../repositories/attestationRepository.js';

// ---------------------------------------------------------------------------
// Minimal DbClient mock
// ---------------------------------------------------------------------------

type CapturedCall = { sql: string; params: any[] | undefined };

function makeClient(countValue = '0', dataRows: any[] = []) {
  const calls: CapturedCall[] = [];

  const client = {
    calls,
    query: vi.fn(async (sql: string, params?: any[]) => {
      calls.push({ sql: sql.replace(/\s+/g, ' ').trim(), params });
      if (sql.toUpperCase().startsWith('SET')) {
        return { rows: [] };
      }
      if (sql.includes('COUNT(*)')) {
        return { rows: [{ count: countValue }] };
      }
      return { rows: dataRows };
    }),
  };

  return client;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function normalise(sql: string) {
  return sql.replace(/\s+/g, ' ').trim().toLowerCase();
}

/** Pick the data query (SELECT … not COUNT), skipping SET LOCAL calls. */
function getDataCall(calls: CapturedCall[]): CapturedCall | undefined {
  return calls.find(
    c => !c.sql.toUpperCase().startsWith('SET') && !c.sql.includes('COUNT'),
  );
}

/** Pick the count query (SELECT COUNT), skipping SET LOCAL calls. */
function getCountCall(calls: CapturedCall[]): CapturedCall | undefined {
  return calls.find(
    c => !c.sql.toUpperCase().startsWith('SET') && c.sql.includes('COUNT'),
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('attestationRepository.list()', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // ── businessId only (baseline) ────────────────────────────────────────────

  describe('businessId filter only', () => {
    it('passes businessId as $1, limit as $2, offset as $3 to the data query', async () => {
      const client = makeClient('2', []);
      await list(client as any, { businessId: 'biz-1' }, { limit: 10, offset: 0 });

      const dc = getDataCall(client.calls);
      expect(dc).toBeDefined();
      expect(dc!.params).toEqual(['biz-1', 10, 0]);
    });

    it('passes only businessId to the count query', async () => {
      const client = makeClient('5', []);
      await list(client as any, { businessId: 'biz-1' }, { limit: 10, offset: 0 });

      const cc = getCountCall(client.calls);
      expect(cc).toBeDefined();
      expect(cc!.params).toEqual(['biz-1']);
    });

    it('returns total from count result, not items length', async () => {
      const client = makeClient('42', []);
      const result = await list(client as any, { businessId: 'biz-1' }, { limit: 10, offset: 0 });
      expect(result.total).toBe(42);
    });
  });

  // ── period filter ─────────────────────────────────────────────────────────

  describe('period filter', () => {
    it('includes period = $2 clause in the data query', async () => {
      const client = makeClient('3', []);
      await list(client as any, { businessId: 'biz-1', period: '2026-01' }, { limit: 10, offset: 0 });

      const dc = getDataCall(client.calls);
      expect(dc).toBeDefined();
      expect(normalise(dc!.sql)).toContain('period = $2');
      expect(dc!.params).toContain('2026-01');
    });

    it('includes period = $2 clause in the count query', async () => {
      const client = makeClient('3', []);
      await list(client as any, { businessId: 'biz-1', period: '2026-01' }, { limit: 10, offset: 0 });

      const cc = getCountCall(client.calls);
      expect(cc).toBeDefined();
      expect(normalise(cc!.sql)).toContain('period = $2');
      expect(cc!.params).toContain('2026-01');
    });

    it('places period param after businessId ($1)', async () => {
      const client = makeClient('3', []);
      await list(client as any, { businessId: 'biz-1', period: '2026-01' }, { limit: 10, offset: 0 });

      const dc = getDataCall(client.calls);
      // params: [businessId, period, limit, offset]
      expect(dc!.params).toEqual(['biz-1', '2026-01', 10, 0]);
    });

    it('count params include businessId and period', async () => {
      const client = makeClient('3', []);
      await list(client as any, { businessId: 'biz-1', period: '2026-01' }, { limit: 10, offset: 0 });

      const cc = getCountCall(client.calls);
      expect(cc!.params).toEqual(['biz-1', '2026-01']);
    });
  });

  // ── status filter ─────────────────────────────────────────────────────────

  describe('status filter', () => {
    it('uses COALESCE(status, \'submitted\') in the data query', async () => {
      const client = makeClient('5', []);
      await list(client as any, { businessId: 'biz-1', status: 'submitted' }, { limit: 10, offset: 0 });

      const dc = getDataCall(client.calls);
      expect(dc).toBeDefined();
      expect(normalise(dc!.sql)).toContain("coalesce(status, 'submitted')");
    });

    it('uses COALESCE(status, \'submitted\') in the count query', async () => {
      const client = makeClient('5', []);
      await list(client as any, { businessId: 'biz-1', status: 'submitted' }, { limit: 10, offset: 0 });

      const cc = getCountCall(client.calls);
      expect(cc).toBeDefined();
      expect(normalise(cc!.sql)).toContain("coalesce(status, 'submitted')");
    });

    it('passes the status value as a param for status=revoked', async () => {
      const client = makeClient('5', []);
      await list(client as any, { businessId: 'biz-1', status: 'revoked' }, { limit: 10, offset: 0 });

      const dc = getDataCall(client.calls);
      expect(dc!.params).toContain('revoked');
    });

    it('places status param after businessId ($1)', async () => {
      const client = makeClient('5', []);
      await list(client as any, { businessId: 'biz-1', status: 'revoked' }, { limit: 10, offset: 0 });

      const dc = getDataCall(client.calls);
      // params: [businessId, status, limit, offset]
      expect(dc!.params).toEqual(['biz-1', 'revoked', 10, 0]);
    });

    it('count params include businessId and status', async () => {
      const client = makeClient('5', []);
      await list(client as any, { businessId: 'biz-1', status: 'revoked' }, { limit: 10, offset: 0 });

      const cc = getCountCall(client.calls);
      expect(cc!.params).toEqual(['biz-1', 'revoked']);
    });
  });

  // ── period + status combined ───────────────────────────────────────────────

  describe('period + status combined', () => {
    it('includes both period and status clauses in the data query', async () => {
      const client = makeClient('2', []);
      await list(
        client as any,
        { businessId: 'biz-1', period: '2026-01', status: 'revoked' },
        { limit: 10, offset: 0 },
      );

      const dc = getDataCall(client.calls);
      expect(dc).toBeDefined();
      const sql = normalise(dc!.sql);
      expect(sql).toContain('period = $2');
      expect(sql).toContain("coalesce(status, 'submitted') = $3");
    });

    it('params order is [businessId, period, status, limit, offset]', async () => {
      const client = makeClient('2', []);
      await list(
        client as any,
        { businessId: 'biz-1', period: '2026-01', status: 'revoked' },
        { limit: 10, offset: 0 },
      );

      const dc = getDataCall(client.calls);
      expect(dc!.params).toEqual(['biz-1', '2026-01', 'revoked', 10, 0]);
    });

    it('count params order is [businessId, period, status]', async () => {
      const client = makeClient('2', []);
      await list(
        client as any,
        { businessId: 'biz-1', period: '2026-01', status: 'revoked' },
        { limit: 10, offset: 0 },
      );

      const cc = getCountCall(client.calls);
      expect(cc!.params).toEqual(['biz-1', '2026-01', 'revoked']);
    });

    it('total reflects count query, not items length', async () => {
      const client = makeClient('25', []);
      const result = await list(
        client as any,
        { businessId: 'biz-1', period: '2026-01', status: 'revoked' },
        { limit: 10, offset: 0 },
      );
      expect(result.total).toBe(25);
    });
  });

  // ── acceptance criterion from issue ───────────────────────────────────────

  describe('issue #1224 acceptance criterion', () => {
    it('30 total attestations, 5 revoked: status=revoked → total=5 from count query', async () => {
      /**
       * Simulates: 30 attestations in the DB, 5 of them revoked.
       * The count query (with status filter) returns 5.
       * The data query returns 5 rows.
       * list() must return total=5 — not 30.
       */
      const fiveRevokedRows = Array.from({ length: 5 }).map((_, i) => ({
        id: `att-${i}`,
        business_id: 'biz-1',
        period: '2026-01',
        merkle_root: '0xabc',
        tx_hash: '0xdef',
        status: 'revoked',
        version: 1,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      }));

      const client = makeClient('5', fiveRevokedRows);
      const result = await list(
        client as any,
        { businessId: 'biz-1', status: 'revoked' },
        { limit: 10, offset: 0 },
      );

      expect(result.items).toHaveLength(5);
      expect(result.total).toBe(5);
    });
  });

  // ── userId filter with period ──────────────────────────────────────────────

  describe('userId filter with period', () => {
    it('uses table alias a. for period and status clauses in the JOIN query', async () => {
      const client = makeClient('3', []);
      await list(client as any, { userId: 'user-1', period: '2026-01' }, { limit: 10, offset: 0 });

      const dc = getDataCall(client.calls);
      expect(dc).toBeDefined();
      const sql = normalise(dc!.sql);
      expect(sql).toContain('a.period = $2');
    });

    it('uses table alias a. for status in the JOIN query', async () => {
      const client = makeClient('3', []);
      await list(client as any, { userId: 'user-1', status: 'revoked' }, { limit: 10, offset: 0 });

      const dc = getDataCall(client.calls);
      expect(dc).toBeDefined();
      const sql = normalise(dc!.sql);
      expect(sql).toContain("coalesce(a.status, 'submitted') = $2");
    });
  });
});
