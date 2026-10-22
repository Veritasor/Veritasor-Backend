/**
 * Tests for GET /api/attestations list endpoint.
 *
 * Covers:
 *  - formatPaginatedResponse envelope (data, page, limit, total, totalPages)
 *  - status filter returning correct items and totals
 *  - period filter returning correct items and totals
 *  - no in-memory filtering: totals come from the repository, not from
 *    re-counting filteredItems after fetching a page
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import request from 'supertest';
import express from 'express';
import { attestationsRouter } from '../attestations.js';
import { errorHandler } from '../../middleware/errorHandler.js';

// ---------------------------------------------------------------------------
// Module mocks
// ---------------------------------------------------------------------------

vi.mock('../../repositories/attestationRepository.js', () => ({
  list: vi.fn(),
  getById: vi.fn(),
  create: vi.fn(),
  updateStatus: vi.fn(),
}));

vi.mock('../../repositories/business.js', () => ({
  businessRepository: {
    getByUserId: vi.fn(),
  },
}));

vi.mock('../../db/client.js', () => ({ db: {} }));
vi.mock('../../redis.ts', () => ({}));
vi.mock('../../ws/attestationStream.js', () => ({
  broadcaster: { publish: vi.fn() },
}));
vi.mock('../../middleware/idempotency.js', () => ({
  idempotencyMiddleware: () => (_req: any, _res: any, next: any) => next(),
}));
vi.mock('../../middleware/rateLimiter.js', () => ({
  rateLimiter: () => (_req: any, _res: any, next: any) => next(),
}));
vi.mock('../../metrics.js', () => ({
  observeAttestationSubmitLatency: vi.fn(),
}));
vi.mock('../../repositories/auditLogRepository.js', () => ({
  createAuditLog: vi.fn(),
}));
vi.mock('../../services/soroban/submitAttestation.js', () => ({
  enqueueQueuedAttestation: vi.fn(),
  isSorobanQueueEnabled: vi.fn(() => false),
}));
vi.mock('../../services/merkle/generateProof.js', () => ({
  generateProof: vi.fn(),
  verifyProof: vi.fn(() => true),
}));
vi.mock('../../tracing/index.js', () => ({}));

import * as attestationRepository from '../../repositories/attestationRepository.js';
import { businessRepository } from '../../repositories/business.js';

// ---------------------------------------------------------------------------
// Test app setup
// ---------------------------------------------------------------------------

const app = express();
app.use(express.json());
app.use('/api/attestations', attestationsRouter);
app.use(errorHandler);

const USER_ID = 'user-001';
const BUSINESS_ID = 'biz-001';

// Auth header expected by requireAuth (reads x-user-id)
const authHeaders = { 'x-user-id': USER_ID };

/**
 * Build a minimal attestation DB row mirroring what the repository returns
 * after mapRowToAttestation().
 */
function makeAttestation(overrides: {
  id?: string;
  period?: string;
  status?: 'submitted' | 'revoked' | 'pending' | 'confirmed' | 'failed';
} = {}) {
  const now = new Date('2026-01-15T10:00:00.000Z');
  return {
    id: overrides.id ?? `att-${Math.random().toString(36).slice(2)}`,
    businessId: BUSINESS_ID,
    period: overrides.period ?? '2026-01',
    merkleRoot: '0xabc',
    txHash: '0xdef',
    status: overrides.status ?? 'submitted',
    version: 1,
    createdAt: now,
    updatedAt: now,
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const mockedList = vi.mocked(attestationRepository.list);
const mockedGetByUserId = vi.mocked(
  (businessRepository as any).getByUserId as (id: string) => Promise<{ id: string } | null>,
);

beforeEach(() => {
  vi.clearAllMocks();
  mockedGetByUserId.mockResolvedValue({ id: BUSINESS_ID });
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('GET /api/attestations', () => {
  describe('pagination envelope', () => {
    it('returns correct envelope shape with data, page, limit, total, totalPages', async () => {
      const items = [makeAttestation(), makeAttestation()];
      mockedList.mockResolvedValue({ items, total: 2 });

      const res = await request(app)
        .get('/api/attestations?page=1&limit=10')
        .set(authHeaders);

      expect(res.status).toBe(200);
      expect(res.body.status).toBe('success');
      expect(res.body.data).toHaveLength(2);
      expect(res.body.pagination).toMatchObject({
        page: 1,
        limit: 10,
        total: 2,
        totalPages: 1,
      });
    });

    it('calculates totalPages correctly for multiple pages', async () => {
      const items = Array.from({ length: 10 }, () => makeAttestation());
      mockedList.mockResolvedValue({ items, total: 30 });

      const res = await request(app)
        .get('/api/attestations?page=1&limit=10')
        .set(authHeaders);

      expect(res.status).toBe(200);
      expect(res.body.pagination.total).toBe(30);
      expect(res.body.pagination.totalPages).toBe(3);
    });

    it('forwards the correct offset to the repository for page 2', async () => {
      mockedList.mockResolvedValue({ items: [], total: 0 });

      await request(app)
        .get('/api/attestations?page=2&limit=10')
        .set(authHeaders);

      expect(mockedList).toHaveBeenCalledWith(
        expect.anything(),
        expect.objectContaining({ businessId: BUSINESS_ID }),
        expect.objectContaining({ limit: 10, offset: 10 }),
      );
    });
  });

  describe('status filter', () => {
    it('passes status=revoked to the repository (not filtered in-memory)', async () => {
      const revokedItems = Array.from({ length: 5 }, () =>
        makeAttestation({ status: 'revoked' }),
      );
      // Repository returns the already-filtered 5 rows with total=5
      mockedList.mockResolvedValue({ items: revokedItems, total: 5 });

      const res = await request(app)
        .get('/api/attestations?status=revoked&limit=10&page=1')
        .set(authHeaders);

      expect(res.status).toBe(200);

      // The repository must have received the status filter
      expect(mockedList).toHaveBeenCalledWith(
        expect.anything(),
        expect.objectContaining({ businessId: BUSINESS_ID, status: 'revoked' }),
        expect.objectContaining({ limit: 10, offset: 0 }),
      );

      // Response reflects repository-reported total, not in-memory re-count
      expect(res.body.data).toHaveLength(5);
      expect(res.body.pagination).toMatchObject({ total: 5, totalPages: 1 });
    });

    it('returns 5 items total:5 totalPages:1 for ?status=revoked scenario from issue', async () => {
      /**
       * Acceptance criterion from issue #1224:
       *   30 attestations, 5 of them revoked.
       *   ?status=revoked&limit=10&page=1 → 5 items, total:5, totalPages:1
       *
       * The repository mock already does the filtering and returns the correct
       * total; this test verifies the route does NOT re-filter or re-count.
       */
      const revokedItems = Array.from({ length: 5 }, () =>
        makeAttestation({ status: 'revoked' }),
      );
      mockedList.mockResolvedValue({ items: revokedItems, total: 5 });

      const res = await request(app)
        .get('/api/attestations?status=revoked&limit=10&page=1')
        .set(authHeaders);

      expect(res.status).toBe(200);
      expect(res.body.data).toHaveLength(5);
      expect(res.body.pagination.total).toBe(5);
      expect(res.body.pagination.totalPages).toBe(1);
    });

    it('passes status=submitted to the repository', async () => {
      mockedList.mockResolvedValue({ items: [], total: 0 });

      await request(app)
        .get('/api/attestations?status=submitted')
        .set(authHeaders);

      expect(mockedList).toHaveBeenCalledWith(
        expect.anything(),
        expect.objectContaining({ status: 'submitted' }),
        expect.anything(),
      );
    });
  });

  describe('period filter', () => {
    it('passes period to the repository and returns matching totals', async () => {
      const items = Array.from({ length: 3 }, () =>
        makeAttestation({ period: '2026-01' }),
      );
      mockedList.mockResolvedValue({ items, total: 3 });

      const res = await request(app)
        .get('/api/attestations?period=2026-01&limit=10&page=1')
        .set(authHeaders);

      expect(res.status).toBe(200);

      expect(mockedList).toHaveBeenCalledWith(
        expect.anything(),
        expect.objectContaining({ businessId: BUSINESS_ID, period: '2026-01' }),
        expect.objectContaining({ limit: 10, offset: 0 }),
      );

      expect(res.body.data).toHaveLength(3);
      expect(res.body.pagination).toMatchObject({ total: 3, totalPages: 1 });
    });

    it('acceptance criterion: ?period=2026-01 returns only that period with matching totals', async () => {
      const items = Array.from({ length: 7 }, () =>
        makeAttestation({ period: '2026-01' }),
      );
      mockedList.mockResolvedValue({ items, total: 7 });

      const res = await request(app)
        .get('/api/attestations?period=2026-01&limit=20&page=1')
        .set(authHeaders);

      expect(res.status).toBe(200);
      expect(res.body.data.every((a: any) => a.period === '2026-01')).toBe(true);
      expect(res.body.pagination.total).toBe(7);
    });
  });

  describe('combined period + status filter', () => {
    it('passes both period and status to the repository', async () => {
      mockedList.mockResolvedValue({ items: [], total: 0 });

      await request(app)
        .get('/api/attestations?period=2026-01&status=revoked')
        .set(authHeaders);

      expect(mockedList).toHaveBeenCalledWith(
        expect.anything(),
        expect.objectContaining({ period: '2026-01', status: 'revoked' }),
        expect.anything(),
      );
    });
  });

  describe('error handling', () => {
    it('returns 404 when no business is found for the user', async () => {
      mockedGetByUserId.mockResolvedValue(null);

      const res = await request(app)
        .get('/api/attestations')
        .set(authHeaders);

      expect(res.status).toBe(404);
    });

    it('returns 401 when no auth header is provided', async () => {
      const res = await request(app).get('/api/attestations');
      expect(res.status).toBe(401);
    });

    it('returns 400 for an invalid status value', async () => {
      const res = await request(app)
        .get('/api/attestations?status=invalid')
        .set(authHeaders);

      expect(res.status).toBe(400);
    });

    it('returns 400 for a non-integer page value', async () => {
      const res = await request(app)
        .get('/api/attestations?page=abc')
        .set(authHeaders);

      expect(res.status).toBe(400);
    });
  });
});
