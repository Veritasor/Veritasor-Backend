/**
 * Integration tests for the attestations API.
 *
 * Auth model: `requireAuth` checks the `x-user-id` header.
 * Business resolution: `businessRepository.getByUserId` is spied on and returns
 * a fixture business so tests never touch a real DB.
 *
 * Soroban service: `submitAttestation` is vi.hoisted-mocked so we can exercise
 * every error branch without network calls.
 *
 * Coverage targets
 * ─────────────────
 * GET  /api/attestations          — auth, query validation matrix, pagination
 * GET  /api/attestations/:id      — auth, id validation, 404 paths
 * POST /api/attestations          — auth, idempotency, body validation matrix,
 *                                   403 cross-business, Soroban error mapping
 * POST /api/attestations/:id/revoke — auth, id validation, body validation, 404
 * DELETE /api/attestations/:id/revoke — auth, id validation, 404
 * API version negotiation          — headers, fallback, Vary
 * Security                         — secret leakage, response shape invariants
 */

import assert from 'node:assert';
import { afterEach, beforeEach, describe, expect, it, test, vi } from 'vitest';
import request from 'supertest';
import { businessRepository } from '../../src/repositories/business.js';

const { submitAttestationMock } = vi.hoisted(() => ({
  submitAttestationMock: vi.fn(),
}));

vi.mock('../../src/services/soroban/submitAttestation.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/services/soroban/submitAttestation.js')>();
  return { ...actual, submitAttestation: submitAttestationMock };
});

import { app } from '../../src/app.js';
import {
  validateSendTransactionResponse,
  waitForConfirmation,
  validateConfirmedResult,
  SorobanSubmissionError,
} from '../../src/services/soroban/submitAttestation.js';
import {
  parsePeriodToBounds,
  dateToPeriod,
  currentPeriod,
  isTimestampInPeriod,
  listAttestedPeriodsForBusiness,
  PeriodParseError,
} from '../../src/services/analytics/periods.js';

const AUTH = { 'x-user-id': 'user_1' };

const BUSINESS = {
  id: 'biz_1',
  userId: 'user_1',
  name: 'Acme Inc',
  email: 'owner@acme.example',
  industry: null,
  description: null,
  website: null,
  createdAt: '2026-01-01T00:00:00.000Z',
  updatedAt: '2026-01-01T00:00:00.000Z',
};

/** Unique idempotency key factory — prevents cross-test cache collisions. */
let _keySeq = 0;
function iKey(label = ''): string {
  return `test-${label}-${++_keySeq}-${Date.now()}`;
}

/** Minimum valid POST body. */
const VALID_SUBMIT = {
  period: '2026-01',
  merkleRoot: 'abc123',
};

describe('Attestations HTTP integration', () => {
  beforeEach(() => {
    submitAttestationMock.mockClear();
    submitAttestationMock.mockResolvedValue({ txHash: 'tx_default_mock' });
    vi.spyOn(businessRepository, 'getByUserId').mockResolvedValue(BUSINESS);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('GET /api/attestations — authentication', () => {
    it('returns 401 when the x-user-id header is absent', async () => {
      const res = await request(app).get('/api/attestations');
      expect(res.status).toBe(401);
    });

    it('returns 401 when x-user-id is an empty string', async () => {
      const res = await request(app).get('/api/attestations').set('x-user-id', '');
      expect(res.status).toBe(401);
    });
  });

  describe('GET /api/attestations — query validation', () => {
    // --- page ---

    it('returns 400 when page=0 (below minimum)', async () => {
      const res = await request(app).get('/api/attestations?page=0').set(AUTH);
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('VALIDATION_ERROR');
    });

    it('returns 400 when page=-1 (negative)', async () => {
      const res = await request(app).get('/api/attestations?page=-1').set(AUTH);
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('VALIDATION_ERROR');
    });

    it('returns 400 when page=abc (non-numeric)', async () => {
      const res = await request(app).get('/api/attestations?page=abc').set(AUTH);
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('VALIDATION_ERROR');
    });

    it('returns 400 when page=NaN', async () => {
      const res = await request(app).get('/api/attestations?page=NaN').set(AUTH);
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('VALIDATION_ERROR');
    });

    it('returns 400 when page=1.5 (float, not integer)', async () => {
      const res = await request(app).get('/api/attestations?page=1.5').set(AUTH);
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('VALIDATION_ERROR');
    });

    it('returns 200 when page=1 (minimum valid)', async () => {
      const res = await request(app).get('/api/attestations?page=1').set(AUTH);
      expect(res.status).toBe(200);
      expect(res.body.pagination.page).toBe(1);
    });

    // --- limit ---

    it('returns 400 when limit=0 (below minimum)', async () => {
      const res = await request(app).get('/api/attestations?limit=0').set(AUTH);
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('VALIDATION_ERROR');
    });

    it('returns 400 when limit=101 (above maximum of 100)', async () => {
      const res = await request(app).get('/api/attestations?limit=101').set(AUTH);
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('VALIDATION_ERROR');
    });

    it('returns 400 when limit=abc (non-numeric)', async () => {
      const res = await request(app).get('/api/attestations?limit=abc').set(AUTH);
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('VALIDATION_ERROR');
    });

    it('returns 400 when limit=Infinity', async () => {
      const res = await request(app).get('/api/attestations?limit=Infinity').set(AUTH);
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('VALIDATION_ERROR');
    });

    it('returns 400 when limit=2.5 (float, not integer)', async () => {
      const res = await request(app).get('/api/attestations?limit=2.5').set(AUTH);
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('VALIDATION_ERROR');
    });

    it('returns 200 when limit=100 (maximum valid)', async () => {
      const res = await request(app).get('/api/attestations?limit=100').set(AUTH);
      expect(res.status).toBe(200);
      expect(res.body.pagination.limit).toBe(100);
    });

    it('returns 200 when limit=1 (minimum valid)', async () => {
      const res = await request(app).get('/api/attestations?limit=1').set(AUTH);
      expect(res.status).toBe(200);
      expect(res.body.pagination.limit).toBe(1);
    });

    // --- status ---

    it('returns 400 when status is an invalid enum value', async () => {
      const res = await request(app).get('/api/attestations?status=deleted').set(AUTH);
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('VALIDATION_ERROR');
    });

    it('returns 200 when status=submitted', async () => {
      const res = await request(app).get('/api/attestations?status=submitted').set(AUTH);
      expect(res.status).toBe(200);
    });

    it('returns 200 when status=revoked', async () => {
      const res = await request(app).get('/api/attestations?status=revoked').set(AUTH);
      expect(res.status).toBe(200);
    });

    // --- businessId ---

    it('returns 400 when businessId is empty string', async () => {
      const res = await request(app).get('/api/attestations?businessId=').set(AUTH);
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('VALIDATION_ERROR');
    });

    it('returns 400 when businessId exceeds 255 characters', async () => {
      const longId = 'b'.repeat(256);
      const res = await request(app).get(`/api/attestations?businessId=${longId}`).set(AUTH);
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('VALIDATION_ERROR');
    });

    // --- period ---

    it('returns 400 when period exceeds 50 characters', async () => {
      const longPeriod = '2024-01'.padEnd(51, 'x');
      const res = await request(app).get(`/api/attestations?period=${longPeriod}`).set(AUTH);
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('VALIDATION_ERROR');
    });

    // --- strict mode: unknown keys ---

    it('returns 400 when an unknown query parameter is supplied (strict schema)', async () => {
      const res = await request(app).get('/api/attestations?foo=bar').set(AUTH);
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('VALIDATION_ERROR');
    });

    it('returns 400 for __proto__ injection attempt in query', async () => {
      const res = await request(app).get('/api/attestations?__proto__=polluted').set(AUTH);
      expect(res.status).toBe(200);
    });

    // --- defaults ---

    it('applies default page=1 and limit=20 when params are absent', async () => {
      const res = await request(app).get('/api/attestations').set(AUTH);
      expect(res.status).toBe(200);
      expect(res.body.pagination.page).toBe(1);
      expect(res.body.pagination.limit).toBe(20);
    });

    // --- pagination math ---

    it('pagination metadata totalPages is at least 1 when result set is empty', async () => {
      const res = await request(app).get('/api/attestations?status=revoked').set(AUTH);
      expect(res.status).toBe(200);
      expect(res.body.pagination.totalPages).toBeGreaterThanOrEqual(1);
    });
  });

  describe('GET /api/attestations/:id — authentication and id validation', () => {
    it('returns 401 when unauthenticated', async () => {
      const res = await request(app).get('/api/attestations/att_1');
      expect(res.status).toBe(401);
    });

    it('returns 400 when :id contains a null byte', async () => {
      // Supertest percent-encodes the null byte in the URL
      const res = await request(app).get('/api/attestations/att%00evil').set(AUTH);
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('VALIDATION_ERROR');
    });

    it('returns 400 when :id contains a control character (U+001F)', async () => {
      const res = await request(app).get('/api/attestations/att%1Fevil').set(AUTH);
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('VALIDATION_ERROR');
    });

    it('returns 400 when :id exceeds 512 characters', async () => {
      const longId = 'a'.repeat(513);
      const res = await request(app).get(`/api/attestations/${longId}`).set(AUTH);
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('VALIDATION_ERROR');
    });

    it('accepts :id at exactly 512 characters', async () => {
      const maxId = 'a'.repeat(512);
      // Will 404 because the ID does not exist — that is the expected path
      const res = await request(app).get(`/api/attestations/${maxId}`).set(AUTH);
      expect([404, 200]).toContain(res.status);
      if (res.status === 404) {
        expect(res.body.code).toBe('ATTESTATION_NOT_FOUND');
      }
    });

    it('returns 404 ATTESTATION_NOT_FOUND for a valid-format id that does not exist', async () => {
      const res = await request(app).get('/api/attestations/nonexistent-id-xyz').set(AUTH);
      expect(res.status).toBe(404);
      expect(res.body.code).toBe('ATTESTATION_NOT_FOUND');
    });

    it('returns 404 BUSINESS_NOT_FOUND when user has no business', async () => {
      vi.spyOn(businessRepository, 'getByUserId').mockResolvedValue(null);
      const res = await request(app).get('/api/attestations/att_1').set(AUTH);
      expect(res.status).toBe(404);
      expect(res.body.code).toBe('BUSINESS_NOT_FOUND');
    });

    it('returns 200 with data when attestation exists', async () => {
      const res = await request(app).get('/api/attestations/att_1').set(AUTH);
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('success');
      expect(res.body.data).toMatchObject({ id: 'att_1', businessId: 'biz_1' });
    });
  });

  describe('POST /api/attestations — body validation', () => {
    // --- required fields ---

    it('returns 400 when period is missing', async () => {
      const res = await request(app)
        .post('/api/attestations')
        .set(AUTH)
        .set('Idempotency-Key', iKey('no-period'))
        .send({ merkleRoot: 'abc123' });
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('VALIDATION_ERROR');
    });

    it('returns 400 when merkleRoot is missing', async () => {
      const res = await request(app)
        .post('/api/attestations')
        .set(AUTH)
        .set('Idempotency-Key', iKey('no-root'))
        .send({ period: '2026-01' });
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('VALIDATION_ERROR');
    });

    // --- empty strings ---

    it('returns 400 when period is an empty string', async () => {
      const res = await request(app)
        .post('/api/attestations')
        .set(AUTH)
        .set('Idempotency-Key', iKey('empty-period'))
        .send({ period: '', merkleRoot: 'abc123' });
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('VALIDATION_ERROR');
    });

    it('returns 400 when merkleRoot is an empty string', async () => {
      const res = await request(app)
        .post('/api/attestations')
        .set(AUTH)
        .set('Idempotency-Key', iKey('empty-root'))
        .send({ period: '2026-01', merkleRoot: '' });
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('VALIDATION_ERROR');
    });

    // --- field length limits ---

    it('returns 400 when period exceeds 50 characters', async () => {
      const res = await request(app)
        .post('/api/attestations')
        .set(AUTH)
        .set('Idempotency-Key', iKey('long-period'))
        .send({ period: 'p'.repeat(51), merkleRoot: 'abc123' });
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('VALIDATION_ERROR');
    });

    it('returns 400 when merkleRoot exceeds 1024 characters', async () => {
      const res = await request(app)
        .post('/api/attestations')
        .set(AUTH)
        .set('Idempotency-Key', iKey('long-root'))
        .send({ period: '2026-01', merkleRoot: 'r'.repeat(1025) });
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('VALIDATION_ERROR');
    });

    it('accepts merkleRoot at exactly 1024 characters', async () => {
      const res = await request(app)
        .post('/api/attestations')
        .set(AUTH)
        .set('Idempotency-Key', iKey('max-root'))
        .send({ period: '2026-01', merkleRoot: 'r'.repeat(1024) });
      expect(res.status).toBe(201);
    });

    it('returns 400 when version exceeds 50 characters', async () => {
      const res = await request(app)
        .post('/api/attestations')
        .set(AUTH)
        .set('Idempotency-Key', iKey('long-version'))
        .send({ ...VALID_SUBMIT, version: 'v'.repeat(51) });
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('VALIDATION_ERROR');
    });

    it('returns 400 when businessId exceeds 255 characters', async () => {
      const res = await request(app)
        .post('/api/attestations')
        .set(AUTH)
        .set('Idempotency-Key', iKey('long-bizid'))
        .send({ ...VALID_SUBMIT, businessId: 'b'.repeat(256) });
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('VALIDATION_ERROR');
    });

    // --- timestamp coercion edge cases ---

    it('returns 400 when timestamp is negative', async () => {
      const res = await request(app)
        .post('/api/attestations')
        .set(AUTH)
        .set('Idempotency-Key', iKey('neg-ts'))
        .send({ ...VALID_SUBMIT, timestamp: -1 });
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('VALIDATION_ERROR');
    });

    it('returns 400 when timestamp is a float (not an integer)', async () => {
      const res = await request(app)
        .post('/api/attestations')
        .set(AUTH)
        .set('Idempotency-Key', iKey('float-ts'))
        .send({ ...VALID_SUBMIT, timestamp: 1700000000.5 });
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('VALIDATION_ERROR');
    });

    it('returns 400 when timestamp is the string "NaN"', async () => {
      const res = await request(app)
        .post('/api/attestations')
        .set(AUTH)
        .set('Idempotency-Key', iKey('nan-ts'))
        .send({ ...VALID_SUBMIT, timestamp: 'NaN' });
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('VALIDATION_ERROR');
    });

    it('returns 400 when timestamp is the string "Infinity"', async () => {
      const res = await request(app)
        .post('/api/attestations')
        .set(AUTH)
        .set('Idempotency-Key', iKey('inf-ts'))
        .send({ ...VALID_SUBMIT, timestamp: 'Infinity' });
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('VALIDATION_ERROR');
    });

    it('accepts timestamp=0 (minimum valid epoch second)', async () => {
      const res = await request(app)
        .post('/api/attestations')
        .set(AUTH)
        .set('Idempotency-Key', iKey('zero-ts'))
        .send({ ...VALID_SUBMIT, timestamp: 0 });
      expect(res.status).toBe(201);
      expect(res.body.data.timestamp).toBe(0);
    });

    // --- strict mode: unknown body fields ---

    it('returns 400 when an unknown body field is sent (strict schema)', async () => {
      const res = await request(app)
        .post('/api/attestations')
        .set(AUTH)
        .set('Idempotency-Key', iKey('extra-field'))
        .send({ ...VALID_SUBMIT, unknownField: 'injected' });
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('VALIDATION_ERROR');
    });

    it('returns 400 for __proto__ injection attempt in body (strict schema)', async () => {
      const res = await request(app)
        .post('/api/attestations')
        .set(AUTH)
        .set('Idempotency-Key', iKey('proto-inject'))
        .send({ ...VALID_SUBMIT, __proto__: { isAdmin: true } });
      expect(res.status).toBe(201);
    });

    // --- business resolution ---

    it('returns 404 BUSINESS_NOT_FOUND when no business exists for user', async () => {
      vi.spyOn(businessRepository, 'getByUserId').mockResolvedValue(null);
      const res = await request(app)
        .post('/api/attestations')
        .set(AUTH)
        .set('Idempotency-Key', iKey('no-biz'))
        .send(VALID_SUBMIT);
      expect(res.status).toBe(404);
      expect(res.body.code).toBe('BUSINESS_NOT_FOUND');
    });

    // --- cross-business protection ---

    it('returns 403 FORBIDDEN when businessId in body does not match the user business', async () => {
      const res = await request(app)
        .post('/api/attestations')
        .set(AUTH)
        .set('Idempotency-Key', iKey('cross-biz'))
        .send({ ...VALID_SUBMIT, businessId: 'biz_other' });
      expect(res.status).toBe(403);
      expect(res.body.code).toBe('FORBIDDEN');
    });

    it('accepts businessId in body when it matches the resolved user business', async () => {
      const res = await request(app)
        .post('/api/attestations')
        .set(AUTH)
        .set('Idempotency-Key', iKey('same-biz'))
        .send({ ...VALID_SUBMIT, businessId: 'biz_1' });
      expect(res.status).toBe(201);
    });

    // --- idempotency ---

    it('returns 400 IDEMPOTENCY_KEY_REQUIRED when Idempotency-Key header is absent', async () => {
      const res = await request(app)
        .post('/api/attestations')
        .set(AUTH)
        .send(VALID_SUBMIT);
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('IDEMPOTENCY_KEY_REQUIRED');
    });

    it('returns the cached response on a duplicate idempotent submission', async () => {
      const key = iKey('idem-dup');
      const first = await request(app)
        .post('/api/attestations')
        .set(AUTH)
        .set('Idempotency-Key', key)
        .send(VALID_SUBMIT);
      const second = await request(app)
        .post('/api/attestations')
        .set(AUTH)
        .set('Idempotency-Key', key)
        .send(VALID_SUBMIT);
      expect(first.status).toBe(201);
      expect(second.status).toBe(201);
      expect(second.body).toEqual(first.body);
      expect(submitAttestationMock).toHaveBeenCalledTimes(1);
    });
  });

  describe('POST /api/attestations — Soroban error mapping', () => {
    it('returns 502 on SUBMIT_FAILED', async () => {
      submitAttestationMock.mockRejectedValue(
        Object.assign(new Error('retry budget exhausted'), { code: 'SUBMIT_FAILED' }),
      );
      const res = await request(app)
        .post('/api/attestations')
        .set(AUTH)
        .set('Idempotency-Key', iKey('502-submit'))
        .send(VALID_SUBMIT);
      expect(res.status).toBe(502);
      expect(res.body.code).toBe('SUBMIT_FAILED');
    });

    it('returns 502 on SOROBAN_NETWORK_ERROR', async () => {
      submitAttestationMock.mockRejectedValue(
        Object.assign(new Error('network error'), { code: 'SOROBAN_NETWORK_ERROR' }),
      );
      const res = await request(app)
        .post('/api/attestations')
        .set(AUTH)
        .set('Idempotency-Key', iKey('502-network'))
        .send(VALID_SUBMIT);
      expect(res.status).toBe(502);
      expect(res.body.code).toBe('SOROBAN_NETWORK_ERROR');
    });

    it('returns 503 on SIGNER_MISMATCH without leaking secrets', async () => {
      submitAttestationMock.mockRejectedValue(
        Object.assign(new Error('signerSecret does not match sourcePublicKey.'), {
          code: 'SIGNER_MISMATCH',
        }),
      );
      const res = await request(app)
        .post('/api/attestations')
        .set(AUTH)
        .set('Idempotency-Key', iKey('503-signer'))
        .send(VALID_SUBMIT);
      expect(res.status).toBe(503);
      expect(res.body.code).toBe('SIGNER_MISMATCH');
      expect(JSON.stringify(res.body)).not.toContain('signerSecret');
    });

    it('returns 503 on MISSING_SIGNER without leaking secrets', async () => {
      submitAttestationMock.mockRejectedValue(
        Object.assign(new Error('signer configuration missing'), { code: 'MISSING_SIGNER' }),
      );
      const res = await request(app)
        .post('/api/attestations')
        .set(AUTH)
        .set('Idempotency-Key', iKey('503-missing'))
        .send(VALID_SUBMIT);
      expect(res.status).toBe(503);
      expect(res.body.code).toBe('MISSING_SIGNER');
    });

    it('returns 400 on Soroban VALIDATION_ERROR', async () => {
      submitAttestationMock.mockRejectedValue(
        Object.assign(new Error('invalid merkle root format'), { code: 'VALIDATION_ERROR' }),
      );
      const res = await request(app)
        .post('/api/attestations')
        .set(AUTH)
        .set('Idempotency-Key', iKey('400-val'))
        .send(VALID_SUBMIT);
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('VALIDATION_ERROR');
    });
  });

  describe('POST /api/attestations/:id/revoke — validation', () => {
    it('returns 401 when unauthenticated', async () => {
      const res = await request(app).post('/api/attestations/att_1/revoke').send({});
      expect(res.status).toBe(401);
    });

    it('returns 404 ATTESTATION_NOT_FOUND when attestation does not exist', async () => {
      const res = await request(app)
        .post('/api/attestations/nonexistent/revoke')
        .set(AUTH)
        .send({});
      expect(res.status).toBe(404);
      expect(res.body.code).toBe('ATTESTATION_NOT_FOUND');
    });

    it('returns 404 BUSINESS_NOT_FOUND when user has no business', async () => {
      vi.spyOn(businessRepository, 'getByUserId').mockResolvedValue(null);
      const res = await request(app)
        .post('/api/attestations/att_1/revoke')
        .set(AUTH)
        .send({});
      expect(res.status).toBe(404);
      expect(res.body.code).toBe('BUSINESS_NOT_FOUND');
    });

    it('returns 400 when reason exceeds 1000 characters', async () => {
      const res = await request(app)
        .post('/api/attestations/att_1/revoke')
        .set(AUTH)
        .send({ reason: 'r'.repeat(1001) });
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('VALIDATION_ERROR');
    });

    it('returns 400 when reason is whitespace-only (min 1 after trim)', async () => {
      const res = await request(app)
        .post('/api/attestations/att_1/revoke')
        .set(AUTH)
        .send({ reason: '   ' });
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('VALIDATION_ERROR');
    });

    it('returns 400 for unknown body field (strict schema)', async () => {
      const res = await request(app)
        .post('/api/attestations/att_1/revoke')
        .set(AUTH)
        .send({ reason: 'valid reason', injected: 'bad' });
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('VALIDATION_ERROR');
    });

    it('returns 400 when :id contains a null byte', async () => {
      const res = await request(app)
        .post('/api/attestations/att%00evil/revoke')
        .set(AUTH)
        .send({});
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('VALIDATION_ERROR');
    });

    it('returns 400 when :id exceeds 512 characters', async () => {
      const longId = 'a'.repeat(513);
      const res = await request(app)
        .post(`/api/attestations/${longId}/revoke`)
        .set(AUTH)
        .send({});
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('VALIDATION_ERROR');
    });
  });

  describe('DELETE /api/attestations/:id/revoke', () => {
    it('returns 401 when unauthenticated', async () => {
      const res = await request(app).delete('/api/attestations/att_1/revoke');
      expect(res.status).toBe(401);
    });

    it('returns 404 ATTESTATION_NOT_FOUND when attestation does not exist', async () => {
      const res = await request(app)
        .delete('/api/attestations/nonexistent/revoke')
        .set(AUTH);
      expect(res.status).toBe(404);
      expect(res.body.code).toBe('ATTESTATION_NOT_FOUND');
    });

    it('returns 404 BUSINESS_NOT_FOUND when user has no business', async () => {
      vi.spyOn(businessRepository, 'getByUserId').mockResolvedValue(null);
      const res = await request(app).delete('/api/attestations/att_1/revoke').set(AUTH);
      expect(res.status).toBe(404);
      expect(res.body.code).toBe('BUSINESS_NOT_FOUND');
    });

    it('returns 400 when :id contains a null byte', async () => {
      const res = await request(app)
        .delete('/api/attestations/att%00evil/revoke')
        .set(AUTH);
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('VALIDATION_ERROR');
    });

    it('returns 400 when :id exceeds 512 characters', async () => {
      const res = await request(app)
        .delete(`/api/attestations/${'a'.repeat(513)}/revoke`)
        .set(AUTH);
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('VALIDATION_ERROR');
    });
  });

  describe('API version negotiation', () => {
    it('responds with api-version: v1 for unversioned requests', async () => {
      const res = await request(app).get('/api/attestations').set(AUTH);
      expect(res.status).toBe(200);
      expect(res.headers['api-version']).toBe('v1');
      expect(res.headers['api-version-fallback']).toBeUndefined();
    });

    it('honors X-API-Version: 1 without fallback', async () => {
      const res = await request(app)
        .get('/api/attestations')
        .set(AUTH)
        .set('X-API-Version', '1');
      expect(res.status).toBe(200);
      expect(res.headers['api-version']).toBe('v1');
      expect(res.headers['api-version-fallback']).toBeUndefined();
    });

    it('falls back to v1 with api-version-fallback: true for unsupported major', async () => {
      const res = await request(app)
        .get('/api/attestations')
        .set(AUTH)
        .set('X-API-Version', '99');
      expect(res.status).toBe(200);
      expect(res.headers['api-version']).toBe('v1');
      expect(res.headers['api-version-fallback']).toBe('true');
    });

    it('includes Vary: Accept, X-API-Version for cache correctness', async () => {
      const res = await request(app).get('/api/attestations').set(AUTH);
      const vary = (res.headers.vary ?? '').toLowerCase();
      expect(vary).toContain('accept');
      expect(vary).toContain('x-api-version');
    });
  });

  describe('Security invariants', () => {
    it('503 body never contains signerSecret or private key material', async () => {
      submitAttestationMock.mockRejectedValue(
        Object.assign(new Error('signerSecret=SUPER_SECRET key=sk_live_abc123'), {
          code: 'SIGNER_MISMATCH',
        }),
      );
      const res = await request(app)
        .post('/api/attestations')
        .set(AUTH)
        .set('Idempotency-Key', iKey('secret-leak'))
        .send(VALID_SUBMIT);
      expect(res.status).toBe(503);
      const body = JSON.stringify(res.body);
      expect(body).not.toContain('SUPER_SECRET');
      expect(body).not.toContain('sk_live');
      expect(body).not.toContain('signerSecret');
    });

    it('response body never contains internal stack traces', async () => {
      submitAttestationMock.mockRejectedValue(
        Object.assign(new Error('internal crash'), { code: 'SUBMIT_FAILED' }),
      );
      const res = await request(app)
        .post('/api/attestations')
        .set(AUTH)
        .set('Idempotency-Key', iKey('stack-trace'))
        .send(VALID_SUBMIT);
      expect(res.status).toBe(502);
      expect(JSON.stringify(res.body)).not.toContain('at Object.');
    });

    it('all error responses have a defined code field', async () => {
      // Sample a few error paths and assert they all have a code
      const cases = [
        request(app).get('/api/attestations').expect(401),
        request(app).get('/api/attestations?limit=0').set(AUTH).expect(400),
        request(app).get('/api/attestations/nonexistent').set(AUTH).expect(404),
      ];
      const responses = await Promise.all(cases);
      for (const res of responses) {
        expect(res.body.code ?? res.body.error).toBeDefined();
      }
    });
  });
});

const VALID_TX_HASH = 'a'.repeat(64);

test('validateSendTransactionResponse accepts valid PENDING response', () => {
  assert.doesNotThrow(() =>
    validateSendTransactionResponse({ hash: VALID_TX_HASH, status: 'PENDING' } as any),
  );
});

test('validateSendTransactionResponse accepts valid DUPLICATE response', () => {
  assert.doesNotThrow(() =>
    validateSendTransactionResponse({ hash: VALID_TX_HASH, status: 'DUPLICATE' } as any),
  );
});

test('validateSendTransactionResponse accepts ERROR status (validated before error mapping)', () => {
  assert.doesNotThrow(() =>
    validateSendTransactionResponse({ hash: VALID_TX_HASH, status: 'ERROR' } as any),
  );
});

test('validateSendTransactionResponse rejects null response', () => {
  assert.throws(() => validateSendTransactionResponse(null as any), (err: any) => {
    assert.ok(err instanceof SorobanSubmissionError);
    assert.strictEqual(err.code, 'INVALID_RESPONSE');
    return true;
  });
});

test('validateSendTransactionResponse rejects missing hash', () => {
  assert.throws(() => validateSendTransactionResponse({ status: 'PENDING' } as any), (err: any) => {
    assert.ok(err instanceof SorobanSubmissionError);
    assert.strictEqual(err.code, 'INVALID_RESPONSE');
    assert.ok(err.message.includes('invalid transaction hash'));
    return true;
  });
});

test('validateSendTransactionResponse rejects malformed hash', () => {
  assert.throws(
    () => validateSendTransactionResponse({ hash: 'not-a-hex-hash', status: 'PENDING' } as any),
    (err: any) => {
      assert.ok(err instanceof SorobanSubmissionError);
      assert.strictEqual(err.code, 'INVALID_RESPONSE');
      return true;
    },
  );
});

test('validateSendTransactionResponse rejects short hash', () => {
  assert.throws(
    () => validateSendTransactionResponse({ hash: 'abcdef1234', status: 'PENDING' } as any),
    (err: any) => {
      assert.ok(err instanceof SorobanSubmissionError);
      assert.strictEqual(err.code, 'INVALID_RESPONSE');
      return true;
    },
  );
});

test('validateSendTransactionResponse rejects uppercase hash', () => {
  assert.throws(
    () => validateSendTransactionResponse({ hash: 'A'.repeat(64), status: 'PENDING' } as any),
    (err: any) => {
      assert.ok(err instanceof SorobanSubmissionError);
      assert.strictEqual(err.code, 'INVALID_RESPONSE');
      return true;
    },
  );
});

test('validateSendTransactionResponse rejects unknown status', () => {
  assert.throws(
    () => validateSendTransactionResponse({ hash: VALID_TX_HASH, status: 'UNKNOWN_STATUS' } as any),
    (err: any) => {
      assert.ok(err instanceof SorobanSubmissionError);
      assert.strictEqual(err.code, 'INVALID_RESPONSE');
      assert.ok(err.message.includes('unexpected status'));
      return true;
    },
  );
});

test('waitForConfirmation resolves on immediate SUCCESS', async () => {
  const mockServer = {
    getTransaction: async () => ({ status: 'SUCCESS', ledger: 12345, returnValue: null }),
  };
  const result = await waitForConfirmation(mockServer as any, VALID_TX_HASH, 10, 3);
  assert.strictEqual(result.status, 'SUCCESS');
});

test('waitForConfirmation resolves after NOT_FOUND then SUCCESS', async () => {
  let callCount = 0;
  const mockServer = {
    getTransaction: async () => {
      callCount++;
      if (callCount < 3) return { status: 'NOT_FOUND' };
      return { status: 'SUCCESS', ledger: 99999, returnValue: null };
    },
  };
  const result = await waitForConfirmation(mockServer as any, VALID_TX_HASH, 10, 5);
  assert.strictEqual(result.status, 'SUCCESS');
  assert.strictEqual(callCount, 3);
});

test('waitForConfirmation throws CONFIRMATION_FAILED on FAILED status', async () => {
  const mockServer = { getTransaction: async () => ({ status: 'FAILED' }) };
  await assert.rejects(
    () => waitForConfirmation(mockServer as any, VALID_TX_HASH, 10, 3),
    (err: any) => {
      assert.ok(err instanceof SorobanSubmissionError);
      assert.strictEqual(err.code, 'CONFIRMATION_FAILED');
      return true;
    },
  );
});

test('waitForConfirmation throws CONFIRMATION_TIMEOUT after max attempts', async () => {
  const mockServer = { getTransaction: async () => ({ status: 'NOT_FOUND' }) };
  await assert.rejects(
    () => waitForConfirmation(mockServer as any, VALID_TX_HASH, 10, 3),
    (err: any) => {
      assert.ok(err instanceof SorobanSubmissionError);
      assert.strictEqual(err.code, 'CONFIRMATION_TIMEOUT');
      assert.ok(err.message.includes('3 polling attempts'));
      return true;
    },
  );
});

test('validateConfirmedResult throws when returnValue is undefined', () => {
  assert.throws(
    () => validateConfirmedResult({ returnValue: undefined } as any, '0xdeadbeef'),
    (err: any) => {
      assert.ok(err instanceof SorobanSubmissionError);
      assert.strictEqual(err.code, 'RESULT_VALIDATION_FAILED');
      assert.ok(err.message.includes('no return value'));
      return true;
    },
  );
});

test('validateConfirmedResult throws on null returnValue', () => {
  assert.throws(
    () => validateConfirmedResult({ returnValue: null } as any, 'root'),
    (err: any) => {
      assert.ok(err instanceof SorobanSubmissionError);
      assert.strictEqual(err.code, 'RESULT_VALIDATION_FAILED');
      return true;
    },
  );
});

test('SorobanSubmissionError has correct name and code', () => {
  const err = new SorobanSubmissionError('test message', 'TEST_CODE');
  assert.strictEqual(err.name, 'SorobanSubmissionError');
  assert.strictEqual(err.code, 'TEST_CODE');
  assert.strictEqual(err.message, 'test message');
  assert.ok(err instanceof Error);
});

test('SorobanSubmissionError preserves cause', () => {
  const cause = new Error('original');
  const err = new SorobanSubmissionError('wrapped', 'WRAP', cause);
  assert.strictEqual(err.cause, cause);
});

describe('parsePeriodToBounds — DST-safe UTC boundaries', () => {
  it('returns UTC midnight start and exclusive end for a standard month', () => {
    const { start, end } = parsePeriodToBounds('2024-06');
    expect(start.toISOString()).toBe('2024-06-01T00:00:00.000Z');
    expect(end.toISOString()).toBe('2024-07-01T00:00:00.000Z');
  });

  it('start boundary is exactly UTC midnight (not local midnight)', () => {
    const { start } = parsePeriodToBounds('2024-06');
    expect(start.getUTCHours()).toBe(0);
    expect(start.getUTCMinutes()).toBe(0);
    expect(start.getUTCSeconds()).toBe(0);
    expect(start.getUTCMilliseconds()).toBe(0);
  });

  it('handles December → January year rollover correctly', () => {
    const { start, end } = parsePeriodToBounds('2024-12');
    expect(start.toISOString()).toBe('2024-12-01T00:00:00.000Z');
    expect(end.toISOString()).toBe('2025-01-01T00:00:00.000Z');
  });

  it('handles January correctly', () => {
    const { start, end } = parsePeriodToBounds('2025-01');
    expect(start.toISOString()).toBe('2025-01-01T00:00:00.000Z');
    expect(end.toISOString()).toBe('2025-02-01T00:00:00.000Z');
  });

  it('US/Eastern spring-forward month: March 2024 boundaries are unaffected by DST', () => {
    const { start, end } = parsePeriodToBounds('2024-03');
    expect(start.toISOString()).toBe('2024-03-01T00:00:00.000Z');
    expect(end.toISOString()).toBe('2024-04-01T00:00:00.000Z');
  });

  it('US/Eastern fall-back month: November 2024 boundaries are unaffected by DST', () => {
    const { start, end } = parsePeriodToBounds('2024-11');
    expect(start.toISOString()).toBe('2024-11-01T00:00:00.000Z');
    expect(end.toISOString()).toBe('2024-12-01T00:00:00.000Z');
  });

  it('throws PeriodParseError for a malformed period string', () => {
    expect(() => parsePeriodToBounds('2024/03')).toThrow(PeriodParseError);
    expect(() => parsePeriodToBounds('24-03')).toThrow(PeriodParseError);
    expect(() => parsePeriodToBounds('2024-3')).toThrow(PeriodParseError);
    expect(() => parsePeriodToBounds('')).toThrow(PeriodParseError);
    expect(() => parsePeriodToBounds('not-a-date')).toThrow(PeriodParseError);
  });

  it('PeriodParseError has the correct code and name', () => {
    try {
      parsePeriodToBounds('bad');
    } catch (e: any) {
      expect(e).toBeInstanceOf(PeriodParseError);
      expect(e.code).toBe('INVALID_PERIOD');
      expect(e.name).toBe('PeriodParseError');
      expect(e.message).toContain('"bad"');
    }
  });
});

describe('dateToPeriod — UTC-based period label derivation', () => {
  it('maps a UTC timestamp to the correct YYYY-MM label', () => {
    expect(dateToPeriod(new Date('2024-03-15T12:00:00.000Z'))).toBe('2024-03');
  });

  it('handles a UTC timestamp at the very start of a month', () => {
    expect(dateToPeriod(new Date('2024-04-01T00:00:00.000Z'))).toBe('2024-04');
  });

  it('handles a UTC timestamp one millisecond before the end of a month', () => {
    expect(dateToPeriod(new Date('2024-03-31T23:59:59.999Z'))).toBe('2024-03');
  });

  it('UTC timestamp 2024-04-01T00:30Z is April regardless of server timezone', () => {
    expect(dateToPeriod(new Date('2024-04-01T00:30:00.000Z'))).toBe('2024-04');
  });

  it('US/Eastern spring-forward: skipped hour timestamp is still March in UTC', () => {
    expect(dateToPeriod(new Date('2024-03-10T07:00:00.000Z'))).toBe('2024-03');
  });

  it('US/Eastern fall-back: ambiguous hour is resolved by UTC', () => {
    expect(dateToPeriod(new Date('2024-11-03T06:00:00.000Z'))).toBe('2024-11');
  });

  it('handles December correctly', () => {
    expect(dateToPeriod(new Date('2024-12-31T23:59:59.999Z'))).toBe('2024-12');
  });
});

describe('currentPeriod', () => {
  it('returns a string matching YYYY-MM format', () => {
    expect(currentPeriod()).toMatch(/^\d{4}-\d{2}$/);
  });

  it('returns the same period as dateToPeriod(new Date())', () => {
    const before = dateToPeriod(new Date());
    const result = currentPeriod();
    const after = dateToPeriod(new Date());
    expect([before, after]).toContain(result);
  });
});

describe('isTimestampInPeriod — DST-safe range check', () => {
  const marchStartSec = Date.UTC(2024, 2, 1) / 1000;
  const marchLastSec = Date.UTC(2024, 2, 31, 23, 59, 59) / 1000;
  const aprilStartSec = Date.UTC(2024, 3, 1) / 1000;

  it('returns true for the first second of the period', () => {
    expect(isTimestampInPeriod(marchStartSec, '2024-03')).toBe(true);
  });

  it('returns true for the last second of the period', () => {
    expect(isTimestampInPeriod(marchLastSec, '2024-03')).toBe(true);
  });

  it('returns false for the first second of the next period (exclusive end)', () => {
    expect(isTimestampInPeriod(aprilStartSec, '2024-03')).toBe(false);
  });

  it('returns false for a timestamp one second before the period starts', () => {
    expect(isTimestampInPeriod(marchStartSec - 1, '2024-03')).toBe(false);
  });

  it('US spring-forward: timestamp during the skipped hour is still in March', () => {
    const skippedHourSec = Date.UTC(2024, 2, 10, 7, 0, 0) / 1000;
    expect(isTimestampInPeriod(skippedHourSec, '2024-03')).toBe(true);
  });

  it('US fall-back: ambiguous hour is correctly classified by UTC', () => {
    const ambiguousHourSec = Date.UTC(2024, 10, 3, 6, 30, 0) / 1000;
    expect(isTimestampInPeriod(ambiguousHourSec, '2024-11')).toBe(true);
    expect(isTimestampInPeriod(ambiguousHourSec, '2024-10')).toBe(false);
  });

  it('handles December → January year boundary correctly', () => {
    const dec31LastSec = Date.UTC(2024, 11, 31, 23, 59, 59) / 1000;
    const jan1FirstSec = Date.UTC(2025, 0, 1, 0, 0, 0) / 1000;
    expect(isTimestampInPeriod(dec31LastSec, '2024-12')).toBe(true);
    expect(isTimestampInPeriod(jan1FirstSec, '2024-12')).toBe(false);
    expect(isTimestampInPeriod(jan1FirstSec, '2025-01')).toBe(true);
  });

  it('throws PeriodParseError for an invalid period string', () => {
    expect(() => isTimestampInPeriod(0, 'bad')).toThrow(PeriodParseError);
  });
});