/**
 * Integration Tests for Analytics Routes with requireBusinessAuth Boundary Checks
 *
 * This test suite validates the security and error contract of the requireBusinessAuth
 * middleware on analytics routes (/api/analytics/periods and /api/analytics/revenue).
 *
 * Tests cover all documented error codes and HTTP statuses:
 *   401 MISSING_AUTH        – missing / malformed Authorization header
 *   401 INVALID_TOKEN       – expired, invalid, or revoked JWT; user not found
 *   400 MISSING_BUSINESS_ID – no business ID in header or body
 *   403 BUSINESS_NOT_FOUND  – business absent or owned by a different user
 *   403 BUSINESS_SUSPENDED  – business exists but is suspended
 *
 * Edge cases tested:
 *   - Expired tokens
 *   - Cross-tenant access (valid token but different user's business)
 *   - Malformed business IDs
 *   - Suspended business accounts
 *   - Valid business owner access
 *
 * @module tests/integration/analytics-business-auth
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import request from 'supertest';
import { app } from '../../src/app.js';
import * as jwt from '../../src/utils/jwt.js';
import * as userRepository from '../../src/repositories/userRepository.js';
import * as businessRepo from '../../src/repositories/business.js';
import * as analyticsService from '../../src/services/analytics/periods.js';

// ─── Test Fixtures ────────────────────────────────────────────────────────────

const OWNER_USER = {
  id: 'owner-user-123',
  userId: 'owner-user-123',
  email: 'owner@example.com',
};

const OTHER_USER = {
  id: 'other-user-456',
  userId: 'other-user-456',
  email: 'other@example.com',
};

const OWNER_BUSINESS = {
  id: 'biz-owner-123',
  userId: 'owner-user-123',
  name: 'Owner Business',
  industry: 'Technology',
  description: 'A business owned by owner-user-123',
  website: 'https://owner.example.com',
  createdAt: '2024-01-01T00:00:00Z',
  updatedAt: '2024-01-01T00:00:00Z',
  suspended: false,
};

const OTHER_USER_BUSINESS = {
  id: 'biz-other-456',
  userId: 'other-user-456',
  name: 'Other Business',
  industry: 'Finance',
  description: 'A business owned by other-user-456',
  website: 'https://other.example.com',
  createdAt: '2024-01-01T00:00:00Z',
  updatedAt: '2024-01-01T00:00:00Z',
  suspended: false,
};

const SUSPENDED_BUSINESS = {
  id: 'biz-suspended-789',
  userId: 'owner-user-123',
  name: 'Suspended Business',
  industry: 'Technology',
  description: 'A suspended business',
  website: null,
  createdAt: '2024-01-01T00:00:00Z',
  updatedAt: '2024-01-15T00:00:00Z',
  suspended: true,
};

// ─── Mock Setup Helpers ───────────────────────────────────────────────────────

function setupMocksForOwner() {
  vi.spyOn(jwt, 'verifyToken').mockReturnValue({
    userId: OWNER_USER.id,
    email: OWNER_USER.email,
  });
  vi.spyOn(userRepository, 'findUserById').mockResolvedValue(OWNER_USER as any);
  vi.spyOn(businessRepo.businessRepository, 'getById').mockResolvedValue(OWNER_BUSINESS as any);
  vi.spyOn(analyticsService, 'listAttestedPeriodsForBusiness').mockReturnValue([]);
}

function setupMocksForOtherUser() {
  vi.spyOn(jwt, 'verifyToken').mockReturnValue({
    userId: OTHER_USER.id,
    email: OTHER_USER.email,
  });
  vi.spyOn(userRepository, 'findUserById').mockResolvedValue(OTHER_USER as any);
  vi.spyOn(businessRepo.businessRepository, 'getById').mockImplementation(async (id: string) => {
    if (id === OTHER_USER_BUSINESS.id) return OTHER_USER_BUSINESS as any;
    if (id === OWNER_BUSINESS.id) return OWNER_BUSINESS as any;
    return null;
  });
}

function setupMocksForSuspendedBusiness() {
  vi.spyOn(jwt, 'verifyToken').mockReturnValue({
    userId: OWNER_USER.id,
    email: OWNER_USER.email,
  });
  vi.spyOn(userRepository, 'findUserById').mockResolvedValue(OWNER_USER as any);
  vi.spyOn(businessRepo.businessRepository, 'getById').mockResolvedValue(SUSPENDED_BUSINESS as any);
}

// ─── Test Suite ───────────────────────────────────────────────────────────────

describe('Analytics Routes — requireBusinessAuth Boundary Checks', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('GET /api/analytics/periods', () => {
    describe('401 MISSING_AUTH', () => {
      it('rejects request without Authorization header', async () => {
        const res = await request(app)
          .get('/api/analytics/periods')
          .set('x-business-id', OWNER_BUSINESS.id);

        expect(res.status).toBe(401);
        expect(res.body.code).toBe('MISSING_AUTH');
        expect(res.body.error).toContain('Business authentication required');
      });

      it('rejects request with malformed Authorization header (no Bearer)', async () => {
        const res = await request(app)
          .get('/api/analytics/periods')
          .set('Authorization', 'Basic dXNlcjpwYXNz')
          .set('x-business-id', OWNER_BUSINESS.id);

        expect(res.status).toBe(401);
        expect(res.body.code).toBe('MISSING_AUTH');
      });

      it('rejects request with empty Authorization header', async () => {
        const res = await request(app)
          .get('/api/analytics/periods')
          .set('Authorization', '')
          .set('x-business-id', OWNER_BUSINESS.id);

        expect(res.status).toBe(401);
        expect(res.body.code).toBe('MISSING_AUTH');
      });

      it('rejects request with Authorization header missing Bearer prefix', async () => {
        const res = await request(app)
          .get('/api/analytics/periods')
          .set('Authorization', 'dXNlcjpwYXNz')
          .set('x-business-id', OWNER_BUSINESS.id);

        expect(res.status).toBe(401);
        expect(res.body.code).toBe('MISSING_AUTH');
      });
    });

    describe('401 INVALID_TOKEN', () => {
      it('rejects request with invalid JWT token', async () => {
        vi.spyOn(jwt, 'verifyToken').mockReturnValue(null);
        const res = await request(app)
          .get('/api/analytics/periods')
          .set('Authorization', 'Bearer invalid-token')
          .set('x-business-id', OWNER_BUSINESS.id);

        expect(res.status).toBe(401);
        expect(res.body.code).toBe('INVALID_TOKEN');
        expect(res.body.error).toContain('Invalid authentication');
      });

      it('rejects request when token user not found in database', async () => {
        vi.spyOn(jwt, 'verifyToken').mockReturnValue({
          userId: 'deleted-user',
          email: 'deleted@example.com',
        });
        vi.spyOn(userRepository, 'findUserById').mockResolvedValue(null);

        const res = await request(app)
          .get('/api/analytics/periods')
          .set('Authorization', 'Bearer valid-token-for-deleted-user')
          .set('x-business-id', OWNER_BUSINESS.id);

        expect(res.status).toBe(401);
        expect(res.body.code).toBe('INVALID_TOKEN');
      });

      it('rejects request when verifyToken throws (corrupted token)', async () => {
        vi.spyOn(jwt, 'verifyToken').mockImplementation(() => {
          throw new Error('Token signature invalid');
        });
        const res = await request(app)
          .get('/api/analytics/periods')
          .set('Authorization', 'Bearer corrupted-token')
          .set('x-business-id', OWNER_BUSINESS.id);

        expect(res.status).toBe(401);
        expect(res.body.code).toBe('INVALID_TOKEN');
      });

      it('rejects request when findUserById throws (database error)', async () => {
        vi.spyOn(jwt, 'verifyToken').mockReturnValue({
          userId: OWNER_USER.id,
          email: OWNER_USER.email,
        });
        vi.spyOn(userRepository, 'findUserById').mockRejectedValue(
          new Error('Database connection lost'),
        );

        const res = await request(app)
          .get('/api/analytics/periods')
          .set('Authorization', 'Bearer valid-token')
          .set('x-business-id', OWNER_BUSINESS.id);

        expect(res.status).toBe(401);
        expect(res.body.code).toBe('INVALID_TOKEN');
      });
    });

    describe('400 MISSING_BUSINESS_ID', () => {
      it('rejects request without business context', async () => {
        setupMocksForOwner();
        const res = await request(app)
          .get('/api/analytics/periods')
          .set('Authorization', 'Bearer valid-token');

        expect(res.status).toBe(400);
        expect(res.body.code).toBe('MISSING_BUSINESS_ID');
        expect(res.body.error).toContain('Business context required');
      });

      it('rejects request with invalid business ID format in header', async () => {
        setupMocksForOwner();
        const res = await request(app)
          .get('/api/analytics/periods')
          .set('Authorization', 'Bearer valid-token')
          .set('x-business-id', 'invalid@id!');

        expect(res.status).toBe(400);
        expect(res.body.code).toBe('MISSING_BUSINESS_ID');
      });

      it('rejects request with empty business ID in header', async () => {
        setupMocksForOwner();
        const res = await request(app)
          .get('/api/analytics/periods')
          .set('Authorization', 'Bearer valid-token')
          .set('x-business-id', '   ');

        expect(res.status).toBe(400);
        expect(res.body.code).toBe('MISSING_BUSINESS_ID');
      });

      it('rejects request with business ID exceeding max length in header', async () => {
        setupMocksForOwner();
        const longId = 'a'.repeat(51);
        const res = await request(app)
          .get('/api/analytics/periods')
          .set('Authorization', 'Bearer valid-token')
          .set('x-business-id', longId);

        expect(res.status).toBe(400);
        expect(res.body.code).toBe('MISSING_BUSINESS_ID');
      });

      it('accepts valid business ID from x-business-id header', async () => {
        setupMocksForOwner();
        const res = await request(app)
          .get('/api/analytics/periods')
          .set('Authorization', 'Bearer valid-token')
          .set('x-business-id', OWNER_BUSINESS.id);

        expect(res.status).toBe(200);
        expect(res.body.periods).toBeDefined();
      });

      it('accepts business ID from request body field business_id', async () => {
        setupMocksForOwner();
        const res = await request(app)
          .get('/api/analytics/periods')
          .set('Authorization', 'Bearer valid-token')
          .send({ business_id: OWNER_BUSINESS.id });

        expect(res.status).toBe(200);
        expect(res.body.periods).toBeDefined();
      });

      it('accepts business ID from request body field businessId', async () => {
        setupMocksForOwner();
        const res = await request(app)
          .get('/api/analytics/periods')
          .set('Authorization', 'Bearer valid-token')
          .send({ businessId: OWNER_BUSINESS.id });

        expect(res.status).toBe(200);
        expect(res.body.periods).toBeDefined();
      });

      it('prioritizes x-business-id header over body fields', async () => {
        setupMocksForOwner();
        vi.spyOn(businessRepo.businessRepository, 'getById').mockImplementation(async (id: string) => {
          if (id === OWNER_BUSINESS.id) return OWNER_BUSINESS as any;
          if (id === 'other-id') return null;
          return null;
        });

        const res = await request(app)
          .get('/api/analytics/periods')
          .set('Authorization', 'Bearer valid-token')
          .set('x-business-id', OWNER_BUSINESS.id)
          .send({ business_id: 'other-id' });

        expect(res.status).toBe(200);
        expect(businessRepo.businessRepository.getById).toHaveBeenCalledWith(OWNER_BUSINESS.id);
      });

      it('prioritizes body.business_id over body.businessId', async () => {
        setupMocksForOwner();
        vi.spyOn(businessRepo.businessRepository, 'getById').mockImplementation(async (id: string) => {
          if (id === OWNER_BUSINESS.id) return OWNER_BUSINESS as any;
          if (id === 'other-id') return null;
          return null;
        });

        const res = await request(app)
          .get('/api/analytics/periods')
          .set('Authorization', 'Bearer valid-token')
          .send({ business_id: OWNER_BUSINESS.id, businessId: 'other-id' });

        expect(res.status).toBe(200);
        expect(businessRepo.businessRepository.getById).toHaveBeenCalledWith(OWNER_BUSINESS.id);
      });
    });

    describe('403 BUSINESS_NOT_FOUND', () => {
      it('rejects request for non-existent business', async () => {
        setupMocksForOwner();
        vi.spyOn(businessRepo.businessRepository, 'getById').mockResolvedValue(null);

        const res = await request(app)
          .get('/api/analytics/periods')
          .set('Authorization', 'Bearer valid-token')
          .set('x-business-id', 'non-existent-id');

        expect(res.status).toBe(403);
        expect(res.body.code).toBe('BUSINESS_NOT_FOUND');
        expect(res.body.error).toContain('Business access denied');
      });

      it('rejects request for business owned by different user (cross-tenant)', async () => {
        setupMocksForOtherUser();
        const res = await request(app)
          .get('/api/analytics/periods')
          .set('Authorization', 'Bearer token-for-other-user')
          .set('x-business-id', OWNER_BUSINESS.id);

        expect(res.status).toBe(403);
        expect(res.body.code).toBe('BUSINESS_NOT_FOUND');
        expect(res.body.error).toContain('access denied');
      });

      it('rejects request when businessRepository.getById throws', async () => {
        setupMocksForOwner();
        vi.spyOn(businessRepo.businessRepository, 'getById').mockRejectedValue(
          new Error('Database error'),
        );

        const res = await request(app)
          .get('/api/analytics/periods')
          .set('Authorization', 'Bearer valid-token')
          .set('x-business-id', OWNER_BUSINESS.id);

        expect(res.status).toBe(403);
        expect(res.body.code).toBe('BUSINESS_NOT_FOUND');
      });
    });

    describe('403 BUSINESS_SUSPENDED', () => {
      it('rejects request for suspended business with 403 BUSINESS_SUSPENDED', async () => {
        setupMocksForSuspendedBusiness();
        const res = await request(app)
          .get('/api/analytics/periods')
          .set('Authorization', 'Bearer valid-token')
          .set('x-business-id', SUSPENDED_BUSINESS.id);

        expect(res.status).toBe(403);
        expect(res.body.code).toBe('BUSINESS_SUSPENDED');
        expect(res.body.error).toContain('Business suspended');
      });

      it('does not attempt to fetch analytics for suspended business', async () => {
        setupMocksForSuspendedBusiness();
        const listSpy = vi.spyOn(analyticsService, 'listAttestedPeriodsForBusiness');

        const res = await request(app)
          .get('/api/analytics/periods')
          .set('Authorization', 'Bearer valid-token')
          .set('x-business-id', SUSPENDED_BUSINESS.id);

        expect(res.status).toBe(403);
        expect(listSpy).not.toHaveBeenCalled();
      });
    });

    describe('200 Success Cases', () => {
      it('returns 200 with periods for valid business owner', async () => {
        setupMocksForOwner();
        const res = await request(app)
          .get('/api/analytics/periods')
          .set('Authorization', 'Bearer valid-token')
          .set('x-business-id', OWNER_BUSINESS.id);

        expect(res.status).toBe(200);
        expect(res.body).toHaveProperty('periods');
        expect(Array.isArray(res.body.periods)).toBe(true);
      });

      it('attaches req.user and req.business for valid owner', async () => {
        setupMocksForOwner();
        const getByIdSpy = vi.spyOn(businessRepo.businessRepository, 'getById');

        const res = await request(app)
          .get('/api/analytics/periods')
          .set('Authorization', 'Bearer valid-token')
          .set('x-business-id', OWNER_BUSINESS.id);

        expect(res.status).toBe(200);
        expect(getByIdSpy).toHaveBeenCalledWith(OWNER_BUSINESS.id);
      });
    });
  });

  describe('GET /api/analytics/revenue', () => {
    describe('401 MISSING_AUTH', () => {
      it('rejects request without Authorization header', async () => {
        const res = await request(app)
          .get('/api/analytics/revenue?period=2025-01')
          .set('x-business-id', OWNER_BUSINESS.id);

        expect(res.status).toBe(401);
        expect(res.body.code).toBe('MISSING_AUTH');
      });

      it('rejects request with malformed Authorization header', async () => {
        const res = await request(app)
          .get('/api/analytics/revenue?period=2025-01')
          .set('Authorization', 'Bearer')
          .set('x-business-id', OWNER_BUSINESS.id);

        expect(res.status).toBe(401);
        expect(res.body.code).toBe('MISSING_AUTH');
      });
    });

    describe('401 INVALID_TOKEN', () => {
      it('rejects request with expired token', async () => {
        vi.spyOn(jwt, 'verifyToken').mockReturnValue(null);
        const res = await request(app)
          .get('/api/analytics/revenue?period=2025-01')
          .set('Authorization', 'Bearer expired-token')
          .set('x-business-id', OWNER_BUSINESS.id);

        expect(res.status).toBe(401);
        expect(res.body.code).toBe('INVALID_TOKEN');
      });

      it('rejects request when token user not found', async () => {
        vi.spyOn(jwt, 'verifyToken').mockReturnValue({
          userId: 'deleted-user',
          email: 'deleted@example.com',
        });
        vi.spyOn(userRepository, 'findUserById').mockResolvedValue(null);

        const res = await request(app)
          .get('/api/analytics/revenue?period=2025-01')
          .set('Authorization', 'Bearer valid-token')
          .set('x-business-id', OWNER_BUSINESS.id);

        expect(res.status).toBe(401);
        expect(res.body.code).toBe('INVALID_TOKEN');
      });
    });

    describe('400 MISSING_BUSINESS_ID', () => {
      it('rejects request without business context', async () => {
        setupMocksForOwner();
        const res = await request(app)
          .get('/api/analytics/revenue?period=2025-01')
          .set('Authorization', 'Bearer valid-token');

        expect(res.status).toBe(400);
        expect(res.body.code).toBe('MISSING_BUSINESS_ID');
      });

      it('rejects request with invalid business ID format', async () => {
        setupMocksForOwner();
        const res = await request(app)
          .get('/api/analytics/revenue?period=2025-01')
          .set('Authorization', 'Bearer valid-token')
          .set('x-business-id', 'invalid!!!id');

        expect(res.status).toBe(400);
        expect(res.body.code).toBe('MISSING_BUSINESS_ID');
      });
    });

    describe('403 BUSINESS_NOT_FOUND', () => {
      it('rejects request for non-existent business', async () => {
        setupMocksForOwner();
        vi.spyOn(businessRepo.businessRepository, 'getById').mockResolvedValue(null);

        const res = await request(app)
          .get('/api/analytics/revenue?period=2025-01')
          .set('Authorization', 'Bearer valid-token')
          .set('x-business-id', 'ghost-business');

        expect(res.status).toBe(403);
        expect(res.body.code).toBe('BUSINESS_NOT_FOUND');
      });

      it('rejects request for cross-tenant access (valid token, different user business)', async () => {
        setupMocksForOtherUser();
        const res = await request(app)
          .get('/api/analytics/revenue?period=2025-01')
          .set('Authorization', 'Bearer token-for-other-user')
          .set('x-business-id', OWNER_BUSINESS.id);

        expect(res.status).toBe(403);
        expect(res.body.code).toBe('BUSINESS_NOT_FOUND');
      });
    });

    describe('403 BUSINESS_SUSPENDED', () => {
      it('rejects request for suspended business', async () => {
        setupMocksForSuspendedBusiness();
        const res = await request(app)
          .get('/api/analytics/revenue?period=2025-01')
          .set('Authorization', 'Bearer valid-token')
          .set('x-business-id', SUSPENDED_BUSINESS.id);

        expect(res.status).toBe(403);
        expect(res.body.code).toBe('BUSINESS_SUSPENDED');
      });
    });

    describe('200 Success Cases', () => {
      it('returns 200 for valid business owner with period param', async () => {
        setupMocksForOwner();
        const res = await request(app)
          .get('/api/analytics/revenue?period=2025-01')
          .set('Authorization', 'Bearer valid-token')
          .set('x-business-id', OWNER_BUSINESS.id);

        expect(res.status).toBe(200);
        expect(res.body).toBeDefined();
      });

      it('returns 200 for valid business owner with range params', async () => {
        setupMocksForOwner();
        const res = await request(app)
          .get('/api/analytics/revenue?from=2024-01&to=2024-12')
          .set('Authorization', 'Bearer valid-token')
          .set('x-business-id', OWNER_BUSINESS.id);

        expect(res.status).toBe(200);
        expect(res.body).toBeDefined();
      });
    });
  });

  describe('Cross-Route Consistency', () => {
    it('both routes return identical 401 MISSING_AUTH error shape', async () => {
      const res1 = await request(app)
        .get('/api/analytics/periods')
        .set('x-business-id', OWNER_BUSINESS.id);

      const res2 = await request(app)
        .get('/api/analytics/revenue?period=2025-01')
        .set('x-business-id', OWNER_BUSINESS.id);

      expect(res1.status).toBe(401);
      expect(res2.status).toBe(401);
      expect(res1.body.code).toBe('MISSING_AUTH');
      expect(res2.body.code).toBe('MISSING_AUTH');
      expect(res1.body.error).toBe(res2.body.error);
    });

    it('both routes return identical 400 MISSING_BUSINESS_ID error shape', async () => {
      setupMocksForOwner();

      const res1 = await request(app)
        .get('/api/analytics/periods')
        .set('Authorization', 'Bearer valid-token');

      const res2 = await request(app)
        .get('/api/analytics/revenue?period=2025-01')
        .set('Authorization', 'Bearer valid-token');

      expect(res1.status).toBe(400);
      expect(res2.status).toBe(400);
      expect(res1.body.code).toBe('MISSING_BUSINESS_ID');
      expect(res2.body.code).toBe('MISSING_BUSINESS_ID');
    });

    it('both routes return identical 401 INVALID_TOKEN error shape', async () => {
      vi.spyOn(jwt, 'verifyToken').mockReturnValue(null);

      const res1 = await request(app)
        .get('/api/analytics/periods')
        .set('Authorization', 'Bearer bad-token')
        .set('x-business-id', OWNER_BUSINESS.id);

      const res2 = await request(app)
        .get('/api/analytics/revenue?period=2025-01')
        .set('Authorization', 'Bearer bad-token')
        .set('x-business-id', OWNER_BUSINESS.id);

      expect(res1.status).toBe(401);
      expect(res2.status).toBe(401);
      expect(res1.body.code).toBe('INVALID_TOKEN');
      expect(res2.body.code).toBe('INVALID_TOKEN');
    });

    it('both routes return identical 403 BUSINESS_NOT_FOUND error shape', async () => {
      setupMocksForOwner();
      vi.spyOn(businessRepo.businessRepository, 'getById').mockResolvedValue(null);

      const res1 = await request(app)
        .get('/api/analytics/periods')
        .set('Authorization', 'Bearer valid-token')
        .set('x-business-id', 'ghost-business');

      const res2 = await request(app)
        .get('/api/analytics/revenue?period=2025-01')
        .set('Authorization', 'Bearer valid-token')
        .set('x-business-id', 'ghost-business');

      expect(res1.status).toBe(403);
      expect(res2.status).toBe(403);
      expect(res1.body.code).toBe('BUSINESS_NOT_FOUND');
      expect(res2.body.code).toBe('BUSINESS_NOT_FOUND');
    });

    it('both routes return identical 403 BUSINESS_SUSPENDED error shape', async () => {
      setupMocksForSuspendedBusiness();

      const res1 = await request(app)
        .get('/api/analytics/periods')
        .set('Authorization', 'Bearer valid-token')
        .set('x-business-id', SUSPENDED_BUSINESS.id);

      const res2 = await request(app)
        .get('/api/analytics/revenue?period=2025-01')
        .set('Authorization', 'Bearer valid-token')
        .set('x-business-id', SUSPENDED_BUSINESS.id);

      expect(res1.status).toBe(403);
      expect(res2.status).toBe(403);
      expect(res1.body.code).toBe('BUSINESS_SUSPENDED');
      expect(res2.body.code).toBe('BUSINESS_SUSPENDED');
    });
  });

  describe('Security Scenarios', () => {
    it('prevents token reuse after user deletion', async () => {
      vi.spyOn(jwt, 'verifyToken').mockReturnValue({
        userId: 'deleted-user',
        email: 'deleted@example.com',
      });
      vi.spyOn(userRepository, 'findUserById').mockResolvedValue(null);

      const res = await request(app)
        .get('/api/analytics/periods')
        .set('Authorization', 'Bearer stale-token')
        .set('x-business-id', OWNER_BUSINESS.id);

      expect(res.status).toBe(401);
      expect(res.body.code).toBe('INVALID_TOKEN');
    });

    it('prevents cross-tenant access with valid token', async () => {
      setupMocksForOtherUser();
      const res = await request(app)
        .get('/api/analytics/periods')
        .set('Authorization', 'Bearer token-for-other-user')
        .set('x-business-id', OWNER_BUSINESS.id);

      expect(res.status).toBe(403);
      expect(res.body.code).toBe('BUSINESS_NOT_FOUND');
    });

    it('prevents access to suspended business even with valid token', async () => {
      setupMocksForSuspendedBusiness();
      const res = await request(app)
        .get('/api/analytics/periods')
        .set('Authorization', 'Bearer valid-token')
        .set('x-business-id', SUSPENDED_BUSINESS.id);

      expect(res.status).toBe(403);
      expect(res.body.code).toBe('BUSINESS_SUSPENDED');
    });

    it('rejects requests with business ID injection attempts', async () => {
      setupMocksForOwner();
      const res = await request(app)
        .get('/api/analytics/periods')
        .set('Authorization', 'Bearer valid-token')
        .set('x-business-id', "biz-1'; DROP TABLE businesses; --");

      expect(res.status).toBe(400);
      expect(res.body.code).toBe('MISSING_BUSINESS_ID');
    });

    it('rejects requests with malformed JSON in headers', async () => {
      setupMocksForOwner();
      const res = await request(app)
        .get('/api/analytics/periods')
        .set('Authorization', 'Bearer valid-token')
        .set('x-business-id', '{"id":"biz-1"}');

      expect(res.status).toBe(400);
      expect(res.body.code).toBe('MISSING_BUSINESS_ID');
    });
  });
});
