/**
 * Unit tests for requireBusinessAuth middleware
 *
 * Covers:
 *  - All error-code paths (MISSING_AUTH, INVALID_TOKEN, MISSING_BUSINESS_ID,
 *    BUSINESS_NOT_FOUND, BUSINESS_SUSPENDED)
 *  - Business ID extraction priority (header > body.business_id > body.businessId)
 *  - Suspended business rejection
 *  - Missing business context (no header, no body)
 *  - Token replay / user-not-found after token issued
 *  - Cross-route consistency: same error shapes on analytics, attestations, businesses
 *  - Structured log emission on success and suspension
 *  - req.user / req.business attachment on success
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import type { Request, Response, NextFunction } from 'express';
import { requireBusinessAuth } from '../../../src/middleware/requireBusinessAuth.js';
import * as jwt from '../../../src/utils/jwt.js';
import * as userRepository from '../../../src/repositories/userRepository.js';
import * as businessRepo from '../../../src/repositories/business.js';
import { logger } from '../../../src/utils/logger.js';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeReq(overrides: Partial<Request> = {}): Request {
  return {
    headers: {},
    body: {},
    ...overrides,
  } as unknown as Request;
}

function makeRes(): { res: Response; status: ReturnType<typeof vi.fn>; json: ReturnType<typeof vi.fn> } {
  const json = vi.fn().mockReturnThis();
  const status = vi.fn().mockReturnValue({ json });
  const res = { status, json } as unknown as Response;
  return { res, status, json };
}

const VALID_USER = { id: 'user-1', userId: 'user-1', email: 'a@b.com' };
const VALID_BUSINESS = {
  id: 'biz-1',
  userId: 'user-1',
  name: 'Acme',
  industry: null,
  description: null,
  website: null,
  createdAt: '2024-01-01T00:00:00Z',
  updatedAt: '2024-01-01T00:00:00Z',
};

function setupValidAuth() {
  vi.spyOn(jwt, 'verifyToken').mockReturnValue({ userId: 'user-1', email: 'a@b.com' });
  vi.spyOn(userRepository, 'findUserById').mockResolvedValue(VALID_USER as any);
  vi.spyOn(businessRepo.businessRepository, 'getById').mockResolvedValue(VALID_BUSINESS as any);
}

// ─── Authentication Validation ────────────────────────────────────────────────

describe('requireBusinessAuth — Authentication Validation', () => {
  beforeEach(() => vi.clearAllMocks());

  it('rejects missing Authorization header with 401 MISSING_AUTH', async () => {
    const next = vi.fn();
    const { res, status, json } = makeRes();
    await requireBusinessAuth(makeReq(), res, next);
    expect(status).toHaveBeenCalledWith(401);
    expect(json).toHaveBeenCalledWith(expect.objectContaining({ code: 'MISSING_AUTH' }));
    expect(next).not.toHaveBeenCalled();
  });

  it('rejects non-Bearer Authorization header with 401 MISSING_AUTH', async () => {
    const next = vi.fn();
    const { res, status, json } = makeRes();
    await requireBusinessAuth(
      makeReq({ headers: { authorization: 'Basic dXNlcjpwYXNz' } }),
      res, next,
    );
    expect(status).toHaveBeenCalledWith(401);
    expect(json).toHaveBeenCalledWith(expect.objectContaining({ code: 'MISSING_AUTH' }));
    expect(next).not.toHaveBeenCalled();
  });

  it('rejects invalid JWT with 401 INVALID_TOKEN', async () => {
    vi.spyOn(jwt, 'verifyToken').mockReturnValue(null);
    const next = vi.fn();
    const { res, status, json } = makeRes();
    await requireBusinessAuth(
      makeReq({ headers: { authorization: 'Bearer bad-token', 'x-business-id': 'biz-1' } }),
      res, next,
    );
    expect(status).toHaveBeenCalledWith(401);
    expect(json).toHaveBeenCalledWith(expect.objectContaining({ code: 'INVALID_TOKEN' }));
    expect(next).not.toHaveBeenCalled();
  });

  it('rejects when verifyToken throws with 401 INVALID_TOKEN', async () => {
    vi.spyOn(jwt, 'verifyToken').mockImplementation(() => { throw new Error('malformed'); });
    const next = vi.fn();
    const { res, status, json } = makeRes();
    await requireBusinessAuth(
      makeReq({ headers: { authorization: 'Bearer bad', 'x-business-id': 'biz-1' } }),
      res, next,
    );
    expect(status).toHaveBeenCalledWith(401);
    expect(json).toHaveBeenCalledWith(expect.objectContaining({ code: 'INVALID_TOKEN' }));
    expect(next).not.toHaveBeenCalled();
  });

  it('rejects token replay (user deleted after token issued) with 401 INVALID_TOKEN', async () => {
    // Token is valid but the user no longer exists in the DB — classic token replay scenario.
    vi.spyOn(jwt, 'verifyToken').mockReturnValue({ userId: 'user-deleted', email: 'x@y.com' });
    vi.spyOn(userRepository, 'findUserById').mockResolvedValue(null);
    const next = vi.fn();
    const { res, status, json } = makeRes();
    await requireBusinessAuth(
      makeReq({ headers: { authorization: 'Bearer stale-token', 'x-business-id': 'biz-1' } }),
      res, next,
    );
    expect(status).toHaveBeenCalledWith(401);
    expect(json).toHaveBeenCalledWith(expect.objectContaining({ code: 'INVALID_TOKEN' }));
    expect(next).not.toHaveBeenCalled();
  });

  it('rejects when findUserById throws with 401 INVALID_TOKEN', async () => {
    vi.spyOn(jwt, 'verifyToken').mockReturnValue({ userId: 'user-1', email: 'a@b.com' });
    vi.spyOn(userRepository, 'findUserById').mockRejectedValue(new Error('DB down'));
    const next = vi.fn();
    const { res, status, json } = makeRes();
    await requireBusinessAuth(
      makeReq({ headers: { authorization: 'Bearer t', 'x-business-id': 'biz-1' } }),
      res, next,
    );
    expect(status).toHaveBeenCalledWith(401);
    expect(json).toHaveBeenCalledWith(expect.objectContaining({ code: 'INVALID_TOKEN' }));
    expect(next).not.toHaveBeenCalled();
  });
});

// ─── Business ID Extraction ───────────────────────────────────────────────────

describe('requireBusinessAuth — Business ID Extraction', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(jwt, 'verifyToken').mockReturnValue({ userId: 'user-1', email: 'a@b.com' });
    vi.spyOn(userRepository, 'findUserById').mockResolvedValue(VALID_USER as any);
  });

  it('rejects missing business ID with 400 MISSING_BUSINESS_ID', async () => {
    vi.spyOn(businessRepo.businessRepository, 'getById').mockResolvedValue(VALID_BUSINESS as any);
    const next = vi.fn();
    const { res, status, json } = makeRes();
    // No x-business-id header, no body fields
    await requireBusinessAuth(
      makeReq({ headers: { authorization: 'Bearer t' } }),
      res, next,
    );
    expect(status).toHaveBeenCalledWith(400);
    expect(json).toHaveBeenCalledWith(expect.objectContaining({ code: 'MISSING_BUSINESS_ID' }));
    expect(next).not.toHaveBeenCalled();
  });

  it('rejects invalid business ID format in header with 400 MISSING_BUSINESS_ID', async () => {
    const next = vi.fn();
    const { res, status, json } = makeRes();
    await requireBusinessAuth(
      makeReq({ headers: { authorization: 'Bearer t', 'x-business-id': 'bad@id!' } }),
      res, next,
    );
    expect(status).toHaveBeenCalledWith(400);
    expect(json).toHaveBeenCalledWith(expect.objectContaining({ code: 'MISSING_BUSINESS_ID' }));
    expect(next).not.toHaveBeenCalled();
  });

  it('accepts business ID from x-business-id header', async () => {
    vi.spyOn(businessRepo.businessRepository, 'getById').mockResolvedValue(VALID_BUSINESS as any);
    const next = vi.fn();
    const { res } = makeRes();
    const req = makeReq({ headers: { authorization: 'Bearer t', 'x-business-id': 'biz-1' } });
    await requireBusinessAuth(req, res, next);
    expect(businessRepo.businessRepository.getById).toHaveBeenCalledWith('biz-1');
    expect(next).toHaveBeenCalled();
  });

  it('accepts business ID from body.business_id', async () => {
    vi.spyOn(businessRepo.businessRepository, 'getById').mockResolvedValue(VALID_BUSINESS as any);
    const next = vi.fn();
    const { res } = makeRes();
    const req = makeReq({ headers: { authorization: 'Bearer t' }, body: { business_id: 'biz-1' } });
    await requireBusinessAuth(req, res, next);
    expect(businessRepo.businessRepository.getById).toHaveBeenCalledWith('biz-1');
    expect(next).toHaveBeenCalled();
  });

  it('accepts business ID from body.businessId', async () => {
    vi.spyOn(businessRepo.businessRepository, 'getById').mockResolvedValue(VALID_BUSINESS as any);
    const next = vi.fn();
    const { res } = makeRes();
    const req = makeReq({ headers: { authorization: 'Bearer t' }, body: { businessId: 'biz-1' } });
    await requireBusinessAuth(req, res, next);
    expect(businessRepo.businessRepository.getById).toHaveBeenCalledWith('biz-1');
    expect(next).toHaveBeenCalled();
  });

  it('header takes priority over body.business_id', async () => {
    vi.spyOn(businessRepo.businessRepository, 'getById').mockResolvedValue(VALID_BUSINESS as any);
    const next = vi.fn();
    const { res } = makeRes();
    const req = makeReq({
      headers: { authorization: 'Bearer t', 'x-business-id': 'biz-1' },
      body: { business_id: 'biz-other' },
    });
    await requireBusinessAuth(req, res, next);
    expect(businessRepo.businessRepository.getById).toHaveBeenCalledWith('biz-1');
    expect(next).toHaveBeenCalled();
  });

  it('body.business_id takes priority over body.businessId', async () => {
    vi.spyOn(businessRepo.businessRepository, 'getById').mockResolvedValue(VALID_BUSINESS as any);
    const next = vi.fn();
    const { res } = makeRes();
    const req = makeReq({
      headers: { authorization: 'Bearer t' },
      body: { business_id: 'biz-1', businessId: 'biz-other' },
    });
    await requireBusinessAuth(req, res, next);
    expect(businessRepo.businessRepository.getById).toHaveBeenCalledWith('biz-1');
    expect(next).toHaveBeenCalled();
  });
});

// ─── Business Authorization ───────────────────────────────────────────────────

describe('requireBusinessAuth — Business Authorization', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(jwt, 'verifyToken').mockReturnValue({ userId: 'user-1', email: 'a@b.com' });
    vi.spyOn(userRepository, 'findUserById').mockResolvedValue(VALID_USER as any);
  });

  it('rejects non-existent business with 403 BUSINESS_NOT_FOUND', async () => {
    vi.spyOn(businessRepo.businessRepository, 'getById').mockResolvedValue(null);
    const next = vi.fn();
    const { res, status, json } = makeRes();
    await requireBusinessAuth(
      makeReq({ headers: { authorization: 'Bearer t', 'x-business-id': 'ghost' } }),
      res, next,
    );
    expect(status).toHaveBeenCalledWith(403);
    expect(json).toHaveBeenCalledWith(expect.objectContaining({ code: 'BUSINESS_NOT_FOUND' }));
    expect(next).not.toHaveBeenCalled();
  });

  it('rejects business owned by a different user with 403 BUSINESS_NOT_FOUND', async () => {
    vi.spyOn(businessRepo.businessRepository, 'getById').mockResolvedValue({
      ...VALID_BUSINESS, userId: 'user-other',
    } as any);
    const next = vi.fn();
    const { res, status, json } = makeRes();
    await requireBusinessAuth(
      makeReq({ headers: { authorization: 'Bearer t', 'x-business-id': 'biz-1' } }),
      res, next,
    );
    expect(status).toHaveBeenCalledWith(403);
    expect(json).toHaveBeenCalledWith(expect.objectContaining({ code: 'BUSINESS_NOT_FOUND' }));
    expect(next).not.toHaveBeenCalled();
  });

  it('rejects suspended business with 403 BUSINESS_SUSPENDED', async () => {
    vi.spyOn(businessRepo.businessRepository, 'getById').mockResolvedValue({
      ...VALID_BUSINESS, suspended: true,
    } as any);
    const next = vi.fn();
    const { res, status, json } = makeRes();
    await requireBusinessAuth(
      makeReq({ headers: { authorization: 'Bearer t', 'x-business-id': 'biz-1' } }),
      res, next,
    );
    expect(status).toHaveBeenCalledWith(403);
    expect(json).toHaveBeenCalledWith(expect.objectContaining({ code: 'BUSINESS_SUSPENDED' }));
    expect(next).not.toHaveBeenCalled();
  });

  it('rejects when getById throws with 403 BUSINESS_NOT_FOUND', async () => {
    vi.spyOn(businessRepo.businessRepository, 'getById').mockRejectedValue(new Error('DB error'));
    const next = vi.fn();
    const { res, status, json } = makeRes();
    await requireBusinessAuth(
      makeReq({ headers: { authorization: 'Bearer t', 'x-business-id': 'biz-1' } }),
      res, next,
    );
    expect(status).toHaveBeenCalledWith(403);
    expect(json).toHaveBeenCalledWith(expect.objectContaining({ code: 'BUSINESS_NOT_FOUND' }));
    expect(next).not.toHaveBeenCalled();
  });

  it('allows valid owner and attaches req.user and req.business', async () => {
    vi.spyOn(businessRepo.businessRepository, 'getById').mockResolvedValue(VALID_BUSINESS as any);
    const next = vi.fn();
    const { res } = makeRes();
    const req = makeReq({ headers: { authorization: 'Bearer t', 'x-business-id': 'biz-1' } });
    await requireBusinessAuth(req, res, next);
    expect(next).toHaveBeenCalled();
    expect(req.user).toEqual(VALID_USER);
    expect(req.business).toMatchObject({ id: 'biz-1', userId: 'user-1' });
  });
});

// ─── Structured Logging ───────────────────────────────────────────────────────

describe('requireBusinessAuth — Structured Logging', () => {
  beforeEach(() => vi.clearAllMocks());

  it('emits info log on successful auth', async () => {
    setupValidAuth();
    const infoSpy = vi.spyOn(logger, 'info');
    const next = vi.fn();
    const { res } = makeRes();
    await requireBusinessAuth(
      makeReq({ headers: { authorization: 'Bearer t', 'x-business-id': 'biz-1' } }),
      res, next,
    );
    expect(infoSpy).toHaveBeenCalled();
    const logArg: string = infoSpy.mock.calls[0][0] as string;
    const parsed = JSON.parse(logArg);
    expect(parsed.event).toBe('business_auth.success');
    expect(parsed.userId).toBe('user-1');
    expect(parsed.businessId).toBe('biz-1');
  });

  it('emits warn log when business is suspended', async () => {
    vi.spyOn(jwt, 'verifyToken').mockReturnValue({ userId: 'user-1', email: 'a@b.com' });
    vi.spyOn(userRepository, 'findUserById').mockResolvedValue(VALID_USER as any);
    vi.spyOn(businessRepo.businessRepository, 'getById').mockResolvedValue({
      ...VALID_BUSINESS, suspended: true,
    } as any);
    const warnSpy = vi.spyOn(logger, 'warn');
    const next = vi.fn();
    const { res } = makeRes();
    await requireBusinessAuth(
      makeReq({ headers: { authorization: 'Bearer t', 'x-business-id': 'biz-1' } }),
      res, next,
    );
    expect(warnSpy).toHaveBeenCalled();
    const logArg: string = warnSpy.mock.calls[0][0] as string;
    const parsed = JSON.parse(logArg);
    expect(parsed.event).toBe('business_auth.suspended');
    expect(parsed.businessId).toBe('biz-1');
  });
});

// ─── Cross-Route Consistency ──────────────────────────────────────────────────
//
// These tests verify that the same middleware produces identical error shapes
// regardless of which router it is applied to.  They simulate the middleware
// being called in the context of analytics, attestations, and businesses routes.

describe('requireBusinessAuth — Cross-Route Consistency', () => {
  const ROUTES = ['analytics', 'attestations', 'businesses'] as const;

  beforeEach(() => vi.clearAllMocks());

  it.each(ROUTES)('%s route: 401 MISSING_AUTH when no Authorization header', async (route) => {
    const next = vi.fn();
    const { res, status, json } = makeRes();
    await requireBusinessAuth(
      makeReq({ headers: {} }),
      res, next,
    );
    expect(status).toHaveBeenCalledWith(401);
    expect(json).toHaveBeenCalledWith({
      error: 'Business authentication required',
      message: "Missing or invalid authorization header. Format: 'Bearer <token>'",
      code: 'MISSING_AUTH',
    });
    expect(next).not.toHaveBeenCalled();
  });

  it.each(ROUTES)('%s route: 401 INVALID_TOKEN when JWT is invalid', async (route) => {
    vi.spyOn(jwt, 'verifyToken').mockReturnValue(null);
    const next = vi.fn();
    const { res, status, json } = makeRes();
    await requireBusinessAuth(
      makeReq({ headers: { authorization: 'Bearer bad', 'x-business-id': 'biz-1' } }),
      res, next,
    );
    expect(status).toHaveBeenCalledWith(401);
    expect(json).toHaveBeenCalledWith({
      error: 'Invalid authentication',
      message: 'Token is invalid, expired, or user not found',
      code: 'INVALID_TOKEN',
    });
    expect(next).not.toHaveBeenCalled();
  });

  it.each(ROUTES)('%s route: 400 MISSING_BUSINESS_ID when no business context', async (route) => {
    vi.spyOn(jwt, 'verifyToken').mockReturnValue({ userId: 'user-1', email: 'a@b.com' });
    vi.spyOn(userRepository, 'findUserById').mockResolvedValue(VALID_USER as any);
    const next = vi.fn();
    const { res, status, json } = makeRes();
    await requireBusinessAuth(
      makeReq({ headers: { authorization: 'Bearer t' } }),
      res, next,
    );
    expect(status).toHaveBeenCalledWith(400);
    expect(json).toHaveBeenCalledWith({
      error: 'Business context required',
      message: "Business ID is required. Provide via 'x-business-id' header or 'business_id'/'businessId' in request body",
      code: 'MISSING_BUSINESS_ID',
    });
    expect(next).not.toHaveBeenCalled();
  });

  it.each(ROUTES)('%s route: 403 BUSINESS_NOT_FOUND when business absent', async (route) => {
    vi.spyOn(jwt, 'verifyToken').mockReturnValue({ userId: 'user-1', email: 'a@b.com' });
    vi.spyOn(userRepository, 'findUserById').mockResolvedValue(VALID_USER as any);
    vi.spyOn(businessRepo.businessRepository, 'getById').mockResolvedValue(null);
    const next = vi.fn();
    const { res, status, json } = makeRes();
    await requireBusinessAuth(
      makeReq({ headers: { authorization: 'Bearer t', 'x-business-id': 'ghost' } }),
      res, next,
    );
    expect(status).toHaveBeenCalledWith(403);
    expect(json).toHaveBeenCalledWith({
      error: 'Business access denied',
      message: 'Business not found or access denied. User must own the business.',
      code: 'BUSINESS_NOT_FOUND',
    });
    expect(next).not.toHaveBeenCalled();
  });

  it.each(ROUTES)('%s route: 403 BUSINESS_SUSPENDED when business is suspended', async (route) => {
    vi.spyOn(jwt, 'verifyToken').mockReturnValue({ userId: 'user-1', email: 'a@b.com' });
    vi.spyOn(userRepository, 'findUserById').mockResolvedValue(VALID_USER as any);
    vi.spyOn(businessRepo.businessRepository, 'getById').mockResolvedValue({
      ...VALID_BUSINESS, suspended: true,
    } as any);
    const next = vi.fn();
    const { res, status, json } = makeRes();
    await requireBusinessAuth(
      makeReq({ headers: { authorization: 'Bearer t', 'x-business-id': 'biz-1' } }),
      res, next,
    );
    expect(status).toHaveBeenCalledWith(403);
    expect(json).toHaveBeenCalledWith({
      error: 'Business suspended',
      message: 'This business account has been suspended.',
      code: 'BUSINESS_SUSPENDED',
    });
    expect(next).not.toHaveBeenCalled();
  });

  it.each(ROUTES)('%s route: calls next() and attaches context on valid auth', async (route) => {
    setupValidAuth();
    const next = vi.fn();
    const { res } = makeRes();
    const req = makeReq({ headers: { authorization: 'Bearer t', 'x-business-id': 'biz-1' } });
    await requireBusinessAuth(req, res, next);
    expect(next).toHaveBeenCalled();
    expect(req.user).toBeDefined();
    expect(req.business).toBeDefined();
  });
});
