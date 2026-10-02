/**
 * Unit tests for requireAuth middleware
 *
 * Covers:
 *  - Valid authentication (token valid, user exists)
 *  - Missing Authorization header
 *  - Invalid/non-Bearer Authorization header
 *  - Invalid/expired JWT token
 *  - User not found after valid token
 *  - req.user attachment on success
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { Request, Response, NextFunction } from 'express';
import { requireAuth } from '../../../src/middleware/requireAuth.js';
import * as jwt from '../../../src/utils/jwt.js';
import * as userRepository from '../../../src/repositories/userRepository.js';

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

const VALID_USER = { id: 'user-1', email: 'a@b.com', role: 'user' as const };

function setupValidAuth() {
  vi.spyOn(jwt, 'verifyToken').mockReturnValue({ userId: 'user-1', email: 'a@b.com' });
  vi.spyOn(userRepository, 'findUserById').mockResolvedValue({ ...VALID_USER, role: 'user' } as any);
}

describe('requireAuth — Authentication Validation', () => {
  beforeEach(() => vi.clearAllMocks());

  it('rejects missing Authorization header with 401', async () => {
    const next = vi.fn();
    const { res, status, json } = makeRes();
    await requireAuth(makeReq(), res, next);
    expect(status).toHaveBeenCalledWith(401);
    expect(json).toHaveBeenCalledWith(expect.objectContaining({ error: 'Missing or invalid authorization header' }));
    expect(next).not.toHaveBeenCalled();
  });

  it('rejects non-Bearer Authorization header with 401', async () => {
    const next = vi.fn();
    const { res, status, json } = makeRes();
    await requireAuth(
      makeReq({ headers: { authorization: 'Basic dXNlcjpwYXNz' } }),
      res, next,
    );
    expect(status).toHaveBeenCalledWith(401);
    expect(json).toHaveBeenCalledWith(expect.objectContaining({ error: 'Missing or invalid authorization header' }));
    expect(next).not.toHaveBeenCalled();
  });

  it('rejects invalid JWT with 401', async () => {
    vi.spyOn(jwt, 'verifyToken').mockReturnValue(null);
    const next = vi.fn();
    const { res, status, json } = makeRes();
    await requireAuth(
      makeReq({ headers: { authorization: 'Bearer bad-token' } }),
      res, next,
    );
    expect(status).toHaveBeenCalledWith(401);
    expect(json).toHaveBeenCalledWith(expect.objectContaining({ error: 'Invalid or expired token' }));
    expect(next).not.toHaveBeenCalled();
  });

  it('rejects when user not found after valid token with 401', async () => {
    vi.spyOn(jwt, 'verifyToken').mockReturnValue({ userId: 'non-existent', email: 'x@y.com' });
    vi.spyOn(userRepository, 'findUserById').mockResolvedValue(null);
    const next = vi.fn();
    const { res, status, json } = makeRes();
    await requireAuth(
      makeReq({ headers: { authorization: 'Bearer stale-token' } }),
      res, next,
    );
    expect(status).toHaveBeenCalledWith(401);
    expect(json).toHaveBeenCalledWith(expect.objectContaining({ error: 'User not found' }));
    expect(next).not.toHaveBeenCalled();
  });
});

describe('requireAuth — Successful Authentication', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    setupValidAuth();
  });

  it('attaches req.user and calls next() on valid auth', async () => {
    const next = vi.fn();
    const req = makeReq({ headers: { authorization: 'Bearer valid-token' } });
    const { res } = makeRes();
    await requireAuth(req, res, next);
    expect(next).toHaveBeenCalled();
    expect(req.user).toEqual({
      id: 'user-1',
      userId: 'user-1',
      email: 'a@b.com',
      role: 'user',
    });
  });

  it('attaches req.user with correct shape on valid auth', async () => {
    const next = vi.fn();
    const req = makeReq({ headers: { authorization: 'Bearer valid-token' } });
    const { res } = makeRes();
    await requireAuth(req, res, next);
    expect(next).toHaveBeenCalled();
    const user = req.user;
    expect(user).toHaveProperty('id');
    expect(user).toHaveProperty('userId');
    expect(user).toHaveProperty('email');
    expect(user).toHaveProperty('role');
  });
});