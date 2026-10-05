/**
 * Unit tests for `src/middleware/auth.ts` → `requireAuth`.
 *
 * This is the header-based guard (it reads the `x-user-id` request header) that
 * `src/routes/attestations.ts`, `src/routes/businesses.ts` and
 * `src/routes/integrations.ts` mount on their protected routers. It is the only
 * `requireAuth` in the tree that does not touch the JWT/DB path (see
 * `src/middleware/requireAuth.ts` for that variant), so this suite pins its
 * contract in isolation.
 *
 * Covers:
 *  - Success path: identity attachment (`id`/`userId`/`email`), `next()` shape,
 *    no response mutation, fully synchronous execution.
 *  - Representative invalid inputs: missing headers, missing/empty/undefined
 *    header, and a valid `Authorization` header that must *not* satisfy the
 *    guard.
 *  - Primary state transitions: overwriting stale `req.user`, leaving it
 *    untouched on failure, per-request object identity.
 *  - Error/boundary determinism: `AuthenticationError` shape (401 / VRT-0001),
 *    `next` arity, repeatability, and the real global `errorHandler` envelope.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import type { Request, Response, NextFunction } from 'express';
import { requireAuth } from '../../../src/middleware/auth.js';
import { errorHandler } from '../../../src/middleware/errorHandler.js';
import {
  AppError,
  AuthenticationError,
  VRTErrorCodes,
} from '../../../src/types/errors.js';
import { logger } from '../../../src/utils/logger.js';

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Build a minimal Express request carrying the supplied headers. */
function makeReq(headers: Record<string, unknown> = {}): Request {
  return { headers } as unknown as Request;
}

/** Build a response double whose status/json calls are observable. */
function makeRes(): {
  res: Response;
  status: ReturnType<typeof vi.fn>;
  json: ReturnType<typeof vi.fn>;
} {
  const json = vi.fn().mockReturnThis();
  const status = vi.fn().mockReturnValue({ json });
  const res = { status, json, locals: {} } as unknown as Response;
  return { res, status, json };
}

type NextSpy = ReturnType<typeof vi.fn>;

function makeNext(): NextSpy {
  return vi.fn();
}

const USER_ID = 'user_5f3a1c';
const EXPECTED_USER = { id: USER_ID, userId: USER_ID, email: '' };

/**
 * Assert the observable `AuthenticationError` contract.
 *
 * Note: `AppError`'s base constructor calls `Object.setPrototypeOf(this, AppError.prototype)`,
 * which detaches subclass prototypes, so `instanceof AuthenticationError` is false at runtime
 * even though the instance is a well-formed `AppError` with `name === 'AuthenticationError'`.
 * We therefore assert the fields downstream consumers (the global error handler) actually read.
 */
function expectAuthError(value: unknown): AuthenticationError {
  expect(value).toBeInstanceOf(AppError);
  const error = value as AuthenticationError;
  expect(error.name).toBe('AuthenticationError');
  expect(error.message).toBe('Authentication required');
  expect(error.status).toBe(401);
  expect(error.vrtCode).toBe(VRTErrorCodes.VRT_0001);
  return error;
}

// ─── Success path ─────────────────────────────────────────────────────────────

describe('requireAuth — success path', () => {
  beforeEach(() => vi.clearAllMocks());

  it('attaches the header identity and keeps the exact user shape', () => {
    const req = makeReq({ 'x-user-id': USER_ID });
    const { res, status, json } = makeRes();
    const next = makeNext();

    requireAuth(req, res, next);

    // Exact shape: adding/removing a field (e.g. role) must fail loudly.
    expect(req.user).toEqual(EXPECTED_USER);
  });

  it('derives `id` and `userId` from the same header value and blanks email', () => {
    const req = makeReq({ 'x-user-id': 'actor-9' });
    const { res } = makeRes();
    const next = makeNext();

    requireAuth(req, res, next);

    expect(req.user?.id).toBe('actor-9');
    expect(req.user?.userId).toBe('actor-9');
    expect(req.user?.email).toBe('');
  });

  it('advances the chain with next() called once and without arguments', () => {
    const req = makeReq({ 'x-user-id': USER_ID });
    const { res } = makeRes();
    const next = makeNext();

    requireAuth(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(next.mock.calls[0]).toHaveLength(0);
  });

  it('does not write to the response on success', () => {
    const req = makeReq({ 'x-user-id': USER_ID });
    const { res, status, json } = makeRes();
    const next = makeNext();

    requireAuth(req, res, next);

    expect(status).not.toHaveBeenCalled();
    expect(json).not.toHaveBeenCalled();
  });

  it('runs synchronously — next() is already settled before the call returns', () => {
    const req = makeReq({ 'x-user-id': USER_ID });
    const { res } = makeRes();
    const next = makeNext();

    const returned = requireAuth(req, res, next);

    expect(returned).toBeUndefined();
    expect(next).toHaveBeenCalledTimes(1);
  });

  it('preserves the header value verbatim, including special characters', () => {
    const rawId = 'tenant:42|user/abc+123';
    const req = makeReq({ 'x-user-id': rawId });
    const { res } = makeRes();
    const next = makeNext();

    requireAuth(req, res, next);

    expect(req.user).toEqual({ id: rawId, userId: rawId, email: '' });
  });

  it('authenticates on x-user-id alone when no Authorization header is present', () => {
    const req = makeReq({ 'x-user-id': USER_ID });
    const { res } = makeRes();
    const next = makeNext();

    requireAuth(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(next.mock.calls[0]).toHaveLength(0);
    expect(req.user?.id).toBe(USER_ID);
  });

  it('does not treat a valid-looking Authorization header as authentication', () => {
    // The JWT-based guard lives in `src/middleware/requireAuth.ts`; this guard is
    // header-based, so a Bearer token without x-user-id must still be rejected.
    const req = makeReq({ authorization: 'Bearer header.payload.signature' });
    const { res } = makeRes();
    const next = makeNext();

    requireAuth(req, res, next);

    expect(req.user).toBeUndefined();
    expect(next).toHaveBeenCalledTimes(1);
    expectAuthError(next.mock.calls[0][0]);
  });
});

// ─── State transitions ────────────────────────────────────────────────────────

describe('requireAuth — state transitions', () => {
  beforeEach(() => vi.clearAllMocks());

  it('overwrites a stale req.user left by an earlier middleware', () => {
    const req = makeReq({ 'x-user-id': 'fresh-user' });
    req.user = { id: 'stale-user', userId: 'stale-user', email: 'stale@x.com' };
    const { res } = makeRes();
    const next = makeNext();

    requireAuth(req, res, next);

    expect(req.user).toEqual({ id: 'fresh-user', userId: 'fresh-user', email: '' });
  });

  it('replaces the identity when the same request is re-processed with a new header', () => {
    const req = makeReq({ 'x-user-id': 'first-user' });
    const { res } = makeRes();
    const next = makeNext();

    requireAuth(req, res, next);
    expect(req.user?.id).toBe('first-user');

    req.headers['x-user-id'] = 'second-user';
    requireAuth(req, res, next);

    expect(req.user).toEqual({ id: 'second-user', userId: 'second-user', email: '' });
    expect(next).toHaveBeenCalledTimes(2);
  });

  it('leaves a pre-existing req.user untouched on the failure path', () => {
    const req = makeReq({});
    const existing = { id: 'prev', userId: 'prev', email: 'prev@x.com' };
    req.user = existing;
    const { res } = makeRes();
    const next = makeNext();

    requireAuth(req, res, next);

    // The guard delegates via next(error); it must not clear or mutate context.
    expect(req.user).toBe(existing);
  });

  it('gives each request an independent user object (no shared reference)', () => {
    const reqA = makeReq({ 'x-user-id': 'user-a' });
    const reqB = makeReq({ 'x-user-id': 'user-b' });
    const res = makeRes().res;
    const next = makeNext();

    requireAuth(reqA, res, next);
    requireAuth(reqB, res, next);

    expect(reqA.user).not.toBe(reqB.user);
    (reqA.user as { email?: string }).email = 'mutated@x.com';
    expect(reqB.user?.email).toBe('');
  });
});

// ─── Invalid inputs ───────────────────────────────────────────────────────────

describe('requireAuth — invalid inputs', () => {
  beforeEach(() => vi.clearAllMocks());

  it.each([
    ['an empty headers object', {} as Record<string, unknown>],
    ['unrelated headers only', { accept: 'application/json' } as Record<string, unknown>],
    ['header explicitly undefined', { 'x-user-id': undefined }],
    ['empty string header', { 'x-user-id': '' }],
  ])('rejects %s with AuthenticationError and does not authenticate', (_label, headers) => {
    const req = makeReq(headers);
    const { res, status, json } = makeRes();
    const next = makeNext();

    requireAuth(req, res, next);

    expect(req.user).toBeUndefined();
    expect(next).toHaveBeenCalledTimes(1);
    expectAuthError(next.mock.calls[0][0]);
    // The error path also must not short-circuit the response itself.
    expect(status).not.toHaveBeenCalled();
    expect(json).not.toHaveBeenCalled();
  });

  it('rejects a whitespace-only header on the failure boundary', () => {
    // Truthiness boundary: '   ' is a truthy string, so the current contract
    // accepts it verbatim. Pinning the behaviour keeps any future hardening
    // (trim / validate) as an explicit, reviewable change.
    const req = makeReq({ 'x-user-id': '   ' });
    const { res } = makeRes();
    const next = makeNext();

    requireAuth(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(next.mock.calls[0]).toHaveLength(0);
    expect(req.user).toEqual({ id: '   ', userId: '   ', email: '' });
  });

  it('rejects a Bearer token when the x-user-id header is absent', () => {
    const req = makeReq({ authorization: 'Bearer a.b.c', accept: 'application/json' });
    const { res } = makeRes();
    const next = makeNext();

    requireAuth(req, res, next);

    expectAuthError(next.mock.calls[0][0]);
    expect(req.user).toBeUndefined();
  });

  it('does not normalise header casing itself (Node lowercases incoming names)', () => {
    // Express/Node expose header names lowercased, so a mixed-case key supplied
    // directly is — and must remain — treated as missing.
    const req = makeReq({ 'X-User-Id': USER_ID });
    const { res } = makeRes();
    const next = makeNext();

    requireAuth(req, res, next);

    expect(req.user).toBeUndefined();
    expectAuthError(next.mock.calls[0][0]);
  });
});

// ─── Error & boundary determinism ─────────────────────────────────────────────

describe('requireAuth — error determinism', () => {
  beforeEach(() => vi.clearAllMocks());

  it('delegates an AuthenticationError carrying the 401 / VRT-0001 taxonomy', () => {
    const req = makeReq({});
    const { res } = makeRes();
    const next = makeNext();

    requireAuth(req, res, next);

    expectAuthError(next.mock.calls[0][0]);
  });

  it('passes exactly one argument to next() on failure', () => {
    const req = makeReq({});
    const { res } = makeRes();
    const next = makeNext();

    requireAuth(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(next.mock.calls[0]).toHaveLength(1);
  });

  it('produces a fresh but equivalent error for every rejected request', () => {
    const { res } = makeRes();
    const next = makeNext();

    requireAuth(makeReq({}), res, next);
    requireAuth(makeReq({ 'x-user-id': '' }), res, next);
    requireAuth(makeReq({ 'x-user-id': undefined } as Record<string, unknown>), res, next);

    const errors = next.mock.calls.map((call) => call[0] as AuthenticationError);
    expect(errors).toHaveLength(3);
    expect(errors[0]).not.toBe(errors[1]);
    for (const error of errors) {
      expect({
        name: error.name,
        message: error.message,
        status: error.status,
        vrtCode: error.vrtCode,
      }).toEqual({
        name: 'AuthenticationError',
        message: 'Authentication required',
        status: 401,
        vrtCode: VRTErrorCodes.VRT_0001,
      });
    }
  });

  it('emits an error the real global errorHandler renders as 401 VRT-0001', () => {
    const errorSpy = vi.spyOn(logger, 'error').mockImplementation(() => {});
    const req = makeReq({});
    const { res, status, json } = makeRes();
    const next = makeNext();

    requireAuth(req, res, next);
    const error = next.mock.calls[0][0];

    // Round-trip through the application's real error middleware.
    errorHandler(error, req, res, next);

    expect(status).toHaveBeenCalledWith(401);
    expect(json).toHaveBeenCalledWith(
      expect.objectContaining({
        status: 'error',
        vrtCode: VRTErrorCodes.VRT_0001,
        message: 'Authentication required',
      }),
    );

    errorSpy.mockRestore();
  });
});
