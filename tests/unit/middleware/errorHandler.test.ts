/**
 * Dedicated behavior coverage for `src/middleware/errorHandler.ts`.
 *
 * Exercises the three exported middleware factories/functions directly with
 * lightweight Express-shaped doubles:
 *
 * - `errorHandler`     — status mapping, VRT-XXXX envelope shape, info-leak masking
 * - `asyncErrorHandler`— promise rejection forwarding (and success pass-through)
 * - `notFoundHandler`  — unmatched-route envelope
 *
 * Error-class construction is already covered by `tests/unit/error-handling.test.ts`;
 * this file focuses on the middleware control flow those classes feed into.
 *
 * @module tests/unit/middleware/errorHandler
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { z } from 'zod';
import type { NextFunction, Request, Response } from 'express';
import {
  asyncErrorHandler,
  errorHandler,
  notFoundHandler,
} from '../../../src/middleware/errorHandler.js';
import {
  AppError,
  UnauthorizedError,
  ValidationError,
  VRTErrorCodes,
} from '../../../src/types/errors.js';

const ISO_8601_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

function makeRes(locals: Record<string, unknown> = {}) {
  const json = vi.fn();
  const status = vi.fn();
  const res = { locals, status, json } as unknown as Response;
  status.mockReturnValue(res);
  return { res, status, json };
}

function makeReq(overrides: Partial<Request> = {}): Request {
  return { path: '/api/v1/things', method: 'POST', ...overrides } as unknown as Request;
}

/** Postgres-style error: an `Error` carrying a five-character SQLSTATE code. */
function postgresError(code: string, message = 'database failure'): Error {
  const err = new Error(message);
  (err as Error & { code?: string }).code = code;
  return err;
}

function namedError(name: string, message: string): Error {
  const err = new Error(message);
  err.name = name;
  return err;
}

/** Envelope sent by the last `res.json()` call. */
function envelope(json: ReturnType<typeof vi.fn>): Record<string, unknown> {
  expect(json).toHaveBeenCalledTimes(1);
  return json.mock.calls[0][0] as Record<string, unknown>;
}

describe('errorHandler', () => {
  let errorLog: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    errorLog = vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    errorLog.mockRestore();
  });

  it('maps a 4xx AppError to its status and VRT code, preserving the message', () => {
    const { res, status, json } = makeRes({ requestId: 'req-1' });
    const next = vi.fn();

    errorHandler(
      new AppError('Business rule violated', 422, VRTErrorCodes.VRT_0002),
      makeReq(),
      res,
      next as unknown as NextFunction,
    );

    expect(status).toHaveBeenCalledWith(422);
    const body = envelope(json);
    expect(body.status).toBe('error');
    expect(body.vrtCode).toBe('VRT-0002');
    expect(body.message).toBe('Business rule violated');
    expect(body.requestId).toBe('req-1');
    expect(body.timestamp).toMatch(ISO_8601_RE);
  });

  it('masks the message of AppErrors with a 5xx status but keeps the VRT code', () => {
    const { res, status, json } = makeRes();
    errorHandler(
      new AppError('connection string postgres://user:pw@host leaked', 500, VRTErrorCodes.VRT_0007),
      makeReq(),
      res,
      vi.fn() as unknown as NextFunction,
    );

    expect(status).toHaveBeenCalledWith(500);
    const body = envelope(json);
    expect(body.message).toBe('An unexpected error occurred');
    expect(body.vrtCode).toBe('VRT-0007');
    expect(JSON.stringify(body)).not.toContain('postgres://');
  });

  it('renders a ValidationError with details plus the legacy `errors` alias', () => {
    const details = [{ field: 'email', message: 'Invalid email' }];
    const { res, status, json } = makeRes();

    errorHandler(new ValidationError(details), makeReq(), res, vi.fn() as unknown as NextFunction);

    expect(status).toHaveBeenCalledWith(400);
    const body = envelope(json);
    expect(body.vrtCode).toBe('VRT-0002');
    expect(body.message).toBe('Validation Error');
    expect(body.details).toEqual(details);
    expect(body.errors).toEqual(details);
  });

  it('normalises a raw ZodError into deterministic, serialisable issues', () => {
    const { res, status, json } = makeRes();
    const zodError = new z.ZodError([
      {
        code: z.ZodIssueCode.custom,
        path: ['items', 0, 'name'],
        message: 'Required',
      },
    ]);

    errorHandler(zodError, makeReq(), res, vi.fn() as unknown as NextFunction);

    expect(status).toHaveBeenCalledWith(400);
    const body = envelope(json);
    expect(body.vrtCode).toBe('VRT-0002');
    expect(body.details).toEqual([
      { path: ['items', '0', 'name'], message: 'Required', code: 'custom' },
    ]);
    expect(body.errors).toEqual(body.details);
  });

  it('maps UnauthorizedError to 401 / VRT-0001', () => {
    const { res, status, json } = makeRes();
    errorHandler(new UnauthorizedError(), makeReq(), res, vi.fn() as unknown as NextFunction);

    expect(status).toHaveBeenCalledWith(401);
    expect(envelope(json).vrtCode).toBe('VRT-0001');
    expect(envelope(json).message).toBe('Authentication required');
  });

  it.each([
    ['23505', 'unique_violation'],
    ['23503', 'foreign_key_violation'],
  ])('maps client-safe Postgres conflict %s (%s) to 409 / VRT-0005', (code) => {
    const { res, status, json } = makeRes();
    errorHandler(postgresError(code), makeReq(), res, vi.fn() as unknown as NextFunction);

    expect(status).toHaveBeenCalledWith(409);
    expect(envelope(json).vrtCode).toBe('VRT-0005');
    expect(envelope(json).message).toBe('Resource conflict');
  });

  it('maps a non-client-safe Postgres error to 500 / VRT-0007 without leaking the code', () => {
    const { res, status, json } = makeRes();
    errorHandler(postgresError('42P01', 'relation "secret_table" does not exist'), makeReq(), res, vi.fn() as unknown as NextFunction);

    expect(status).toHaveBeenCalledWith(500);
    const body = envelope(json);
    expect(body.vrtCode).toBe('VRT-0007');
    expect(body.message).toBe('An unexpected error occurred');
    expect(JSON.stringify(body)).not.toContain('secret_table');
    expect(JSON.stringify(body)).not.toContain('42P01');
  });

  it.each([['JsonWebTokenError'], ['TokenExpiredError']])(
    'maps %s to 401 / VRT-0001',
    (name) => {
      const { res, status, json } = makeRes();
      errorHandler(namedError(name, 'jwt problem'), makeReq(), res, vi.fn() as unknown as NextFunction);

      expect(status).toHaveBeenCalledWith(401);
      expect(envelope(json).vrtCode).toBe('VRT-0001');
      expect(envelope(json).message).toBe('Authentication required');
    },
  );

  it.each([[undefined], ['just a string'], [42], [null]])(
    'falls back to 500 / VRT-9999 for non-Error throwable %o',
    (thrown) => {
      const { res, status, json } = makeRes();
      errorHandler(thrown, makeReq(), res, vi.fn() as unknown as NextFunction);

      expect(status).toHaveBeenCalledWith(500);
      expect(envelope(json).vrtCode).toBe('VRT-9999');
      expect(envelope(json).message).toBe('An unexpected error occurred');
    },
  );

  it('omits requestId when res.locals has none', () => {
    const { res, json } = makeRes();
    errorHandler(new AppError('nope'), makeReq(), res, vi.fn() as unknown as NextFunction);

    expect(envelope(json)).not.toHaveProperty('requestId');
  });

  it('does not continue the middleware chain and responds exactly once', () => {
    const { res, status, json } = makeRes();
    const next = vi.fn();

    errorHandler(new AppError('stop', 400), makeReq(), res, next as unknown as NextFunction);

    expect(next).not.toHaveBeenCalled();
    expect(status).toHaveBeenCalledTimes(1);
    expect(json).toHaveBeenCalledTimes(1);
  });

  it('logs structured server-side context including path, method and status', () => {
    const { res } = makeRes({ requestId: 'req-log' });
    errorHandler(
      new AppError('boom', 503, VRTErrorCodes.VRT_0008),
      makeReq({ path: '/api/v1/webhook-subscriptions', method: 'PATCH' }),
      res,
      vi.fn() as unknown as NextFunction,
    );

    expect(errorLog).toHaveBeenCalledTimes(1);
    const entry = JSON.parse(errorLog.mock.calls[0]![0] as string) as Record<string, unknown>;
    expect(entry).toMatchObject({
      type: 'request_error',
      level: 'error',
      path: '/api/v1/webhook-subscriptions',
      method: 'PATCH',
      statusCode: 503,
      requestId: 'req-log',
      vrtCode: 'VRT-0008',
    });
  });

  it('reports VRT-9999 in the log for unknown throwables', () => {
    const { res } = makeRes();
    errorHandler('boom', makeReq(), res, vi.fn() as unknown as NextFunction);

    const entry = JSON.parse(errorLog.mock.calls[0]![0] as string) as Record<string, unknown>;
    expect(entry.vrtCode).toBe('VRT-9999');
    expect(entry.errorType).toBe('string');
  });
});

describe('asyncErrorHandler', () => {
  it('returns a middleware function', () => {
    expect(typeof asyncErrorHandler(async () => undefined)).toBe('function');
  });

  it('forwards a rejected promise to next()', async () => {
    const boom = new Error('async boom');
    const next = vi.fn();
    const wrapped = asyncErrorHandler(async () => {
      throw boom;
    });

    wrapped(makeReq(), makeRes().res, next as unknown as NextFunction);

    await vi.waitFor(() => expect(next).toHaveBeenCalledWith(boom));
  });

  it('forwards non-Error rejection values unchanged', async () => {
    const next = vi.fn();
    const wrapped = asyncErrorHandler(() => Promise.reject('plain-string-rejection'));

    wrapped(makeReq(), makeRes().res, next as unknown as NextFunction);

    await vi.waitFor(() => expect(next).toHaveBeenCalledWith('plain-string-rejection'));
  });

  it('does not call next() when the handler resolves', async () => {
    const next = vi.fn();
    const handler = vi.fn(async () => 'ok');
    const wrapped = asyncErrorHandler(handler);

    wrapped(makeReq(), makeRes().res, next as unknown as NextFunction);
    await vi.waitFor(() => expect(handler).toHaveBeenCalledTimes(1));

    expect(next).not.toHaveBeenCalled();
  });

  it('passes req/res/next through to the wrapped handler', async () => {
    const req = makeReq({ method: 'GET', path: '/ping' });
    const res = makeRes().res;
    const next = vi.fn();
    const seen = vi.fn();
    const wrapped = asyncErrorHandler(async (r, s, n) => {
      seen(r, s, n);
    });

    wrapped(req, res, next as unknown as NextFunction);
    await vi.waitFor(() => expect(seen).toHaveBeenCalledTimes(1));

    expect(seen).toHaveBeenCalledWith(req, res, next);
  });
});

describe('notFoundHandler', () => {
  it('returns a 404 VRT-0004 envelope describing the unmatched route', () => {
    const { res, status, json } = makeRes({ requestId: 'req-404' });

    notFoundHandler(makeReq({ method: 'DELETE', path: '/api/v1/ghost' }), res);

    expect(status).toHaveBeenCalledWith(404);
    const body = envelope(json);
    expect(body.status).toBe('error');
    expect(body.vrtCode).toBe('VRT-0004');
    expect(body.message).toBe('Cannot DELETE /api/v1/ghost');
    expect(body.requestId).toBe('req-404');
    expect(body.timestamp).toMatch(ISO_8601_RE);
  });

  it('emits requestId as undefined when the request was never tagged', () => {
    const { res, json } = makeRes();

    notFoundHandler(makeReq({ method: 'GET', path: '/nope' }), res);

    const body = envelope(json);
    expect(body.requestId).toBeUndefined();
    expect(Object.keys(body)).toContain('requestId');
  });

  it('does not require a next callback (terminal middleware)', () => {
    const { res, status } = makeRes();

    expect(() => notFoundHandler(makeReq(), res)).not.toThrow();
    expect(status).toHaveBeenCalledWith(404);
  });
});
