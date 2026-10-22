import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import type { Request, Response, NextFunction } from 'express';
import {
  idempotencyMiddleware,
  inMemoryIdempotencyStore,
  RedisIdempotencyStore,
  clearIdempotencyStore,
  type RedisClientLike,
} from '../idempotency.js';
import { errorHandler } from '../errorHandler.js';
import { ExternalServiceError } from '../../types/errors.js';

function createMockRequest(overrides: Record<string, unknown> = {}): Request {
  const req = {
    headers: {},
    ip: '127.0.0.1',
    method: 'POST',
    body: {},
    ...overrides,
  } as unknown as Request;
  return req;
}

function createMockResponse(): Response {
  const listeners: Record<string, Array<() => void>> = {};
  const headers: Record<string, string> = {};

  const res = {
    statusCode: 200,
    headersSent: false,
    setHeader: vi.fn((key: string, value: string) => {
      headers[key.toLowerCase()] = value;
      return res;
    }),
    getHeader: vi.fn((key: string) => headers[key.toLowerCase()]),
    status: vi.fn(function (this: any, code: number) {
      this.statusCode = code;
      return this;
    }),
    json: vi.fn(function (this: any, body: unknown) {
      this.body = body;
      return this;
    }),
    once: vi.fn((event: string, cb: () => void) => {
      listeners[event] = listeners[event] || [];
      listeners[event].push(cb);
      return res;
    }),
    on: vi.fn((event: string, cb: () => void) => {
      listeners[event] = listeners[event] || [];
      listeners[event].push(cb);
      return res;
    }),
    emit: (event: string) => {
      const cbs = listeners[event] || [];
      for (const cb of cbs) {
        cb();
      }
    },
  } as unknown as Response & { emit: (event: string) => void; body?: unknown };

  return res;
}

function createMockNext(): NextFunction {
  return vi.fn();
}

/**
 * Mock Redis client implementing SET key val PX ttl NX
 */
function createMockRedisClient(): RedisClientLike & { data: Map<string, string> } {
  const data = new Map<string, string>();

  return {
    data,
    get: vi.fn(async (key: string) => data.get(key) ?? null),
    set: vi.fn(async (key: string, val: string, ...args: unknown[]) => {
      const isPx = args.includes('PX') || args.includes('px');
      const isNx = args.includes('NX') || args.includes('nx');

      if (isNx && data.has(key)) {
        return null;
      }

      data.set(key, val);
      return 'OK';
    }),
    del: vi.fn(async (key: string) => {
      const existed = data.delete(key);
      return existed ? 1 : 0;
    }),
  };
}

describe('idempotencyMiddleware concurrency & failure resilience', () => {
  beforeEach(() => {
    clearIdempotencyStore();
    vi.clearAllMocks();
  });

  afterEach(() => {
    clearIdempotencyStore();
  });

  describe('In-Memory Store', () => {
    it('parallel requests with the same key result in exactly one handler invocation, with the other getting 409 IDEMPOTENCY_IN_PROGRESS', async () => {
      const middleware = idempotencyMiddleware({ scope: 'attestations' });
      const key = '550e8400-e29b-41d4-a716-446655440000';
      const body = { businessId: 'biz_1', amount: 1000 };

      const req1 = createMockRequest({
        headers: { 'idempotency-key': key },
        body,
      });
      const res1 = createMockResponse();

      const req2 = createMockRequest({
        headers: { 'idempotency-key': key },
        body,
      });
      const res2 = createMockResponse();

      let handlerInvocations = 0;
      const next1 = vi.fn(() => {
        handlerInvocations++;
      });
      const next2 = vi.fn(() => {
        handlerInvocations++;
      });

      // Launch both requests simultaneously
      await Promise.all([
        middleware(req1, res1, next1),
        middleware(req2, res2, next2),
      ]);

      // Exactly one invocation should proceed to downstream handler
      expect(handlerInvocations).toBe(1);

      // One got through and called next
      expect(next1).toHaveBeenCalledTimes(1);
      expect(next2).not.toHaveBeenCalled();

      // The other got 409 Conflict with IDEMPOTENCY_IN_PROGRESS and Retry-After
      expect(res2.status).toHaveBeenCalledWith(409);
      expect(res2.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: 'Conflict',
          code: 'IDEMPOTENCY_IN_PROGRESS',
        })
      );
      expect(res2.setHeader).toHaveBeenCalledWith('Retry-After', '1');

      // Now the first request finishes and returns 201 Created
      res1.status(201);
      res1.json({ id: 'att_123', status: 'verified' });

      // A third request with the same key should now hit the cache
      const req3 = createMockRequest({
        headers: { 'idempotency-key': key },
        body,
      });
      const res3 = createMockResponse();
      const next3 = createMockNext();

      await middleware(req3, res3, next3);

      expect(next3).not.toHaveBeenCalled();
      expect(res3.status).toHaveBeenCalledWith(201);
      expect(res3.json).toHaveBeenCalledWith({ id: 'att_123', status: 'verified' });
    });

    it('releases reservation if the handler throws or returns non-2xx so retry can succeed', async () => {
      const middleware = idempotencyMiddleware({ scope: 'attestations' });
      const key = '6ba7b810-9dad-11d1-80b4-00c04fd430c8';
      const body = { businessId: 'biz_1', amount: 2000 };

      const req1 = createMockRequest({
        headers: { 'idempotency-key': key },
        body,
      });
      const res1 = createMockResponse();

      let handlerCalls = 0;
      const next1 = vi.fn(() => {
        handlerCalls++;
        // Handler throws an error
        throw new Error('Soroban RPC submission failed');
      });

      try {
        await middleware(req1, res1, next1);
      } catch (err) {
        // Express error handling or exception propagation
      }

      // Simulate non-2xx status sent by error handler or route
      res1.status(500);
      res1.json({ error: 'Internal Server Error' });

      // Retry request with the same key
      const req2 = createMockRequest({
        headers: { 'idempotency-key': key },
        body,
      });
      const res2 = createMockResponse();
      const next2 = vi.fn(() => {
        handlerCalls++;
        res2.status(200);
        res2.json({ success: true });
      });

      await middleware(req2, res2, next2);

      // The retry must have succeeded and invoked the handler again
      expect(handlerCalls).toBe(2);
      expect(next2).toHaveBeenCalledTimes(1);
      expect(res2.status).toHaveBeenCalledWith(200);
    });
  });

  describe('Redis Store', () => {
    it('parallel requests with RedisIdempotencyStore execute handler once and return 409 to duplicate', async () => {
      const mockRedis = createMockRedisClient();
      const redisStore = new RedisIdempotencyStore(mockRedis);
      const middleware = idempotencyMiddleware({ scope: 'attestations', store: redisStore });

      const key = '7ca7b810-9dad-11d1-80b4-00c04fd430c9';
      const body = { businessId: 'biz_redis', amount: 5000 };

      const req1 = createMockRequest({ headers: { 'idempotency-key': key }, body });
      const res1 = createMockResponse();
      const req2 = createMockRequest({ headers: { 'idempotency-key': key }, body });
      const res2 = createMockResponse();

      let handlerCalls = 0;
      const next1 = vi.fn(() => { handlerCalls++; });
      const next2 = vi.fn(() => { handlerCalls++; });

      await Promise.all([
        middleware(req1, res1, next1),
        middleware(req2, res2, next2),
      ]);

      expect(handlerCalls).toBe(1);
      expect(next1).toHaveBeenCalledTimes(1);
      expect(next2).not.toHaveBeenCalled();

      expect(res2.status).toHaveBeenCalledWith(409);
      expect(res2.json).toHaveBeenCalledWith(
        expect.objectContaining({
          code: 'IDEMPOTENCY_IN_PROGRESS',
        })
      );
      expect(res2.setHeader).toHaveBeenCalledWith('Retry-After', '1');
    });

    it('releases reservation on Redis store when error occurs, allowing retry', async () => {
      const mockRedis = createMockRedisClient();
      const redisStore = new RedisIdempotencyStore(mockRedis);
      const middleware = idempotencyMiddleware({ scope: 'attestations', store: redisStore });

      const key = '8da7b810-9dad-11d1-80b4-00c04fd430ca';
      const body = { businessId: 'biz_redis', amount: 999 };

      const req1 = createMockRequest({ headers: { 'idempotency-key': key }, body });
      const res1 = createMockResponse();

      let handlerCalls = 0;
      const next1 = vi.fn(() => {
        handlerCalls++;
        res1.status(500);
        res1.json({ error: 'Failed' });
      });

      await middleware(req1, res1, next1);
      expect(handlerCalls).toBe(1);

      // Now retry with same key
      const req2 = createMockRequest({ headers: { 'idempotency-key': key }, body });
      const res2 = createMockResponse();
      const next2 = vi.fn(() => {
        handlerCalls++;
        res2.status(201);
        res2.json({ success: true });
      });

      await middleware(req2, res2, next2);
      expect(handlerCalls).toBe(2);
      expect(next2).toHaveBeenCalledTimes(1);
    });
  });

  describe('Store Failure / Fail-Closed Resilience', () => {
    it('when store.get rejects, request calls next(err) resulting in a 503 error envelope, not hanging', async () => {
      const failingStore = {
        get: vi.fn().mockRejectedValue(new Error('Redis connection lost')),
        set: vi.fn().mockResolvedValue(undefined),
        reserve: vi.fn().mockResolvedValue(true),
      };

      const middleware = idempotencyMiddleware({ scope: 'attestations', store: failingStore });

      const req = createMockRequest({
        headers: { 'idempotency-key': '9ea7b810-9dad-11d1-80b4-00c04fd430cb' },
      });
      const res = createMockResponse();
      const next = vi.fn();

      await middleware(req, res, next);

      // Must call next with error instead of hanging
      expect(next).toHaveBeenCalledTimes(1);
      const passedErr = next.mock.calls[0][0];
      expect(passedErr).toBeDefined();
      expect(passedErr).toBeInstanceOf(ExternalServiceError);
      expect(passedErr.status).toBe(503);

      // Verify that passing this error to errorHandler produces a 503 error envelope
      errorHandler(passedErr, req, res, vi.fn());

      expect(res.status).toHaveBeenCalledWith(503);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          status: 'error',
          vrtCode: 'VRT-0008',
          message: 'An unexpected error occurred',
        })
      );
    });

    it('when store.reserve rejects, request calls next(err) and fails closed', async () => {
      const failingStore = {
        get: vi.fn().mockResolvedValue(undefined),
        reserve: vi.fn().mockRejectedValue(new Error('Redis SET NX timeout')),
        set: vi.fn().mockResolvedValue(undefined),
      };

      const middleware = idempotencyMiddleware({ scope: 'attestations', store: failingStore });

      const req = createMockRequest({
        headers: { 'idempotency-key': 'afa7b810-9dad-11d1-80b4-00c04fd430cc' },
      });
      const res = createMockResponse();
      const next = vi.fn();

      await middleware(req, res, next);

      expect(next).toHaveBeenCalledTimes(1);
      const passedErr = next.mock.calls[0][0];
      expect(passedErr).toBeInstanceOf(ExternalServiceError);
      expect(passedErr.status).toBe(503);
    });
  });
});
