/**
 * Unit tests for idempotency middleware
 * 
 * Tests cover:
 * - Key validation (presence, format, length)
 * - Response caching and retrieval
 * - TTL expiration
 * - User scoping
 * - Edge cases
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import type { Request, Response, NextFunction } from 'express';
import { 
  idempotencyMiddleware, 
  inMemoryIdempotencyStore,
  getDefaultTtl,
  getIdempotencyHeaderName,
  clearIdempotencyStore,
  IDEMPOTENCY_KEY_HEADER
} from '../../../src/middleware/idempotency.js';

// Mock request/response helpers - using any to avoid complex type issues
function createMockRequest(overrides: Record<string, unknown> = {}): Request {
  return {
    headers: {},
    ip: '127.0.0.1',
    method: 'POST',
    ...overrides,
  } as Request;
}

function createMockResponse(): Response {
  const res = {
    status: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
  } as unknown as Response;
  return res;
}

function createMockNext(): NextFunction {
  return vi.fn();
}

describe('idempotencyMiddleware', () => {
  beforeEach(() => {
    clearIdempotencyStore();
    vi.clearAllMocks();
  });

  afterEach(() => {
    clearIdempotencyStore();
  });

  describe('Key Validation', () => {
    it('should return 400 when idempotency key is missing', async () => {
      const req = createMockRequest({ headers: {} });
      const res = createMockResponse();
      const next = createMockNext();

      const middleware = idempotencyMiddleware({ scope: 'test' });
      await middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: 'Bad Request',
          code: 'IDEMPOTENCY_KEY_REQUIRED',
        })
      );
      expect(next).not.toHaveBeenCalled();
    });

    it('should return 400 when idempotency key is empty string', async () => {
      const req = createMockRequest({ headers: { 'idempotency-key': '   ' } });
      const res = createMockResponse();
      const next = createMockNext();

      const middleware = idempotencyMiddleware({ scope: 'test' });
      await middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(next).not.toHaveBeenCalled();
    });

    it('should return 400 when key is too short', async () => {
      const req = createMockRequest({ headers: { 'idempotency-key': 'abc' } });
      const res = createMockResponse();
      const next = createMockNext();

      const middleware = idempotencyMiddleware({ scope: 'test' });
      await middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          code: 'IDEMPOTENCY_KEY_INVALID',
        })
      );
      expect(next).not.toHaveBeenCalled();
    });

    it('should return 400 when key is too long', async () => {
      const longKey = 'a'.repeat(300);
      const req = createMockRequest({ headers: { 'idempotency-key': longKey } });
      const res = createMockResponse();
      const next = createMockNext();

      const middleware = idempotencyMiddleware({ scope: 'test' });
      await middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(next).not.toHaveBeenCalled();
    });

    it('should return 400 when key format is invalid in strict mode', async () => {
      const req = createMockRequest({ headers: { 'idempotency-key': 'not-a-uuid' } });
      const res = createMockResponse();
      const next = createMockNext();

      const middleware = idempotencyMiddleware({ 
        scope: 'test', 
        strictKeyFormat: true 
      });
      await middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          message: expect.stringContaining('UUID'),
        })
      );
      expect(next).not.toHaveBeenCalled();
    });

    it('should accept valid key in strict mode when it is UUID', async () => {
      const uuid = '12345678-1234-1234-1234-123456789012';
      const req = createMockRequest({ headers: { 'idempotency-key': uuid } });
      const res = createMockResponse();
      const next = createMockNext();

      const middleware = idempotencyMiddleware({ 
        scope: 'test', 
        strictKeyFormat: true 
      });
      await middleware(req, res, next);

      expect(next).toHaveBeenCalled();
    });
  });

  describe('Response Caching', () => {
    it('should cache successful response and return on duplicate request', async () => {
      const key = 'test-key-123';
      const req1 = createMockRequest({ headers: { 'idempotency-key': key } });
      const res1 = createMockResponse();
      const next1 = createMockNext();

      const middleware = idempotencyMiddleware({ scope: 'test' });
      
      // First request
      await middleware(req1, res1, next1);
      
      // Simulate route handler response
      res1.status(201);
      res1.json({ id: '123', status: 'created' });

      // Second request with same key
      const req2 = createMockRequest({ headers: { 'idempotency-key': key } });
      const res2 = createMockResponse();
      const next2 = createMockNext();
      
      await middleware(req2, res2, next2);

      // Should return cached response without calling next
      expect(res2.status).toHaveBeenCalledWith(201);
      expect(res2.json).toHaveBeenCalledWith({ id: '123', status: 'created' });
      expect(next2).not.toHaveBeenCalled();
    });

    it('should not cache error responses (4xx)', async () => {
      const key = 'error-test-key';
      const req1 = createMockRequest({ headers: { 'idempotency-key': key } });
      const res1 = createMockResponse();
      const next1 = createMockNext();

      const middleware = idempotencyMiddleware({ scope: 'test' });
      
      // First request - returns error
      await middleware(req1, res1, next1);
      
      // Simulate error response
      res1.status(400);
      res1.json({ error: 'Bad request' });

      // Second request with same key - should process again
      const req2 = createMockRequest({ headers: { 'idempotency-key': key } });
      const res2 = createMockResponse();
      const next2 = createMockNext();
      
      await middleware(req2, res2, next2);

      // Should call next (not return cached error)
      expect(next2).toHaveBeenCalled();
    });

    it('should not cache error responses (5xx)', async () => {
      const key = 'server-error-key';
      const req1 = createMockRequest({ headers: { 'idempotency-key': key } });
      const res1 = createMockResponse();
      const next1 = createMockNext();

      const middleware = idempotencyMiddleware({ scope: 'test' });
      
      // First request - returns server error
      await middleware(req1, res1, next1);
      
      // Simulate server error
      res1.status(500);
      res1.json({ error: 'Internal server error' });

      // Second request with same key - should process again
      const req2 = createMockRequest({ headers: { 'idempotency-key': key } });
      const res2 = createMockResponse();
      const next2 = createMockNext();
      
      await middleware(req2, res2, next2);

      // Should call next (not return cached error)
      expect(next2).toHaveBeenCalled();
    });
  });

  describe('User Scoping', () => {
    it('should scope keys by user ID when available', async () => {
      const key = 'user-scoped-key';
      
      // First user
      const req1 = createMockRequest({ 
        headers: { 'idempotency-key': key },
        user: { id: 'user-1', email: 'user1@test.com' }
      });
      const res1 = createMockResponse();
      const next1 = createMockNext();

      const middleware = idempotencyMiddleware({ scope: 'test' });
      await middleware(req1, res1, next1);
      res1.status(201);
      res1.json({ id: '1' });

      // Second user with same key - should NOT get cached response
      const req2 = createMockRequest({ 
        headers: { 'idempotency-key': key },
        user: { id: 'user-2', email: 'user2@test.com' }
      });
      const res2 = createMockResponse();
      const next2 = createMockNext();
      
      await middleware(req2, res2, next2);

      // Different user should get fresh response
      expect(next2).toHaveBeenCalled();
    });

    it('should use IP address as fallback when no user', async () => {
      const key = 'ip-scoped-key';
      
      // First request from IP
      const req1 = createMockRequest({ 
        headers: { 'idempotency-key': key },
        ip: '192.168.1.1'
      });
      const res1 = createMockResponse();
      const next1 = createMockNext();

      const middleware = idempotencyMiddleware({ scope: 'test' });
      await middleware(req1, res1, next1);
      res1.status(201);
      res1.json({ id: '1' });

      // Second request from same IP - should get cached
      const req2 = createMockRequest({ 
        headers: { 'idempotency-key': key },
        ip: '192.168.1.1'
      });
      const res2 = createMockResponse();
      const next2 = createMockNext();
      
      await middleware(req2, res2, next2);

      // Should return cached
      expect(res2.status).toHaveBeenCalledWith(201);
      expect(next2).not.toHaveBeenCalled();
    });

    it('should use custom getUserKey function', async () => {
      const key = 'custom-user-key';
      
      const req1 = createMockRequest({ 
        headers: { 'idempotency-key': key, 'x-api-key': 'api-key-123' }
      });
      const res1 = createMockResponse();
      const next1 = createMockNext();

      const middleware = idempotencyMiddleware({ 
        scope: 'test',
        getUserKey: (req) => (req.headers['x-api-key'] as string) ?? 'anonymous'
      });
      await middleware(req1, res1, next1);
      res1.status(201);
      res1.json({ id: '1' });

      // Same API key - should get cached
      const req2 = createMockRequest({ 
        headers: { 'idempotency-key': key, 'x-api-key': 'api-key-123' }
      });
      const res2 = createMockResponse();
      const next2 = createMockNext();
      
      await middleware(req2, res2, next2);

      expect(res2.status).toHaveBeenCalledWith(201);
      expect(next2).not.toHaveBeenCalled();
    });
  });

  describe('TTL and Expiration', () => {
    it('should respect custom TTL', async () => {
      const key = 'ttl-test-key';
      const shortTtl = 100; // 100ms
      
      const req1 = createMockRequest({ headers: { 'idempotency-key': key } });
      const res1 = createMockResponse();
      const next1 = createMockNext();

      const middleware = idempotencyMiddleware({ 
        scope: 'test', 
        ttlMs: shortTtl 
      });
      await middleware(req1, res1, next1);
      res1.status(201);
      res1.json({ id: '1' });

      // Wait for TTL to expire
      await new Promise(resolve => setTimeout(resolve, 150));

      // Second request after TTL - should process again
      const req2 = createMockRequest({ headers: { 'idempotency-key': key } });
      const res2 = createMockResponse();
      const next2 = createMockNext();
      
      await middleware(req2, res2, next2);

      expect(next2).toHaveBeenCalled();
    });
  });

  describe('Custom Validation', () => {
    it('should use custom key validation function', async () => {
      const key = 'custom-validation-key';
      
      const req = createMockRequest({ headers: { 'idempotency-key': key } });
      const res = createMockResponse();
      const next = createMockNext();

      // Custom validator that only accepts keys starting with 'valid-'
      const middleware = idempotencyMiddleware({ 
        scope: 'test',
        validateKey: (k) => k.startsWith('valid-')
      });
      await middleware(req, res, next);

      // Should fail because key doesn't start with 'valid-'
      expect(res.status).toHaveBeenCalledWith(400);
      expect(next).not.toHaveBeenCalled();
    });

    it('should accept key when custom validation passes', async () => {
      const key = 'valid-custom-key';
      
      const req = createMockRequest({ headers: { 'idempotency-key': key } });
      const res = createMockResponse();
      const next = createMockNext();

      const middleware = idempotencyMiddleware({ 
        scope: 'test',
        validateKey: (k) => k.startsWith('valid-')
      });
      await middleware(req, res, next);

      // Should pass because key starts with 'valid-'
      expect(next).toHaveBeenCalled();
    });
  });

  describe('Skip Function', () => {
    it('should skip idempotency when skipIf returns true', async () => {
      const req = createMockRequest({ 
        headers: { 'idempotency-key': 'some-key' },
        method: 'GET'
      });
      const res = createMockResponse();
      const next = createMockNext();

      const middleware = idempotencyMiddleware({ 
        scope: 'test',
        skipIf: (r) => r.method === 'GET'
      });
      await middleware(req, res, next);

      // Should skip and call next without checking key
      expect(next).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
    });
  });

  describe('Scope Isolation', () => {
    it('should not share cache between different scopes', async () => {
      const key = 'shared-key';
      
      // First scope
      const req1 = createMockRequest({ headers: { 'idempotency-key': key } });
      const res1 = createMockResponse();
      const next1 = createMockNext();

      const middleware1 = idempotencyMiddleware({ scope: 'scope-a' });
      await middleware1(req1, res1, next1);
      res1.status(201);
      res1.json({ id: 'from-scope-a' });

      // Second scope with same key - should NOT get cached
      const req2 = createMockRequest({ headers: { 'idempotency-key': key } });
      const res2 = createMockResponse();
      const next2 = createMockNext();

      const middleware2 = idempotencyMiddleware({ scope: 'scope-b' });
      await middleware2(req2, res2, next2);

      // Different scope should get fresh response
      expect(next2).toHaveBeenCalled();
    });
  });

  describe('Edge Cases', () => {
    it('should handle array of idempotency keys (use first)', async () => {
      const req = createMockRequest({ 
        headers: { 'idempotency-key': ['valid-key-123', 'key2'] }
      });
      const res = createMockResponse();
      const next = createMockNext();

      const middleware = idempotencyMiddleware({ scope: 'test' });
      await middleware(req, res, next);

      // Should use first key
      expect(next).toHaveBeenCalled();
    });

    it('should handle whitespace in key', async () => {
      const req = createMockRequest({ 
        headers: { 'idempotency-key': '  test-key-123  ' }
      });
      const res = createMockResponse();
      const next = createMockNext();

      const middleware = idempotencyMiddleware({ scope: 'test' });
      await middleware(req, res, next);

      // Should trim whitespace
      expect(next).toHaveBeenCalled();
    });

    it('should handle store errors gracefully', async () => {
      // Create a store that throws on set
      const failingStore = {
        get: vi.fn().mockResolvedValue(undefined),
        set: vi.fn().mockRejectedValue(new Error('Store error')),
      };

      const req = createMockRequest({ headers: { 'idempotency-key': 'test-key' } });
      const res = createMockResponse();
      const next = createMockNext();

      const middleware = idempotencyMiddleware({ 
        scope: 'test',
        store: failingStore
      });
      await middleware(req, res, next);
      res.status(201);
      res.json({ id: '1' });

      // Should still complete without throwing
      expect(next).toHaveBeenCalled();
    });
  });
});

describe('Utility Functions', () => {
  it('getDefaultTtl should return 24 hours in ms', () => {
    expect(getDefaultTtl()).toBe(24 * 60 * 60 * 1000);
  });

  it('getIdempotencyHeaderName should return header name', () => {
    expect(getIdempotencyHeaderName()).toBe('idempotency-key');
  });

  it('IDEMPOTENCY_KEY_HEADER constant should be exported', () => {
    expect(IDEMPOTENCY_KEY_HEADER).toBe('idempotency-key');
  });
});

describe('In-Memory Store', () => {
  beforeEach(() => {
    clearIdempotencyStore();
  });

  afterEach(() => {
    clearIdempotencyStore();
  });

  it('should store and retrieve entries', async () => {
    const entry = { status: 200, body: { test: true }, createdAt: Date.now() };
    await inMemoryIdempotencyStore.set('key1', entry, 60000);
    
    const result = await inMemoryIdempotencyStore.get('key1');
    expect(result).toEqual(entry);
  });

  it('should return undefined for non-existent key', async () => {
    const result = await inMemoryIdempotencyStore.get('nonexistent');
    expect(result).toBeUndefined();
  });

  it('should delete entries', async () => {
    const entry = { status: 200, body: { test: true }, createdAt: Date.now() };
    await inMemoryIdempotencyStore.set('key1', entry, 60000);
    
    if (inMemoryIdempotencyStore.delete) {
      await inMemoryIdempotencyStore.delete('key1');
      const result = await inMemoryIdempotencyStore.get('key1');
      expect(result).toBeUndefined();
    }
  });

  it('should clear all entries', async () => {
    const entry = { status: 200, body: { test: true }, createdAt: Date.now() };
    await inMemoryIdempotencyStore.set('key1', entry, 60000);
    await inMemoryIdempotencyStore.set('key2', entry, 60000);
    
    if (inMemoryIdempotencyStore.clear) {
      await inMemoryIdempotencyStore.clear();
      const result1 = await inMemoryIdempotencyStore.get('key1');
      const result2 = await inMemoryIdempotencyStore.get('key2');
      expect(result1).toBeUndefined();
      expect(result2).toBeUndefined();
    }
  });

  it('should expire entries after TTL', async () => {
    const entry = { status: 200, body: { test: true }, createdAt: Date.now() };
    await inMemoryIdempotencyStore.set('key1', entry, 50);
    
    // Wait for expiration
    await new Promise(resolve => setTimeout(resolve, 100));
    
    const result = await inMemoryIdempotencyStore.get('key1');
    expect(result).toBeUndefined();
  });
});
