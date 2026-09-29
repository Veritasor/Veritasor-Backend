import { describe, it, expect, vi, beforeEach } from 'vitest';
import { RedisIdempotencyStore, type RedisClientLike } from '../idempotency.js';

vi.mock('../../utils/logger.js', () => ({
  logger: {
    error: vi.fn(),
    warn: vi.fn(),
    info: vi.fn()
  }
}));

vi.mock('../../metrics.js', () => ({
  idempotencyBatchSize: { observe: vi.fn() },
  idempotencyEvictionsTotal: { inc: vi.fn() },
  idempotencyKeysCount: { set: vi.fn() },
  idempotencySweepRunsTotal: { inc: vi.fn() }
}));

vi.mock('../../redis.js', () => ({
  redisCircuitBreaker: {
    execute: vi.fn(async (operation, fallback) => {
      try {
        return await operation();
      } catch (err) {
        return fallback ? fallback() : undefined;
      }
    })
  }
}));

describe('RedisIdempotencyStore Regression Suite', () => {
  let mockClient: import('vitest').Mocked<RedisClientLike>;
  let store: RedisIdempotencyStore;

  beforeEach(() => {
    mockClient = {
      get: vi.fn(),
      set: vi.fn(),
      del: vi.fn(),
      pipeline: vi.fn()
    };
    store = new RedisIdempotencyStore(mockClient);
    vi.clearAllMocks();
  });

  describe('get()', () => {
    it('should handle explicit failure or empty-result path (if !raw return undefined)', async () => {
      mockClient.get.mockResolvedValue(null);
      
      const result = await store.get('missing-key');
      
      expect(mockClient.get).toHaveBeenCalledWith('missing-key');
      expect(result).toBeUndefined();
    });

    it('should gracefully handle and return undefined on JSON parsing failures', async () => {
      mockClient.get.mockResolvedValue('{"malformed_json...'); // Triggers catch { return undefined; }
      
      const result = await store.get('corrupted-key');
      
      expect(mockClient.get).toHaveBeenCalledWith('corrupted-key');
      expect(result).toBeUndefined();
    });

    it('should return parsed IdempotencyEntry when successfully retrieved', async () => {
      const entry = { status: 200, body: { success: true }, requestHash: 'hash123', createdAt: 123456789 };
      mockClient.get.mockResolvedValue(JSON.stringify(entry));
      
      const result = await store.get('valid-key');
      
      expect(mockClient.get).toHaveBeenCalledWith('valid-key');
      expect(result).toEqual(entry);
    });

    it('should fallback to primary client if readonly client misses', async () => {
      const readonlyClient = { get: vi.fn().mockResolvedValue(null) } as unknown as RedisClientLike;
      mockClient.get.mockResolvedValue(JSON.stringify({ status: 201 }));
      
      const storeWithRo = new RedisIdempotencyStore(mockClient, readonlyClient);
      const result = await storeWithRo.get('test-key');
      
      expect(readonlyClient.get).toHaveBeenCalledWith('test-key');
      expect(mockClient.get).toHaveBeenCalledWith('test-key');
      expect(result).toEqual({ status: 201 });
    });
  });

  describe('executeBatch()', () => {
    it('should throw and reject batch when pipeline returns empty results', async () => {
      const mockPipeline = {
        get: vi.fn(),
        // Trigger "if (!results) throw new Error('Pipeline returned empty results');"
        exec: vi.fn().mockResolvedValue(null) 
      };
      mockClient.pipeline.mockReturnValue(mockPipeline);

      const resolve = vi.fn();
      const reject = vi.fn();
      const batch = [{ key: 'k1', resolve, reject }];

      // Access private method for coverage
      await (store as any).executeBatch(batch);

      expect(reject).toHaveBeenCalledWith(expect.objectContaining({
        message: 'Pipeline returned empty results'
      }));
      expect(resolve).not.toHaveBeenCalled();
    });

    it('should resolve batch items successfully with pipeline', async () => {
      const mockPipeline = {
        get: vi.fn(),
        exec: vi.fn().mockResolvedValue([
          [null, '{"status":200}'] // [Error | null, string | null]
        ])
      };
      mockClient.pipeline.mockReturnValue(mockPipeline);

      const resolve = vi.fn();
      const reject = vi.fn();
      const batch = [{ key: 'k1', resolve, reject }];

      await (store as any).executeBatch(batch);

      expect(resolve).toHaveBeenCalledWith('{"status":200}');
      expect(reject).not.toHaveBeenCalled();
    });

    it('should reject individual batch items when pipeline contains item-level error', async () => {
      const mockPipeline = {
        get: vi.fn(),
        exec: vi.fn().mockResolvedValue([
          [new Error('Item lookup failed'), null]
        ])
      };
      mockClient.pipeline.mockReturnValue(mockPipeline);

      const resolve = vi.fn();
      const reject = vi.fn();
      const batch = [{ key: 'k1', resolve, reject }];

      await (store as any).executeBatch(batch);

      expect(reject).toHaveBeenCalledWith(expect.objectContaining({
        message: 'Item lookup failed'
      }));
      expect(resolve).not.toHaveBeenCalled();
    });

    it('should completely reject all items if pipeline exec throws entirely', async () => {
      const mockPipeline = {
        get: vi.fn(),
        exec: vi.fn().mockRejectedValue(new Error('Connection completely lost'))
      };
      mockClient.pipeline.mockReturnValue(mockPipeline);

      const resolve = vi.fn();
      const reject = vi.fn();
      const batch = [{ key: 'k1', resolve, reject }];

      await (store as any).executeBatch(batch);

      expect(reject).toHaveBeenCalledWith(expect.objectContaining({
        message: 'Connection completely lost'
      }));
    });

    it('should use fallback promise execution if pipeline() is not available on client', async () => {
      mockClient.pipeline = undefined; // Force fallback logic
      mockClient.get.mockResolvedValue('{"status":204}');

      const resolve = vi.fn();
      const reject = vi.fn();
      const batch = [{ key: 'k1', resolve, reject }];

      await (store as any).executeBatch(batch);

      expect(mockClient.get).toHaveBeenCalledWith('k1');
      expect(resolve).toHaveBeenCalledWith('{"status":204}');
    });

    it('should reject gracefully in fallback promise execution when get throws', async () => {
      mockClient.pipeline = undefined;
      mockClient.get.mockRejectedValue(new Error('Client GET failed'));

      const resolve = vi.fn();
      const reject = vi.fn();
      const batch = [{ key: 'k1', resolve, reject }];

      await (store as any).executeBatch(batch);

      expect(mockClient.get).toHaveBeenCalledWith('k1');
      expect(reject).toHaveBeenCalledWith(expect.objectContaining({
        message: 'Client GET failed'
      }));
    });
  });
});
