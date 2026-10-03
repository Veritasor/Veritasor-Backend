import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { RedisIdempotencyStore, type RedisClientLike } from '../../../src/middleware/idempotency.js';

describe('RedisIdempotencyStore - Pipelining', () => {
  let mockPipelineExec: any;
  let mockPipelineGet: any;
  let mockClient: RedisClientLike;
  let store: RedisIdempotencyStore;

  beforeEach(() => {
    vi.useFakeTimers();

    mockPipelineGet = vi.fn();
    mockPipelineExec = vi.fn().mockResolvedValue([]);

    mockClient = {
      get: vi.fn(),
      set: vi.fn(),
      del: vi.fn(),
      pipeline: vi.fn().mockReturnValue({
        get: mockPipelineGet,
        exec: mockPipelineExec
      })
    };

    store = new RedisIdempotencyStore(mockClient);
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('batches multiple get requests into a single pipeline', async () => {
    mockPipelineExec.mockResolvedValue([
      [null, JSON.stringify({ status: 200, body: 'res1', requestHash: 'h1', createdAt: 0 })],
      [null, JSON.stringify({ status: 201, body: 'res2', requestHash: 'h2', createdAt: 0 })],
    ]);

    const p1 = store.get('key1');
    const p2 = store.get('key2');
    
    // Advance time by batchWindowMs
    vi.advanceTimersByTime(5);

    const [res1, res2] = await Promise.all([p1, p2]);

    expect(mockClient.pipeline).toHaveBeenCalledOnce();
    expect(mockPipelineGet).toHaveBeenCalledTimes(2);
    expect(mockPipelineGet).toHaveBeenNthCalledWith(1, 'key1');
    expect(mockPipelineGet).toHaveBeenNthCalledWith(2, 'key2');
    expect(mockPipelineExec).toHaveBeenCalledOnce();

    expect(res1?.body).toBe('res1');
    expect(res2?.body).toBe('res2');
  });

  it('handles partial pipeline failures', async () => {
    const redisError = new Error('Some redis error');
    mockPipelineExec.mockResolvedValue([
      [null, JSON.stringify({ status: 200, body: 'res1', requestHash: 'h1', createdAt: 0 })],
      [redisError, null],
    ]);

    const p1 = store.get('key1');
    const p2 = store.get('key2');
    
    vi.advanceTimersByTime(5);

    await expect(p1).resolves.toBeDefined();
    await expect(p2).rejects.toThrow('Some redis error');
  });

  it('handles complete pipeline execution failure', async () => {
    mockPipelineExec.mockRejectedValue(new Error('Connection dropped'));

    const p1 = store.get('key1');
    const p2 = store.get('key2');
    
    vi.advanceTimersByTime(5);

    await expect(p1).rejects.toThrow('Connection dropped');
    await expect(p2).rejects.toThrow('Connection dropped');
  });

  it('flushes immediately if max batch size is reached', async () => {
    mockPipelineExec.mockResolvedValue(Array(100).fill([null, null]));

    const promises = [];
    for (let i = 0; i < 100; i++) {
      promises.push(store.get(`key${i}`));
    }
    
    // Batch should flush immediately at size 100 without waiting for timer
    expect(mockClient.pipeline).toHaveBeenCalledOnce();
    expect(mockPipelineGet).toHaveBeenCalledTimes(100);
    
    await Promise.all(promises);
  });
  
  it('falls back to standard get if pipeline is not available on client', async () => {
    mockClient.pipeline = undefined as any;
    (mockClient.get as any).mockResolvedValueOnce(JSON.stringify({ status: 200, body: 'res1', requestHash: 'h1', createdAt: 0 }));
    (mockClient.get as any).mockResolvedValueOnce(null);
    
    const p1 = store.get('key1');
    const p2 = store.get('key2');
    
    vi.advanceTimersByTime(5);
    
    const [res1, res2] = await Promise.all([p1, p2]);
    
    expect(mockClient.get).toHaveBeenCalledTimes(2);
    expect(res1?.body).toBe('res1');
    expect(res2).toBeUndefined();
  });
});
