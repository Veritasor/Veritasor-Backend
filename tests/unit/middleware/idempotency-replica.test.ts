import { describe, it, expect, vi, beforeEach } from 'vitest';
import { RedisIdempotencyStore, type RedisClientLike } from '../../../src/middleware/idempotency.js';

describe('RedisIdempotencyStore - Replica Reads', () => {
  let mockPrimaryClient: RedisClientLike;
  let mockReplicaClient: RedisClientLike;

  beforeEach(() => {
    mockPrimaryClient = {
      get: vi.fn(),
      set: vi.fn(),
      del: vi.fn(),
    };
    mockReplicaClient = {
      get: vi.fn(),
      set: vi.fn(),
      del: vi.fn(),
    };
  });

  it('routes reads to replica if available', async () => {
    const store = new RedisIdempotencyStore(mockPrimaryClient, mockReplicaClient);
    (mockReplicaClient.get as any).mockResolvedValue(JSON.stringify({
      status: 200,
      body: 'replica_data',
      requestHash: 'h1',
      createdAt: 0
    }));

    const result = await store.get('key1');

    expect(mockReplicaClient.get).toHaveBeenCalledWith('key1');
    expect(mockPrimaryClient.get).not.toHaveBeenCalled();
    expect(result?.body).toBe('replica_data');
  });

  it('falls back to primary if replica returns cache miss (staleness)', async () => {
    const store = new RedisIdempotencyStore(mockPrimaryClient, mockReplicaClient);
    (mockReplicaClient.get as any).mockResolvedValue(null); // Cache miss on replica
    (mockPrimaryClient.get as any).mockResolvedValue(JSON.stringify({
      status: 200,
      body: 'primary_data',
      requestHash: 'h1',
      createdAt: 0
    }));

    const result = await store.get('key1');

    expect(mockReplicaClient.get).toHaveBeenCalledWith('key1');
    expect(mockPrimaryClient.get).toHaveBeenCalledWith('key1');
    expect(result?.body).toBe('primary_data');
  });

  it('returns undefined if both replica and primary miss', async () => {
    const store = new RedisIdempotencyStore(mockPrimaryClient, mockReplicaClient);
    (mockReplicaClient.get as any).mockResolvedValue(null);
    (mockPrimaryClient.get as any).mockResolvedValue(null);

    const result = await store.get('key1');

    expect(mockReplicaClient.get).toHaveBeenCalledWith('key1');
    expect(mockPrimaryClient.get).toHaveBeenCalledWith('key1');
    expect(result).toBeUndefined();
  });

  it('uses primary if no replica is provided', async () => {
    const store = new RedisIdempotencyStore(mockPrimaryClient);
    (mockPrimaryClient.get as any).mockResolvedValue(JSON.stringify({
      status: 200,
      body: 'primary_data',
      requestHash: 'h1',
      createdAt: 0
    }));

    const result = await store.get('key1');

    expect(mockPrimaryClient.get).toHaveBeenCalledWith('key1');
    expect(result?.body).toBe('primary_data');
  });

  it('handles replica rejection correctly (bubbles error)', async () => {
    const store = new RedisIdempotencyStore(mockPrimaryClient, mockReplicaClient);
    const redisError = new Error('Replica disconnected');
    (mockReplicaClient.get as any).mockRejectedValue(redisError);

    await expect(store.get('key1')).rejects.toThrow('Replica disconnected');
    expect(mockPrimaryClient.get).not.toHaveBeenCalled();
  });
});
