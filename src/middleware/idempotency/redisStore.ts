import { logger } from '../../utils/logger.js';
import { idempotencyBatchSize } from '../../metrics.js';
import { redisCircuitBreaker } from '../../redis.js';
import type { IdempotencyEntry, IdempotencyStore, RedisClientLike } from './types.js';

interface BatchItem {
  key: string;
  resolve: (value: string | null) => void;
  reject: (error: Error) => void;
}

/**
 * Redis-backed idempotency store. Works with both single-node and cluster
 * clients from `src/redis.ts`. Keys are stored as JSON strings with a TTL
 * set via PEXPIRE so no background sweep is needed for eviction — Redis
 * self-evicts. The sweeper still uses `count()` to populate the
 * storage-pressure gauge.
 *
 * `scanForCount` is the (optional) SCAN helper used by `count()`. It is
 * exposed separately so tests can inject a deterministic implementation
 * without monkey-patching the redis client.
 */
export class RedisIdempotencyStore implements IdempotencyStore {
  private batch: BatchItem[] = [];
  private batchTimer: NodeJS.Timeout | null = null;
  private readonly maxBatchSize = 100;
  private readonly batchWindowMs = 5;

  constructor(
    private client: RedisClientLike,
    private readonlyClient?: RedisClientLike,
    private readonly options: { scanMatch?: string; scanCount?: number } = {},
  ) {}

  private flushBatch = () => {
    if (this.batch.length === 0) return;
    const currentBatch = this.batch;
    this.batch = [];
    if (this.batchTimer) {
      clearTimeout(this.batchTimer);
      this.batchTimer = null;
    }

    idempotencyBatchSize.observe(currentBatch.length);

    this.executeBatch(currentBatch).catch(err => {
      logger.error('[idempotency] Batch execution failed (should not happen)', err);
    });
  }

  private async executeBatch(batch: BatchItem[]) {
    try {
      if (typeof this.client.pipeline === 'function') {
        const pipeline = this.client.pipeline();
        for (const item of batch) {
          pipeline.get(item.key);
        }

        // ioredis pipeline.exec() returns an array of [Error | null, result] tuples
        // If the whole pipeline execution fails (e.g. connection error), it might throw
        const results = await pipeline.exec();

        if (!results) {
          throw new Error('Pipeline returned empty results');
        }

        for (let i = 0; i < batch.length; i++) {
          const [err, val] = results[i] as [Error | null, string | null];
          if (err) {
            batch[i].reject(err);
          } else {
            batch[i].resolve(val);
          }
        }
      } else {
        // Fallback for mocks/tests that don't implement pipeline()
        await Promise.all(batch.map(async item => {
          try {
            const val = await this.client.get(item.key);
            item.resolve(val);
          } catch (err) {
            item.reject(err instanceof Error ? err : new Error(String(err)));
          }
        }));
      }
    } catch (err) {
      // Handle partial or complete pipeline failure
      const error = err instanceof Error ? err : new Error(String(err));
      for (const item of batch) {
        item.reject(error);
      }
    }
  }

  async get(key: string): Promise<IdempotencyEntry | undefined> {
    const readClient = this.readonlyClient ?? this.client;
    let raw = await readClient.get(key);

    // Fallback to primary on staleness (cache miss)
    if (!raw && this.readonlyClient) {
      raw = await this.client.get(key);
    }

    if (!raw) return undefined;
    try {
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === 'object' && parsed.inFlight === true) {
        return undefined;
      }
      return parsed as IdempotencyEntry;
    } catch {
      return undefined;
    }
  }

  async reserve(key: string, ttlMs: number): Promise<boolean> {
    const reservationPayload = JSON.stringify({ inFlight: true, createdAt: Date.now() });
    const result = await redisCircuitBreaker.execute(
      () => this.client.set(key, reservationPayload, 'PX', ttlMs, 'NX'),
      () => null
    );
    return result === 'OK' || result === true;
  }

  async set(key: string, entry: IdempotencyEntry, ttlMs: number): Promise<void> {
    await redisCircuitBreaker.execute(
      () => this.client.set(key, JSON.stringify(entry), 'PX', ttlMs),
      () => {} // Fallback to no-op
    );
  }

  async delete(key: string): Promise<void> {
    await redisCircuitBreaker.execute(
      () => this.client.del(key),
      () => {} // Fallback to no-op
    );
  }

  /**
   * Redis already evicts expired keys via PEXPIRE, so there is nothing
   * to do here. Returning 0 keeps the sweeper's accounting honest:
   * it counts the work that this store actually performed.
   */
  async sweepExpired(): Promise<number> {
    return 0;
  }

  /**
   * Best-effort keyspace walk using SCAN. SCAN is non-blocking and
   * cursor-paged, so the sweeper never stalls the request path even
   * on multi-million key sets.
   *
   * Returns -1 when the underlying client lacks SCAN support (e.g. an
   * in-memory mock used in unit tests); the gauge is then left stale
   * for that cycle.
   */
  async count(): Promise<number> {
    if (typeof this.client.scan !== 'function') {
      return -1;
    }

    const match = this.options.scanMatch ?? 'idempotency:*';
    const count = this.options.scanCount ?? 500;

    let cursor: string | number = '0';
    let total = 0;

    do {
      // ioredis signature: scan(cursor, 'MATCH', pattern, 'COUNT', count)
      const result = await redisCircuitBreaker.execute(
        () => this.client.scan!(cursor, 'MATCH', match, 'COUNT', count),
        () => undefined // Fallback to undefined on breaker open
      ) as [string | number, string[]] | undefined;

      if (!result || !Array.isArray(result)) {
        break;
      }

      const [next, keys] = result;
      cursor = next;
      if (Array.isArray(keys)) {
        total += keys.length;
      }
    } while (cursor !== '0' && cursor !== 0);

    return total;
  }
}

/**
 * Helper to create the canonical Redis-backed idempotency store used by
 * the application. The store is wired to the shared Redis / Cluster
 * client from `src/redis.ts`.
 *
 * Returns `null` when neither `REDIS_URL` nor `REDIS_CLUSTER_NODES` is
 * configured, so the caller can fall back to the in-memory store.
 */
export async function createRedisIdempotencyStore(): Promise<RedisIdempotencyStore | null> {
  const hasRedis =
    Boolean(process.env.REDIS_URL) || Boolean(process.env.REDIS_CLUSTER_NODES);
  if (!hasRedis) return null;

  // Lazy import to avoid a hard dependency on the redis module in
  // single-process environments (tests, in-memory dev).
  const mod = (await import('../../redis.js')) as {
    getRedisClient: () => RedisClientLike;
    getReadonlyRedisClient: () => RedisClientLike;
  };
  return new RedisIdempotencyStore(mod.getRedisClient(), mod.getReadonlyRedisClient());
}
