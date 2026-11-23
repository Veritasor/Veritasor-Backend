import { logger } from '../../utils/logger.js';
import { idempotencyEvictionsTotal } from '../../metrics.js';
import type { IdempotencyEntry, IdempotencyStore } from './types.js';

/**
 * In-memory storage for idempotency entries
 * Note: This is suitable for single-instance deployments only.
 * For production, use Redis or similar distributed cache.
 *
 * Safety: Implements a basic size limit to prevent memory exhaustion.
 */
const MAX_MEMORY_STORE_SIZE = 10000;
const memoryStore = new Map<string, { entry: IdempotencyEntry | null; inFlight?: boolean; expiresAt: number }>();

/**
 * Internal helper: prune entries whose TTL has elapsed and return the
 * number of evictions. Never throws; safe to call from the sweeper or
 * from `set()` when the store is at the overflow boundary.
 */
function pruneExpiredMemoryStore(now: number = Date.now()): number {
  let evicted = 0;
  for (const [k, v] of memoryStore) {
    if (now > v.expiresAt) {
      memoryStore.delete(k);
      evicted += 1;
    }
  }
  return evicted;
}

/**
 * Default in-memory idempotency store
 * @exports inMemoryIdempotencyStore
 */
export const inMemoryIdempotencyStore: IdempotencyStore = {
  /**
   * Get a cached idempotency entry
   */
  async get(key: string): Promise<IdempotencyEntry | undefined> {
    const row = memoryStore.get(key);
    if (!row) return undefined;

    // Check expiration
    if (Date.now() > row.expiresAt) {
      memoryStore.delete(key);
      return undefined;
    }

    if (row.inFlight || !row.entry) {
      return undefined;
    }

    return row.entry;
  },

  /**
   * Reserve an idempotency key atomically for an in-flight request
   */
  async reserve(key: string, ttlMs: number): Promise<boolean> {
    const now = Date.now();
    const existing = memoryStore.get(key);
    if (existing && existing.expiresAt > now) {
      return false;
    }

    if (memoryStore.size >= MAX_MEMORY_STORE_SIZE) {
      pruneExpiredMemoryStore(now);
      if (memoryStore.size >= MAX_MEMORY_STORE_SIZE) {
        return false;
      }
    }

    memoryStore.set(key, {
      entry: null,
      inFlight: true,
      expiresAt: now + ttlMs,
    });
    return true;
  },

  /**
   * Store an idempotency entry
   */
  async set(key: string, entry: IdempotencyEntry, ttlMs: number): Promise<void> {
    // Basic memory protection: if store is too large, clear old entries or just stop
    // In a real LRU we'd evict the oldest, but here we just prevent unbounded growth
    if (memoryStore.size >= MAX_MEMORY_STORE_SIZE) {
      logger.warn(`[idempotency] Memory store reached limit (${MAX_MEMORY_STORE_SIZE}). Pruning expired entries.`);
      const evicted = pruneExpiredMemoryStore();
      if (evicted > 0) {
        idempotencyEvictionsTotal.inc({ backend: 'memory', reason: 'overflow' }, evicted);
      }

      // If still too large, stop adding to prevent OOM
      if (memoryStore.size >= MAX_MEMORY_STORE_SIZE) {
        logger.error('[idempotency] Memory store still at limit after pruning. Skipping cache set.');
        return;
      }
    }

    memoryStore.set(key, {
      entry,
      inFlight: false,
      expiresAt: Date.now() + ttlMs,
    });
  },

  /**
   * Delete a specific entry
   */
  async delete(key: string): Promise<void> {
    if (memoryStore.delete(key)) {
      idempotencyEvictionsTotal.inc({ backend: 'memory', reason: 'manual' });
    }
  },

  /**
   * Clear all entries
   */
  async clear(): Promise<void> {
    memoryStore.clear();
  },

  /**
   * Evict entries past TTL and return the number of evictions.
   * Emits `idempotency_evictions_total{reason="expired"}` for accounting.
   */
  async sweepExpired(): Promise<number> {
    const evicted = pruneExpiredMemoryStore();
    if (evicted > 0) {
      idempotencyEvictionsTotal.inc({ backend: 'memory', reason: 'expired' }, evicted);
    }
    return evicted;
  },

  /**
   * Snapshot of the current key count. This is O(1) — the gauge is
   * driven from the Map's `size`, never from a full enumeration.
   */
  async count(): Promise<number> {
    return memoryStore.size;
  },
};

/**
 * Clear the in-memory idempotency store (useful for testing)
 * @deprecated Use store.clear() instead
 */
export function clearIdempotencyStore(): void {
  memoryStore.clear();
}
