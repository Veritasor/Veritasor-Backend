import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// ---------------------------------------------------------------------------
// Redis mock — dataExportRepository resolves getRedisClient() on every call,
// so a stateful in-memory stub replaces src/redis.js entirely. Expiry
// semantics mirror Redis: a key read after its TTL has elapsed is treated as
// deleted, which makes boundary behavior observable and deterministic.
// ---------------------------------------------------------------------------

interface StoredValue {
  value: string;
  expiresAt: number | null;
}

function createRedisStub() {
  const store = new Map<string, StoredValue>();
  const calls = {
    setex: [] as Array<{ key: string; ttl: number; value: string }>,
    set: [] as Array<{ key: string; value: string }>,
    get: [] as string[],
    del: [] as string[],
  };

  const client = {
    setex: vi.fn(async (key: string, ttl: number, value: string) => {
      calls.setex.push({ key, ttl, value });
      store.set(key, { value, expiresAt: ttl > 0 ? Date.now() + ttl * 1000 : null });
      return 'OK';
    }),
    set: vi.fn(async (key: string, value: string) => {
      calls.set.push({ key, value });
      store.set(key, { value, expiresAt: null });
      return 'OK';
    }),
    get: vi.fn(async (key: string) => {
      calls.get.push(key);
      const entry = store.get(key);
      if (!entry) return null;
      if (entry.expiresAt !== null && entry.expiresAt <= Date.now()) {
        store.delete(key);
        return null;
      }
      return entry.value;
    }),
    del: vi.fn(async (key: string) => {
      calls.del.push(key);
      return store.delete(key) ? 1 : 0;
    }),
  };

  return { store, calls, client };
}

let redis: ReturnType<typeof createRedisStub>;

vi.mock('../../../src/redis.js', () => ({
  getRedisClient: () => redis.client,
  redisCircuitBreaker: {
    execute: async <T>(fn: () => Promise<T>) => fn(),
    getState: () => 'CLOSED',
    reset: () => {},
  },
}));

// ---------------------------------------------------------------------------
// Module under test (imported after the mock is registered)
// ---------------------------------------------------------------------------

import {
  createDataExport,
  getDataExport,
  updateDataExportStatus,
  createDownloadToken,
  consumeDownloadToken,
  getUserDataExports,
  deleteDataExport,
  type DataExport,
  type DataExportToken,
} from '../../../src/repositories/dataExportRepository.js';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const USER_ID = 'user-123';
const SEVEN_DAYS_SECONDS = 7 * 24 * 60 * 60;
const TWENTY_FOUR_HOURS_SECONDS = 24 * 60 * 60;

/** A valid DataExport for seeded-store scenarios. */
function makeExportRecord(overrides: Partial<DataExport> = {}): DataExport {
  const now = Date.now();
  return {
    id: 'seeded-export-id',
    userId: USER_ID,
    status: 'pending',
    createdAt: new Date(now),
    expiresAt: new Date(now + SEVEN_DAYS_SECONDS * 1000),
    ...overrides,
  };
}

function seedExport(overrides: Partial<DataExport> = {}): DataExport {
  const record = makeExportRecord(overrides);
  redis.store.set(`data-export:${record.id}`, {
    value: JSON.stringify(record),
    expiresAt: null,
  });
  return record;
}

function seedDownloadToken(token: string, exportId: string, downloaded = false): void {
  redis.store.set(`data-export-token:${token}`, {
    value: JSON.stringify({ exportId, downloaded }),
    expiresAt: null,
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/**
 * Records are persisted as JSON, so Date fields (createdAt, expiresAt,
 * completedAt, downloadedAt) deserialize as ISO strings, not Date instances.
 * These helpers make that contract explicit and keep comparisons deterministic.
 */
const iso = (d: Date | string | undefined): string => new Date(d as Date | string).toISOString();

describe('DataExportRepository', () => {
  beforeEach(() => {
    redis = createRedisStub();
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('createDataExport', () => {
    it('creates a pending export with a 32-char hex id and 7-day expiry', async () => {
      const before = Date.now();
      const record = await createDataExport(USER_ID);

      expect(record.id).toMatch(/^[0-9a-f]{32}$/);
      expect(record.userId).toBe(USER_ID);
      expect(record.status).toBe('pending');
      expect(record.createdAt).toBeInstanceOf(Date);
      expect(record.expiresAt).toBeInstanceOf(Date);
      expect(record.expiresAt.getTime() - record.createdAt.getTime()).toBe(SEVEN_DAYS_SECONDS * 1000);
      expect(record.createdAt.getTime()).toBeGreaterThanOrEqual(before);
      // Optional lifecycle fields are absent on creation.
      expect(record.completedAt).toBeUndefined();
      expect(record.downloadedAt).toBeUndefined();
      expect(record.error).toBeUndefined();
      expect(record.archiveSize).toBeUndefined();
    });

    it('persists the record under "data-export:<id>" with a 7-day TTL', async () => {
      const record = await createDataExport(USER_ID);
      const key = `data-export:${record.id}`;

      expect(redis.calls.setex).toHaveLength(1);
      expect(redis.calls.setex[0].key).toBe(key);
      expect(redis.calls.setex[0].ttl).toBe(SEVEN_DAYS_SECONDS);
      expect(JSON.parse(redis.calls.setex[0].value)).toEqual(JSON.parse(JSON.stringify(record)));
      expect(redis.store.get(key)).toBeDefined();
    });

    it('generates unique ids for consecutive creations', async () => {
      const a = await createDataExport(USER_ID);
      const b = await createDataExport(USER_ID);

      expect(a.id).not.toBe(b.id);
    });
  });

  describe('getDataExport', () => {
    it('returns the persisted record for an existing id (dates round-trip as ISO strings)', async () => {
      const seeded = seedExport();
      const retrieved = await getDataExport(seeded.id);

      expect(retrieved).not.toBeNull();
      expect(iso(retrieved!.createdAt)).toBe(iso(seeded.createdAt));
      expect(iso(retrieved!.expiresAt)).toBe(iso(seeded.expiresAt));
      expect(retrieved!.id).toBe(seeded.id);
      expect(retrieved!.userId).toBe(USER_ID);
      expect(retrieved!.status).toBe('pending');
      // Documented storage behavior: JSON round-trip means dates are strings.
      expect(retrieved!.createdAt).not.toBeInstanceOf(Date);
    });

    it('returns null for a non-existent id', async () => {
      expect(await getDataExport('non-existent-id')).toBeNull();
    });

    it('returns null once the stored record has expired (boundary)', async () => {
      vi.useFakeTimers();
      const start = new Date('2026-01-01T00:00:00Z');
      vi.setSystemTime(start);

      // Written with a real 7-day TTL, like production.
      const record = await createDataExport(USER_ID);
      expect(await getDataExport(record.id)).not.toBeNull();

      // One millisecond past expiry the key is gone.
      vi.setSystemTime(start.getTime() + SEVEN_DAYS_SECONDS * 1000 + 1);
      expect(await getDataExport(record.id)).toBeNull();
    });

    it('surfaces Redis failures instead of swallowing them', async () => {
      seedExport();
      vi.mocked(redis.client.get).mockRejectedValueOnce(new Error('Redis timeout'));

      await expect(getDataExport('seeded-export-id')).rejects.toThrow('Redis timeout');
    });
  });

  describe('updateDataExportStatus — primary state transitions', () => {
    it('transitions pending → processing and preserves existing fields', async () => {
      const seeded = seedExport();
      const updated = await updateDataExportStatus(seeded.id, 'processing');

      expect(updated).not.toBeNull();
      expect(updated!.status).toBe('processing');
      expect(updated!.userId).toBe(USER_ID);
      expect(updated!.completedAt).toBeUndefined();
    });

    it('transitions processing → completed, stamps completedAt, and applies partial updates', async () => {
      const seeded = seedExport({ status: 'processing' });
      const archiveSize = 2048;

      const updated = await updateDataExportStatus(seeded.id, 'completed', { archiveSize });

      expect(updated!.status).toBe('completed');
      expect(updated!.archiveSize).toBe(archiveSize);
      // completedAt is freshly stamped (a Date), not re-read from the store.
      expect(updated!.completedAt).toBeInstanceOf(Date);
      expect(updated!.completedAt!.getTime()).toBeGreaterThanOrEqual(seeded.createdAt.getTime());
    });

    it('transitions to failed with an error message and stamps completedAt', async () => {
      const seeded = seedExport();
      const updated = await updateDataExportStatus(seeded.id, 'failed', {
        error: 'archive generation failed',
      });

      expect(updated!.status).toBe('failed');
      expect(updated!.error).toBe('archive generation failed');
      expect(updated!.completedAt).toBeInstanceOf(Date);
    });

    it('does not overwrite an existing completedAt for non-terminal statuses', async () => {
      const originalCompletedAt = new Date('2026-01-01T00:00:00Z');
      const seeded = seedExport({ status: 'completed', completedAt: originalCompletedAt });

      const updated = await updateDataExportStatus(seeded.id, 'processing');

      expect(iso(updated!.completedAt)).toBe(iso(originalCompletedAt));
    });

    it('merges partial updates without clobbering unset fields', async () => {
      const seeded = seedExport();
      const updated = await updateDataExportStatus(seeded.id, 'completed', { archiveSize: 1 });

      expect(updated!.id).toBe(seeded.id);
      expect(updated!.userId).toBe(USER_ID);
      expect(iso(updated!.expiresAt)).toBe(iso(seeded.expiresAt));
    });

    it('returns null and writes nothing when the export does not exist (failure path)', async () => {
      expect(await updateDataExportStatus('non-existent-id', 'completed')).toBeNull();
      expect(redis.calls.setex).toHaveLength(0);
    });

    it('persists the transition with a refreshed 7-day TTL', async () => {
      const seeded = seedExport();
      await updateDataExportStatus(seeded.id, 'completed', { archiveSize: 1 });

      expect(redis.calls.setex).toHaveLength(1);
      expect(redis.calls.setex[0].ttl).toBe(SEVEN_DAYS_SECONDS);
    });
  });

  describe('createDownloadToken / DataExportToken', () => {
    it('creates a 64-char hex token stored with a 24h TTL and downloaded=false', async () => {
      const token = await createDownloadToken('some-export-id');

      expect(token).toMatch(/^[0-9a-f]{64}$/);
      expect(redis.calls.setex).toHaveLength(1);
      expect(redis.calls.setex[0].key).toBe(`data-export-token:${token}`);
      expect(redis.calls.setex[0].ttl).toBe(TWENTY_FOUR_HOURS_SECONDS);
      expect(JSON.parse(redis.calls.setex[0].value)).toEqual({
        exportId: 'some-export-id',
        downloaded: false,
      });
    });

    it('creates distinct tokens for different exports', async () => {
      const t1 = await createDownloadToken('export-a');
      const t2 = await createDownloadToken('export-b');

      expect(t1).not.toBe(t2);
    });
  });

  describe('consumeDownloadToken — one-time semantics', () => {
    it('returns the exportId on first use and marks the token as downloaded', async () => {
      seedDownloadToken('tok-1', 'export-1');

      const exportId = await consumeDownloadToken('tok-1');

      expect(exportId).toBe('export-1');
      expect(redis.calls.set).toHaveLength(1);
      expect(JSON.parse(redis.store.get('data-export-token:tok-1')!.value)).toEqual({
        exportId: 'export-1',
        downloaded: true,
      });
    });

    it('returns null on second use (one-time download enforced)', async () => {
      seedDownloadToken('tok-2', 'export-2');

      expect(await consumeDownloadToken('tok-2')).toBe('export-2');
      expect(await consumeDownloadToken('tok-2')).toBeNull();
    });

    it('returns null for a token that does not exist', async () => {
      expect(await consumeDownloadToken('missing-token')).toBeNull();
    });

    it('returns null for a token that was already downloaded before consumption', async () => {
      seedDownloadToken('tok-3', 'export-3', true);

      expect(await consumeDownloadToken('tok-3')).toBeNull();
      // Rejected tokens are not re-marked via set.
      expect(redis.calls.set).toHaveLength(0);
    });

    it('surfaces Redis failures instead of swallowing them', async () => {
      seedDownloadToken('tok-4', 'export-4');
      vi.mocked(redis.client.get).mockRejectedValueOnce(new Error('connection refused'));

      await expect(consumeDownloadToken('tok-4')).rejects.toThrow('connection refused');
    });
  });

  describe('getUserDataExports', () => {
    it('resolves to an empty list (no per-user index in this implementation)', async () => {
      seedExport();

      const exports = await getUserDataExports(USER_ID);

      expect(exports).toEqual([]);
    });
  });

  describe('deleteDataExport', () => {
    it('deletes an existing export and returns true', async () => {
      const seeded = seedExport();

      expect(await deleteDataExport(seeded.id)).toBe(true);
      expect(await getDataExport(seeded.id)).toBeNull();
      expect(redis.calls.del).toEqual([`data-export:${seeded.id}`]);
    });

    it('returns false when the export does not exist', async () => {
      expect(await deleteDataExport('non-existent-id')).toBe(false);
    });
  });
});
