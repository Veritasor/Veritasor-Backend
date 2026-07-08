/**
 * Idempotency Middleware
 * 
 * Provides request idempotency for API endpoints to prevent duplicate operations.
 * When a client sends an Idempotency-Key header, the middleware caches the response
 * and returns the cached response for duplicate requests within the TTL window.
 * 
 * Security Features:
 * - Key format validation (UUID format recommended)
 * - Key length constraints to prevent abuse
 * - Per-user key scoping to prevent cross-user collisions
 * - TTL-based expiration for automatic cleanup
 * 
 * @module middleware/idempotency
 * @version 1.0.0
 */

import { createHash } from 'node:crypto';
import type { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger.js';
import {
  idempotencyEvictionsTotal,
  idempotencyKeysCount,
  idempotencySweepRunsTotal,
} from '../metrics.js';

// ============================================================================
// Constants
// ============================================================================

/** Header name for idempotency key */
const IDEMPOTENCY_KEY_HEADER = 'idempotency-key';

/** Default TTL: 24 hours in milliseconds */
const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000;

/** Minimum key length to prevent trivial keys */
const MIN_KEY_LENGTH = 8;

/** Maximum key length to prevent abuse */
const MAX_KEY_LENGTH = 256;

/** Default key format: UUID pattern */
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// ============================================================================
// Types
// ============================================================================

/**
 * Cached response entry for idempotency
 * @interface IdempotencyEntry
 */
export interface IdempotencyEntry {
  /** HTTP status code of the original response */
  status: number;
  /** Response body (cached) */
  body: unknown;
  /** Hash of the original request body to detect collisions */
  requestHash: string;
  /** Timestamp when the entry was created */
  createdAt: number;
}

/**
 * Storage interface for idempotency entries
 * @interface IdempotencyStore
 */
export interface IdempotencyStore {
  /**
   * Retrieve a cached idempotency entry
   * @param key - The idempotency key
   * @returns The cached entry or undefined if not found/expired
   */
  get(key: string): Promise<IdempotencyEntry | undefined>;

  /**
   * Store an idempotency entry
   * @param key - The idempotency key
   * @param entry - The response entry to cache
   * @param ttlMs - Time to live in milliseconds
   */
  set(key: string, entry: IdempotencyEntry, ttlMs: number): Promise<void>;

  /**
   * Delete a specific entry (optional method)
   * @param key - The idempotency key to delete
   */
  delete?(key: string): Promise<void>;

  /**
   * Clear all entries (optional method)
   */
  clear?(): Promise<void>;

  /**
   * Evict entries whose TTL has elapsed and return the number of evictions.
   *
   * Optional. Stores that already self-evict (e.g. Redis with PEXPIRE) may
   * return 0; they still need a `count()` to drive the storage-pressure
   * gauge. The sweeper never blocks the request path: this method may do
   * work in chunks and is expected to be safe to call concurrently with
   * `get`/`set`/`delete`.
   */
  sweepExpired?(): Promise<number>;

  /**
   * Best-effort count of live entries.
   *
   * Returns -1 if the store cannot enumerate cheaply; the gauge is then
   * left untouched for that cycle. This is intentional: we never want the
   * sweeper to stall on a hot path.
   */
  count?(): Promise<number>;
}

/**
 * Configuration options for idempotency middleware
 * @interface IdempotencyOptions
 */
export interface IdempotencyOptions {
  /** Custom storage implementation */
  store?: IdempotencyStore;
  /** Scope identifier (e.g., 'attestations', 'payments') */
  scope: string;
  /** Custom TTL in milliseconds (default: 24 hours) */
  ttlMs?: number;
  /**
   * Custom function to identify the user/key for scoping
   * @param req - Express request object
   * @returns User identifier string
   */
  getUserKey?: (req: Request) => string;
  /**
   * Enable strict key format validation (default: false)
   * When true, keys must match UUID format
   */
  strictKeyFormat?: boolean;
  /**
   * Custom key validation function
   * @param key - The key to validate
   * @returns True if valid, false otherwise
   */
  validateKey?: (key: string) => boolean;
  /**
   * Skip idempotency check for certain requests
   * @param req - Express request object
   * @returns True to skip idempotency processing
   */
  skipIf?: (req: Request) => boolean;
}

// ============================================================================
// Redis Store Implementation
// ============================================================================

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
export interface RedisClientLike {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, px: 'PX', ms: number): Promise<unknown>;
  del(key: string): Promise<unknown>;
  scan?(cursor: string | number, ...args: unknown[]): Promise<unknown>;
}

export class RedisIdempotencyStore implements IdempotencyStore {
  constructor(
    private client: RedisClientLike,
    private readonly options: { scanMatch?: string; scanCount?: number } = {},
  ) {}

  async get(key: string): Promise<IdempotencyEntry | undefined> {
    const raw = await this.client.get(key);
    if (!raw) return undefined;
    try {
      return JSON.parse(raw) as IdempotencyEntry;
    } catch {
      return undefined;
    }
  }

  async set(key: string, entry: IdempotencyEntry, ttlMs: number): Promise<void> {
    await this.client.set(key, JSON.stringify(entry), 'PX', ttlMs);
  }

  async delete(key: string): Promise<void> {
    await this.client.del(key);
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
      const result = (await this.client.scan(cursor, 'MATCH', match, 'COUNT', count)) as
        | [string | number, string[]]
        | undefined;

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

// ============================================================================
// In-Memory Store Implementation
// ============================================================================

/**
 * In-memory storage for idempotency entries
 * Note: This is suitable for single-instance deployments only.
 * For production, use Redis or similar distributed cache.
 *
 * Safety: Implements a basic size limit to prevent memory exhaustion.
 */
const MAX_MEMORY_STORE_SIZE = 10000;
const memoryStore = new Map<string, { entry: IdempotencyEntry; expiresAt: number }>();

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

    return row.entry;
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

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Validate idempotency key format
 * @param key - The key to validate
 * @param strict - Whether to require UUID format
 * @returns True if valid
 */
function isValidKeyFormat(key: string, strict: boolean): boolean {
  // Check length constraints
  if (key.length < MIN_KEY_LENGTH || key.length > MAX_KEY_LENGTH) {
    return false;
  }
  
  // In strict mode, require UUID format
  if (strict && !UUID_PATTERN.test(key)) {
    return false;
  }
  
  return true;
}

/**
 * Generate store key from components
 * @param scope - Operation scope
 * @param userKey - User identifier
 * @param keyValue - Client-provided idempotency key
 * @returns Full store key
 */
function generateStoreKey(scope: string, userKey: string, keyValue: string): string {
  return `idempotency:${scope}:${userKey}:${keyValue}`;
}

/**
 * Generate a hash of the request body for integrity checking
 * @param body - Request body
 * @returns SHA-256 hash
 */
function generateRequestHash(body: unknown): string {
  const content = body ? JSON.stringify(body) : '';
  return createHash('sha256').update(content).digest('hex');
}

// ============================================================================
// Middleware Factory
// ============================================================================

/**
 * Creates idempotency middleware for protecting API endpoints
 * 
 * @example
 * ```typescript
 * // Basic usage
 * app.post('/api/attestations', 
 *   requireAuth,
 *   idempotencyMiddleware({ scope: 'attestations' }),
 *   handleAttestation
 * );
 * 
 * // With custom options
 * app.post('/api/payments',
 *   idempotencyMiddleware({
 *     scope: 'payments',
 *     ttlMs: 3600000, // 1 hour
 *     strictKeyFormat: true,
 *     getUserKey: (req) => req.user?.id ?? req.ip ?? 'anonymous',
 *   }),
 *   handlePayment
 * );
 * ```
 * 
 * @param options - Middleware configuration options
 * @returns Express middleware function
 */
export function idempotencyMiddleware(options: IdempotencyOptions) {
  const store = options.store ?? inMemoryIdempotencyStore;
  const scope = options.scope;
  const ttlMs = options.ttlMs ?? DEFAULT_TTL_MS;
  const getUserKey = options.getUserKey ?? ((req: Request) => {
    // Try to get user ID from authenticated request
    if (req.user && typeof req.user === 'object' && 'id' in req.user) {
      return (req.user as { id: string }).id;
    }
    return req.ip ?? 'anonymous';
  });
  const strictKeyFormat = options.strictKeyFormat ?? false;
  const validateKey = options.validateKey ?? ((key: string) => isValidKeyFormat(key, strictKeyFormat));
  const skipIf = options.skipIf ?? (() => false);

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    // Check if we should skip idempotency processing
    if (skipIf(req)) {
      next();
      return;
    }

    // Extract and validate idempotency key
    const rawKey = req.headers[IDEMPOTENCY_KEY_HEADER];
    const keyValue = typeof rawKey === 'string' 
      ? rawKey.trim() 
      : Array.isArray(rawKey) 
        ? rawKey[0]?.trim() 
        : undefined;

    // Validate key presence
    if (!keyValue) {
      res.status(400).json({
        error: 'Bad Request',
        message: `Missing ${IDEMPOTENCY_KEY_HEADER} header`,
        code: 'IDEMPOTENCY_KEY_REQUIRED',
      });
      return;
    }

    // Validate key format
    if (!validateKey(keyValue)) {
      res.status(400).json({
        error: 'Bad Request',
        message: `Invalid ${IDEMPOTENCY_KEY_HEADER} format. Key must be between ${MIN_KEY_LENGTH} and ${MAX_KEY_LENGTH} characters${getStrictKeyFormatMessage(strictKeyFormat)}`,
        code: 'IDEMPOTENCY_KEY_INVALID',
      });
      return;
    }

    // Generate unique key for this user + scope + key combination
    const userKey = getUserKey(req);
    const storeKey = generateStoreKey(scope, userKey, keyValue);
    const currentRequestHash = generateRequestHash(req.body);

    // Check for cached response
    const cached = await store.get(storeKey);
    if (cached) {
      // Verify body integrity to prevent key collisions with different payloads
      if (cached.requestHash !== currentRequestHash) {
        logger.warn(`[idempotency] Key collision detected for key: ${keyValue}. Payloads do not match.`);
        res.status(422).json({
          error: 'Unprocessable Entity',
          message: 'Idempotency key already used with a different request body',
          code: 'IDEMPOTENCY_KEY_COLLISION',
        });
        return;
      }

      logger.info(`[idempotency] Returning cached response for key: ${keyValue}`);
      // Return cached response
      res.status(cached.status).json(cached.body);
      return;
    }

    // Store original methods
    const originalJson = res.json.bind(res);
    const originalStatus = res.status.bind(res);
    let statusCode = 200;

    // Override status to track the actual status code
    res.status = function (code: number): Response {
      statusCode = code;
      return originalStatus(code);
    };

    // Override json to cache the response
    res.json = function (body: unknown): Response {
      // Only cache successful responses (2xx)
      if (statusCode >= 200 && statusCode < 300) {
        const entry: IdempotencyEntry = {
          status: statusCode,
          body,
          requestHash: currentRequestHash,
          createdAt: Date.now(),
        };
        store.set(storeKey, entry, ttlMs).catch((err) => {
          logger.error('[idempotency] Failed to cache response:', err);
        });
      }
      return originalJson(body);
    };

    // Continue to route handler
    next();
  };
}

/**
 * Helper to generate the strict format message
 */
function getStrictKeyFormatMessage(strict: boolean): string {
  return strict ? ' and must be a valid UUID' : '';
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Clear the in-memory idempotency store (useful for testing)
 * @deprecated Use store.clear() instead
 */
export function clearIdempotencyStore(): void {
  memoryStore.clear();
}

/**
 * Get the default TTL value
 * @returns Default TTL in milliseconds
 */
export function getDefaultTtl(): number {
  return DEFAULT_TTL_MS;
}

/**
 * Get the header name for idempotency key
 * @returns Header name
 */
export function getIdempotencyHeaderName(): string {
  return IDEMPOTENCY_KEY_HEADER;
}

// ============================================================================
// Re-export for convenience
// ============================================================================

export { IDEMPOTENCY_KEY_HEADER };

// ============================================================================
// Cooperative Sweeper
// ============================================================================

/** Default sweep interval: 60 seconds. */
const DEFAULT_SWEEP_INTERVAL_MS = 60_000;

/** Hard ceiling so a misconfigured `IDEMPOTENCY_SWEEP_INTERVAL_MS`
 *  cannot accidentally DoS the process. */
const MIN_SWEEP_INTERVAL_MS = 1_000;

export type IdempotencyBackend = 'memory' | 'redis';

/** Result of a single sweep cycle. Useful in tests and structured logs. */
export interface SweepResult {
  backend: IdempotencyBackend;
  evicted: number;
  /** Set to the live key count after the sweep, or -1 if unavailable. */
  keys: number;
  /** Always false if the cycle completed without throwing. */
  errored: boolean;
  durationMs: number;
}

export interface IdempotencySweeperOptions {
  store: IdempotencyStore;
  backend: IdempotencyBackend;
  /** How often the sweeper runs. Defaults to 60s. */
  intervalMs?: number;
  /**
   * When true, `start()` schedules the first sweep on the next tick
   * rather than after one full interval. Defaults to true so that SREs
   * see gauge data immediately after boot.
   */
  runImmediately?: boolean;
  /** Injected for tests. Defaults to the global timer functions. */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  setIntervalFn?: (cb: () => void, ms: number) => any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  clearIntervalFn?: (handle: any) => void;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  setTimeoutFn?: (cb: () => void, ms: number) => any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  clearTimeoutFn?: (handle: any) => void;
  /** Injected for tests. Defaults to the structured `logger`. */
  log?: typeof logger;
}

/**
 * Cooperative, non-blocking TTL sweeper for the idempotency store.
 *
 * Design constraints (intentional):
 *
 * - The interval is unref'd so the sweeper never keeps the event loop
 *   alive on its own. This is the "cooperative" promise: the process
 *   can exit at any time without waiting for the next cycle.
 *
 * - `runOnce()` swallows all store errors and emits a metric with
 *   `outcome="error"`. A single Redis blip must not break the loop or
 *   pin the process; the ioredis client handles reconnection and the
 *   next cycle will simply succeed.
 *
 * - `stop()` is idempotent and safe to call from shutdown handlers even
 *   while a cycle is in flight: the in-flight cycle is awaited, so the
 *   caller can rely on a quiescent state before exit.
 *
 * - `sweepExpired` and `count` are both optional. The sweeper no-ops
 *   gracefully when neither is present (e.g. a custom store that does
 *   its own retention).
 */
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
  const mod = (await import('../redis.js')) as {
    getRedisClient: () => RedisClientLike;
  };
  return new RedisIdempotencyStore(mod.getRedisClient());
}

/**
 * Parse the sweep interval from `IDEMPOTENCY_SWEEP_INTERVAL_MS`, applying
 * a hard floor so a misconfigured value cannot turn the sweeper into a
 * tight loop. Returns the resolved interval in milliseconds.
 */
export function resolveSweepIntervalMs(): number {
  const raw = process.env.IDEMPOTENCY_SWEEP_INTERVAL_MS;
  if (raw === undefined || raw === '') return DEFAULT_SWEEP_INTERVAL_MS;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    return DEFAULT_SWEEP_INTERVAL_MS;
  }
  return Math.max(MIN_SWEEP_INTERVAL_MS, parsed);
}

export interface IdempotencySweeperHandle {
  sweeper: IdempotencySweeper;
  backend: IdempotencyBackend;
  stop: () => Promise<void>;
}

/**
 * Start the application-wide idempotency sweeper.
 *
 * - When a Redis store is configured, the sweeper runs against it.
 * - Otherwise it runs against the in-memory store.
 *
 * The interval is read from `IDEMPOTENCY_SWEEP_INTERVAL_MS` (default
 * 60s, hard floor 1s). The returned handle exposes `stop()` for
 * graceful shutdown.
 */
export async function startIdempotencySweeper(): Promise<IdempotencySweeperHandle | null> {
  const redisStore = await createRedisIdempotencyStore();
  const intervalMs = resolveSweepIntervalMs();

  if (redisStore) {
    const sweeper = new IdempotencySweeper({
      store: redisStore,
      backend: 'redis',
      intervalMs,
    });
    sweeper.start();
    return {
      sweeper,
      backend: 'redis',
      stop: () => sweeper.stop(),
    };
  }

  // The in-memory store has no external dependencies; we always run a
  // sweeper against it so SREs get the same gauge for single-process
  // deployments as they do for cluster deployments.
  const sweeper = new IdempotencySweeper({
    store: inMemoryIdempotencyStore,
    backend: 'memory',
    intervalMs,
  });
  sweeper.start();
  return {
    sweeper,
    backend: 'memory',
    stop: () => sweeper.stop(),
  };
}

export class IdempotencySweeper {
  private readonly store: IdempotencyStore;
  private readonly backend: IdempotencyBackend;
  private readonly intervalMs: number;
  private readonly runImmediately: boolean;
  // The global setTimeout/setInterval signatures union DOM and Node
  // overloads; cast at the boundary so the class compiles cleanly.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private readonly setIntervalFn: (cb: () => void, ms: number) => any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private readonly clearIntervalFn: (handle: any) => void;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private readonly setTimeoutFn: (cb: () => void, ms: number) => any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private readonly clearTimeoutFn: (handle: any) => void;
  private readonly log: typeof logger;

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private intervalHandle: any = null;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private timeoutHandle: any = null;
  private inflight: Promise<SweepResult> | null = null;
  private stopped = false;

  constructor(options: IdempotencySweeperOptions) {
    this.store = options.store;
    this.backend = options.backend;
    const requested = options.intervalMs ?? DEFAULT_SWEEP_INTERVAL_MS;
    this.intervalMs = Math.max(MIN_SWEEP_INTERVAL_MS, requested);
    this.runImmediately = options.runImmediately ?? true;
    this.setIntervalFn = options.setIntervalFn ?? setInterval;
    this.clearIntervalFn = options.clearIntervalFn ?? clearInterval;
    this.setTimeoutFn = options.setTimeoutFn ?? setTimeout;
    this.clearTimeoutFn = options.clearTimeoutFn ?? clearTimeout;
    this.log = options.log ?? logger;
  }

  /** Whether the background interval is currently scheduled. */
  isRunning(): boolean {
    return this.intervalHandle !== null;
  }

  /** Schedule the periodic sweep. Safe to call multiple times. */
  start(): void {
    if (this.isRunning()) return;

    this.stopped = false;

    if (this.runImmediately) {
      // Use a setTimeout(0) so we never block the caller (e.g. boot
      // sequence) on a sweep that might be slow on a hot Redis.
      this.timeoutHandle = this.setTimeoutFn(() => {
        this.timeoutHandle = null;
        void this.runOnce();
      }, 0);
      if (typeof this.timeoutHandle.unref === 'function') {
        this.timeoutHandle.unref();
      }
    }

    this.intervalHandle = this.setIntervalFn(() => {
      void this.runOnce();
    }, this.intervalMs);
    // CRITICAL: an unref'd interval does not keep the event loop alive.
    // The sweeper must never block process exit.
    if (typeof this.intervalHandle.unref === 'function') {
      this.intervalHandle.unref();
    }
  }

  /**
   * Cancel future sweeps and wait for any in-flight cycle to finish.
   * Idempotent: calling `stop()` twice is safe and resolves immediately
   * the second time.
   */
  async stop(): Promise<void> {
    if (this.stopped && !this.inflight) return;
    this.stopped = true;

    if (this.timeoutHandle !== null) {
      this.clearTimeoutFn(this.timeoutHandle);
      this.timeoutHandle = null;
    }

    if (this.intervalHandle !== null) {
      this.clearIntervalFn(this.intervalHandle);
      this.intervalHandle = null;
    }

    if (this.inflight) {
      try {
        await this.inflight;
      } catch {
        // runOnce() never throws, but be defensive so a future
        // refactor cannot wedge shutdown.
      }
    }
  }

  /**
   * Run a single sweep cycle. Concurrent callers (e.g. the interval
   * firing while a manual `runOnce()` is still working) share the
   * same in-flight promise — the sweeper never overlaps itself.
   *
   * Never throws. All errors are logged and surfaced as metrics.
   */
  runOnce(): Promise<SweepResult> {
    if (this.inflight) return this.inflight;

    const cycle = this.executeCycle()
      .catch((err: unknown) => {
        // Defensive: executeCycle already swallows everything, but if
        // a future change introduces a path that throws, we still
        // must not reject the in-flight promise (callers rely on it).
        const message = err instanceof Error ? err.message : String(err);
        this.log.error({
          event: 'idempotency_sweep_unexpected_error',
          backend: this.backend,
          error: message,
        });
        idempotencySweepRunsTotal.inc({ backend: this.backend, outcome: 'error' });
        return {
          backend: this.backend,
          evicted: 0,
          keys: -1,
          errored: true,
          durationMs: 0,
        } satisfies SweepResult;
      })
      .finally(() => {
        this.inflight = null;
      });

    this.inflight = cycle;
    return cycle;
  }

  private async executeCycle(): Promise<SweepResult> {
    const start = Date.now();
    let evicted = 0;
    let keys = -1;
    let errored = false;

    try {
      if (typeof this.store.sweepExpired === 'function') {
        evicted = await this.store.sweepExpired();
      }

      if (typeof this.store.count === 'function') {
        keys = await this.store.count();
        if (keys >= 0) {
          idempotencyKeysCount.set({ backend: this.backend }, keys);
        }
      }

      idempotencySweepRunsTotal.inc({ backend: this.backend, outcome: 'ok' });
    } catch (err) {
      errored = true;
      const message = err instanceof Error ? err.message : String(err);
      this.log.warn({
        event: 'idempotency_sweep_failed',
        backend: this.backend,
        error: message,
      });
      idempotencySweepRunsTotal.inc({ backend: this.backend, outcome: 'error' });
    }

    return {
      backend: this.backend,
      evicted,
      keys,
      errored,
      durationMs: Date.now() - start,
    };
  }
}
