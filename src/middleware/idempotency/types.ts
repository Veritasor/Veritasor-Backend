import type { Request } from 'express';

/** Header name for idempotency key */
export const IDEMPOTENCY_KEY_HEADER = 'idempotency-key';

/** Default TTL: 24 hours in milliseconds */
export const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000;

/** Minimum key length to prevent trivial keys */
export const MIN_KEY_LENGTH = 8;

/** Maximum key length to prevent abuse */
export const MAX_KEY_LENGTH = 256;

/** Default key format: UUID pattern */
export const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Default sweep interval: 60 seconds. */
export const DEFAULT_SWEEP_INTERVAL_MS = 60_000;

/** Hard ceiling so a misconfigured `IDEMPOTENCY_SWEEP_INTERVAL_MS`
 *  cannot accidentally DoS the process. */
export const MIN_SWEEP_INTERVAL_MS = 1_000;

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
   * Reserve an idempotency key atomically for an in-flight request
   * @param key - The idempotency key
   * @param ttlMs - Time to live in milliseconds for the reservation
   * @returns Promise<boolean> - True if reservation was acquired, false if already reserved/cached
   */
  reserve?(key: string, ttlMs: number): Promise<boolean>;

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

/**
 * Minimal Redis client interface for `RedisIdempotencyStore`.
 */
export interface RedisClientLike {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, ...args: unknown[]): Promise<unknown>;
  del(key: string): Promise<unknown>;
  scan?(cursor: string | number, ...args: unknown[]): Promise<unknown>;
  pipeline?(): any;
}

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
