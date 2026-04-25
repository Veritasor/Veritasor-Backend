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

import type { Request, Response, NextFunction } from 'express';

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
// In-Memory Store Implementation
// ============================================================================

/**
 * In-memory storage for idempotency entries
 * Note: This is suitable for single-instance deployments only.
 * For production, use Redis or similar distributed cache.
 */
const memoryStore = new Map<string, { entry: IdempotencyEntry; expiresAt: number }>();

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
    memoryStore.set(key, {
      entry,
      expiresAt: Date.now() + ttlMs,
    });
  },
  
  /**
   * Delete a specific entry
   */
  async delete(key: string): Promise<void> {
    memoryStore.delete(key);
  },
  
  /**
   * Clear all entries
   */
  async clear(): Promise<void> {
    memoryStore.clear();
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

    // Check for cached response
    const cached = await store.get(storeKey);
    if (cached) {
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
          createdAt: Date.now(),
        };
        store.set(storeKey, entry, ttlMs).catch((err) => {
          console.error('[idempotency] Failed to cache response:', err);
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
