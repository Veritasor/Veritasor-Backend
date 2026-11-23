/**
 * Used-token store abstraction for refresh-token rotation protection.
 *
 * Rotation protection requires that a consumed refresh token JTI can never be
 * accepted again. The store is responsible for:
 *   1. Checking whether a JTI has already been consumed.
 *   2. Marking a JTI as consumed with a TTL so rows self-expire.
 *
 * Two implementations are provided:
 *   - InMemoryUsedTokenStore  — default in tests; reset via clearUsedRefreshTokens()
 *   - DbUsedTokenStore        — production; persists to PostgreSQL, shared across
 *                               all instances, survives restarts
 *
 * @module usedTokenStore
 */

import { db } from '../../db/client.js'
import { logger } from '../../utils/logger.js'

// ---------------------------------------------------------------------------
// Interface
// ---------------------------------------------------------------------------

export interface UsedTokenStore {
  /**
   * Returns true if the given JTI has already been consumed.
   * Must be safe to call concurrently — the DB implementation relies on a
   * PRIMARY KEY constraint to make the mark() operation atomic.
   */
  has(jti: string): Promise<boolean>

  /**
   * Marks a JTI as consumed.
   * Returns true only when this call inserted the row (i.e. this caller won
   * the race). Returns false when the JTI was already consumed, which the
   * caller must treat as a replay attempt.
   * @param jti      - The unique JWT ID to consume.
   * @param userId   - Owner of the token (stored for audit purposes).
   * @param expiresAt - When the token would have expired; used as the TTL so
   *                    the row is eligible for cleanup after the token lifetime.
   */
  mark(jti: string, userId: string, expiresAt: Date): Promise<boolean>

  /**
   * Removes all entries. Intended for test isolation only.
   */
  clear(): void | Promise<void>
}

// ---------------------------------------------------------------------------
// In-memory implementation (tests)
// ---------------------------------------------------------------------------

/**
 * Simple in-memory store backed by a Set.
 * Not safe for multi-instance deployments — use DbUsedTokenStore in production.
 */
export class InMemoryUsedTokenStore implements UsedTokenStore {
  private readonly store = new Set<string>()

  async has(jti: string): Promise<boolean> {
    return this.store.has(jti)
  }

  async mark(jti: string, _userId: string, _expiresAt: Date): Promise<boolean> {
    return this.store.add(jti) === undefined ? false : true
  }

  clear(): void {
    this.store.clear()
  }
}

// ---------------------------------------------------------------------------
// PostgreSQL implementation (production)
// ---------------------------------------------------------------------------

/**
 * Persistent store backed by the `used_refresh_tokens` table.
 *
 * Replay protection is enforced at the DB level via a PRIMARY KEY on `jti`.
 * mark() uses INSERT ... ON CONFLICT DO NOTHING RETURNING jti and reports
 * whether this call inserted the row, so concurrent callers racing on the
 * same JTI resolve to exactly one winner.
 *
 * TTL cleanup: rows with expires_at < NOW() are stale and can be deleted by a
 * periodic job. They do not affect correctness because an expired JWT is
 * rejected by the JWT library before the store is consulted.
 */
export class DbUsedTokenStore implements UsedTokenStore {
  async has(jti: string): Promise<boolean> {
    const result = await db.query(
      'SELECT 1 FROM used_refresh_tokens WHERE jti = $1 LIMIT 1',
      [jti]
    )
    return (result.rowCount ?? 0) > 0
  }

  async mark(jti: string, userId: string, expiresAt: Date): Promise<boolean> {
    try {
      const result = await db.query(
        `INSERT INTO used_refresh_tokens (jti, user_id, expires_at)
         VALUES ($1, $2, $3)
         ON CONFLICT (jti) DO NOTHING
         RETURNING jti`,
        [jti, userId, expiresAt]
      )
      return (result.rowCount ?? 0) === 1
    } catch (err: unknown) {
      // Any DB error is re-thrown so the caller can fail closed (refresh.ts
      // fails closed). A unique violation cannot occur here because of
      // ON CONFLICT DO NOTHING; conflicts are reported via the return value.
      logger.error('DbUsedTokenStore.mark failed', { jti, userId, error: err })
      throw err
    }
  }

  async clear(): Promise<void> {
    await db.query('DELETE FROM used_refresh_tokens')
  }
}

// ---------------------------------------------------------------------------
// Singleton selection
// ---------------------------------------------------------------------------

/**
 * Returns the appropriate store for the current environment.
 * Tests override this via setUsedTokenStore().
 */
let activeStore: UsedTokenStore = new InMemoryUsedTokenStore()

/**
 * Replace the active store. Intended for test setup and DI in integration tests.
 * In production the app calls this once at startup with a DbUsedTokenStore.
 */
export function setUsedTokenStore(store: UsedTokenStore): void {
  activeStore = store
}

export function getUsedTokenStore(): UsedTokenStore {
  return activeStore
}
