/**
 * PgBouncer / transient-connection retry logic.
 *
 * PgBouncer can forcibly close a server-side socket during pool churn,
 * maintenance reloads, or brief network partitions.  node-postgres surfaces
 * these as errors with specific pg error codes or Node.js syscall codes
 * before the query reaches the database, so retrying them is safe.
 *
 * Security note
 * ─────────────
 * Only errors that are known to be transient *pre-query* disconnects are
 * retried.  Errors that indicate the query was received by Postgres
 * (e.g. constraint violations, serialisation failures, auth errors) are
 * never retried here so we cannot accidentally duplicate writes or mask
 * persistent outages.
 *
 * Retry cap
 * ─────────
 * A maximum of PGBOUNCER_MAX_RETRIES attempts (default 3) is enforced.
 * After that the error is re-thrown unchanged so callers / APM tools see
 * the real root cause.
 */

import { logger } from '../utils/logger.js';

// ─── Tunables (overridable via env for ops flexibility) ───────────────────────

/** How many *additional* attempts after the first failure. */
export const PGBOUNCER_MAX_RETRIES =
  Math.max(0, Number(process.env.PGBOUNCER_MAX_RETRIES ?? 3));

/** Base delay in ms for the exponential backoff. */
export const PGBOUNCER_BASE_DELAY_MS =
  Math.max(1, Number(process.env.PGBOUNCER_BASE_DELAY_MS ?? 50));

/** Upper cap on the computed backoff delay in ms. */
export const PGBOUNCER_MAX_DELAY_MS =
  Math.max(1, Number(process.env.PGBOUNCER_MAX_DELAY_MS ?? 2_000));

// ─── Transient error detection ────────────────────────────────────────────────

/**
 * PostgreSQL error codes that indicate the connection was reset before the
 * backend processed the query.  These come from node-postgres as `error.code`.
 */
const PG_TRANSIENT_CODES = new Set([
  '08000', // connection_exception
  '08003', // connection_does_not_exist
  '08006', // connection_failure
  '08001', // sqlclient_unable_to_establish_sqlconnection
  '08004', // sqlserver_rejected_establishment_of_sqlconnection
  '57P01', // admin_shutdown (PgBouncer forced-close)
  '57P02', // crash_shutdown
  '57P03', // cannot_connect_now
]);

/**
 * Node.js / OS-level socket codes that node-postgres attaches to the error
 * object before it wraps it.
 */
const NODE_TRANSIENT_CODES = new Set([
  'ECONNRESET',
  'ECONNREFUSED',
  'ECONNABORTED',
  'EPIPE',
  'ETIMEDOUT',
  'EHOSTUNREACH',
  'ENETUNREACH',
]);

/** Returns true only for errors that are safe to retry. */
export function isTransientConnectionError(err: unknown): boolean {
  if (!(err instanceof Error)) return false;
  const e = err as NodeJS.ErrnoException & { code?: string };
  if (e.code && PG_TRANSIENT_CODES.has(e.code)) return true;
  if (e.code && NODE_TRANSIENT_CODES.has(e.code)) return true;
  // node-postgres also throws with a message when the pool client is
  // destroyed mid-query ("Connection terminated unexpectedly" / "read ECONNRESET")
  if (/connection terminated/i.test(e.message)) return true;
  return false;
}

// ─── Jittered backoff ─────────────────────────────────────────────────────────

/**
 * Full-jitter exponential backoff.
 * delay = random(0, min(MAX_DELAY, BASE * 2^attempt))
 *
 * "Full jitter" avoids thundering-herd on multi-replica services because each
 * client picks a uniformly random point in the window rather than the same
 * deterministic value.
 *
 * @param attempt  1-based retry attempt index.
 * @param randomFn Injected for deterministic tests; defaults to Math.random.
 */
export function pgBouncerBackoffMs(
  attempt: number,
  randomFn: () => number = Math.random,
): number {
  const window = Math.min(
    PGBOUNCER_MAX_DELAY_MS,
    PGBOUNCER_BASE_DELAY_MS * 2 ** attempt,
  );
  return Math.round(randomFn() * window);
}

// ─── Retry wrapper ────────────────────────────────────────────────────────────

/**
 * Executes `fn` and retries up to `PGBOUNCER_MAX_RETRIES` times on transient
 * PgBouncer / connection-reset errors using full-jitter exponential backoff.
 *
 * Non-transient errors (query errors, auth failures, constraint violations …)
 * are re-thrown immediately without retrying.
 *
 * @param fn       Async operation to retry (must be idempotent / outside a tx).
 * @param label    Short identifier included in log lines for observability.
 * @param sleepFn  Injected for deterministic tests; defaults to setTimeout.
 * @param randomFn Injected for deterministic tests; defaults to Math.random.
 */
export async function withPgBouncerRetry<T>(
  fn: () => Promise<T>,
  label = 'query',
  sleepFn: (ms: number) => Promise<void> = (ms) =>
    new Promise((r) => setTimeout(r, ms)),
  randomFn: () => number = Math.random,
): Promise<T> {
  let lastError: unknown;

  for (let attempt = 0; attempt <= PGBOUNCER_MAX_RETRIES; attempt++) {
    try {
      return await fn();
    } catch (err) {
      lastError = err;

      if (!isTransientConnectionError(err) || attempt >= PGBOUNCER_MAX_RETRIES) {
        // Either non-retryable, or we've exhausted our budget — surface it.
        throw err;
      }

      const delayMs = pgBouncerBackoffMs(attempt + 1, randomFn);
      logger.warn(
        JSON.stringify({
          event: 'pgbouncer_reconnect_retry',
          label,
          attempt: attempt + 1,
          maxRetries: PGBOUNCER_MAX_RETRIES,
          delayMs,
          errorCode: (err as NodeJS.ErrnoException).code ?? null,
          errorMessage: (err as Error).message,
        }),
      );
      await sleepFn(delayMs);
    }
  }

  // Unreachable, but satisfies TypeScript.
  throw lastError;
}
