/**
 * @module shutdown
 *
 * Graceful shutdown orchestrator for the Veritasor Backend.
 *
 * Shutdown lifecycle (in order):
 *
 *   1. Signal received (SIGTERM or SIGINT)
 *   2. Mark `isShuttingDown = true` so repeated signals force-exit immediately
 *   3. Stop background workers while the database remains available
 *   4. Close WebSockets and HTTP connections, including idle keep-alive sockets
 *   5. Drain and close the PostgreSQL pool
 *   6. Exit cleanly with code 0
 *
 * Bounded timeout:
 *   - A configurable deadline (default: SHUTDOWN_TIMEOUT_MS env var or 15 s) guards the
 *     entire sequence. If the deadline expires before steps 4–5 complete, the process
 *     force-exits with code 1 to avoid hanging deployments.
 *
 * Repeated signals:
 *   - A second SIGTERM/SIGINT while shutdown is already in progress triggers an
 *     immediate `process.exit(1)` so operators can always escape a stuck drain.
 */

import type { Server } from 'node:http';
import type { Pool } from 'pg';
import { logger } from './utils/logger.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ShutdownOptions {
  /** Milliseconds to wait before force-exiting. Defaults to 15 000. */
  timeoutMs?: number;
  /**
   * Injected pool reference. Accepting `Pool | { end(): Promise<void> }` so
   * tests can pass a plain stub without importing pg.
   */
  pool: Pick<Pool, 'end'>;
  /** Stop background workers before closing the server and database pool. */
  onCleanup?: () => Promise<void>;
  closeWebSockets?: () => Promise<void> | void;
}

export interface ShutdownOrchestrator {
  /**
   * Register SIGTERM and SIGINT handlers on the given process (defaults to
   * the real `process`). Returns the registered handler function so tests can
   * invoke it directly.
   */
  register(server: Server, proc?: NodeJS.Process): (signal: string) => void;
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create a graceful shutdown orchestrator bound to `opts`.
 *
 * @example
 * ```ts
 * const shutdown = createShutdownOrchestrator({ pool });
 * const handler = shutdown.register(server);
 * ```
 */
export function createShutdownOrchestrator(opts: ShutdownOptions): ShutdownOrchestrator {
  const timeoutMs = opts.timeoutMs ?? getDefaultTimeoutMs();

  return {
    register(server: Server, proc: NodeJS.Process = process) {
      /**
       * Whether a shutdown sequence is already in progress.
       * A second signal while this is `true` triggers an immediate force-exit.
       */
      let isShuttingDown = false;

      const handler = (signal: string): void => {
        // ------------------------------------------------------------------
        // Repeated-signal guard: force-exit immediately if already draining
        // ------------------------------------------------------------------
        if (isShuttingDown) {
          console.error(
            `[Shutdown] Received second ${signal} during active shutdown — force-exiting.`,
          );
          proc.exit(1);
          return;
        }

        isShuttingDown = true;

        logger.info({
          event: 'shutdown_initiated',
          signal,
          timeoutMs,
        });

        // ------------------------------------------------------------------
        // Bounded deadline timer — triggers force-exit if drain stalls
        // ------------------------------------------------------------------
        const deadline = setTimeout(() => {
          console.error(
            `[Shutdown] Graceful shutdown exceeded ${timeoutMs} ms deadline — force-exiting.`,
          );
          proc.exit(1);
        }, timeoutMs);

        // Ensure the timer does not keep the event loop alive after clean exit
        if (typeof deadline.unref === 'function') {
          deadline.unref();
        }

        // Run the actual async sequence, piping any unhandled rejection to a
        // synchronous error log + force-exit so the process never hangs silently.
        performShutdown(server, opts, timeoutMs)
          .then(() => {
            clearTimeout(deadline);
            logger.info({ event: 'shutdown_complete', signal });
            proc.exit(0);
          })
          .catch((err: unknown) => {
            clearTimeout(deadline);
            console.error('[Shutdown] Unexpected error during shutdown:', err);
            proc.exit(1);
          });
      };

      // Register on both termination signals
      proc.on('SIGTERM', handler);
      proc.on('SIGINT', handler);

      return handler;
    },
  };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * The async shutdown sequence.
 *
 * Step 1 — stop workers and WebSockets.
 * Step 2 — `server.close()`: Node stops accepting new connections.  Active
 *   keep-alive connections are tracked by the server; this call waits for all
 *   in-flight requests to complete before invoking the callback.
 *
 * Step 3 — `pool.end()`: pg drains idle clients, waits for any active queries
 *   to finish, then closes all sockets.
 *
 */
async function performShutdown(
  server: Server,
  opts: ShutdownOptions,
  timeoutMs: number,
): Promise<void> {
  // ── Step 1: stop background workers while database access is available ──
  if (opts.onCleanup) {
    try { await opts.onCleanup(); } catch (err) { console.error('[Shutdown] Error in onCleanup hook:', err); }
  }
  try { await opts.closeWebSockets?.(); } catch (err) { console.error('[Shutdown] Error closing WebSockets:', err); }

  // ── Step 2: stop accepting new HTTP connections ─────────────────────────
  logger.info({ event: 'shutdown_server_closing' });

  await closeServer(server, timeoutMs);

  logger.info({ event: 'shutdown_server_closed' });

  // ── Step 3: drain the PostgreSQL pool ───────────────────────────────────
  logger.info({ event: 'shutdown_pool_draining' });

  try {
    await opts.pool.end();
    logger.info({ event: 'shutdown_pool_closed' });
  } catch (err: unknown) {
    // Log but do not rethrow — a pool-close error should not block exit
    console.error('[Shutdown] Error while closing DB pool:', err);
  }
}

/**
 * Wrap `server.close()` in a Promise.
 *
 * `server.close()` stops accepting connections but Node's built-in behaviour
 * closes idle keep-alive sockets immediately after initiating close, while
 * allowing active requests to finish draining.
 */
function closeServer(server: Server, _timeoutMs: number): Promise<void> {
  return new Promise((resolve, reject) => {
    server.close((err?: Error) => {
      if (err) {
        reject(err);
      } else {
        resolve();
      }
    });
    server.closeIdleConnections?.();
  });
}

/**
 * Read the shutdown timeout from the environment, falling back to 15 seconds.
 * Accepts `SHUTDOWN_TIMEOUT_MS` as a positive integer.
 */
function getDefaultTimeoutMs(): number {
  const raw = process.env.SHUTDOWN_TIMEOUT_MS;
  if (raw !== undefined) {
    const parsed = Number.parseInt(raw, 10);
    if (Number.isInteger(parsed) && parsed > 0) {
      return parsed;
    }
    console.warn(
      `[Shutdown] Invalid SHUTDOWN_TIMEOUT_MS="${raw}" — using default 15 000 ms.`,
    );
  }
  return 15_000;
}
