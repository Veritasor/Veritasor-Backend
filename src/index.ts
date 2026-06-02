/**
 * Application entry point.
 *
 * Responsibilities:
 *   1. Load secrets via `secretLoader` before any request is served.
 *   2. Start the HTTP server through `startServer()`.
 *   3. Register graceful shutdown handlers (SIGTERM / SIGINT) so that:
 *        - In-flight requests finish before connections close.
 *        - The PostgreSQL pool drains cleanly.
 *        - The process exits with code 0 on success, 1 on timeout/error.
 *   4. Reload secrets on SIGHUP without restarting the process.
 *
 * See `src/shutdown.ts` for the full shutdown lifecycle documentation.
 */

import 'dotenv/config';
import { startServer } from './app.js';
import { pool } from './db/client.js';
import { logger } from './utils/logger.js';
import { secretLoader } from './utils/secret-loader.js';
import { createShutdownOrchestrator } from './shutdown.js';

const PORT = process.env.PORT ? Number(process.env.PORT) : 3000;

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

async function bootstrap(): Promise<void> {
  // Load secrets before the server starts accepting traffic
  await secretLoader.reload();

  // Start the HTTP server; `startServer` returns the `http.Server` instance
  const server = await startServer(PORT);

  // ── Graceful shutdown ────────────────────────────────────────────────────
  //
  // `createShutdownOrchestrator` returns a thin object whose `.register()`
  // method attaches SIGTERM / SIGINT handlers.  The `timeoutMs` option can be
  // overridden via the `SHUTDOWN_TIMEOUT_MS` environment variable (default 15 s).
  //
  // Shutdown order:
  //   1. server.close()  — stop accepting new connections
  //   2. pool.end()      — drain + close all PostgreSQL connections
  //   3. process.exit(0) — clean exit
  //
  // If the drain exceeds the deadline the process force-exits with code 1.
  // A repeated SIGTERM/SIGINT during an active shutdown triggers immediate exit.

  const shutdown = createShutdownOrchestrator({ pool });
  shutdown.register(server);

  logger.info({
    event: 'server_ready',
    port: PORT,
    shutdownTimeoutMs: process.env.SHUTDOWN_TIMEOUT_MS ?? 15_000,
  });
}

// ---------------------------------------------------------------------------
// SIGHUP — hot-reload secrets without restarting the process
// ---------------------------------------------------------------------------

process.on('SIGHUP', async () => {
  logger.info({ event: 'secret_reload_requested', key: 'all' });

  try {
    await secretLoader.reload();
    logger.info({ event: 'secret_reload_succeeded', key: 'all' });
  } catch (error) {
    logger.error({
      event: 'secret_reload_failed',
      key: 'all',
      error: error instanceof Error ? error.message : String(error),
    });
  }
});

// ---------------------------------------------------------------------------
// Start (skipped in test environments to avoid side-effects)
// ---------------------------------------------------------------------------

if (process.env.NODE_ENV !== 'test') {
  bootstrap().catch((error) => {
    const message = error instanceof Error ? error.message : 'Unknown startup error';
    console.error(`[Startup] ${message}`);
    process.exit(1);
  });
}
