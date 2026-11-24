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
import { config } from './config/index.js';
import { startServer, stopIdempotencySweeper } from './app.js';
import { stopPgBouncerScraperIfNeeded } from './services/pgbouncerScraper.js';
import { getPgClient } from './db/client.js';
import { logger } from './utils/logger.js';
import { secretLoader } from './utils/secret-loader.js';
import { jwksManager } from './utils/jwks.js';
import { createShutdownOrchestrator } from './shutdown.js';
import { createRevenueConsumer } from './services/revenue/kafkaConsumer.js';
import { stopStatsdDualWriteIfNeeded } from './services/metrics/statsdBootstrap.js';

const PORT = process.env.PORT ? Number(process.env.PORT) : 3000;

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

export async function bootstrap(): Promise<void> {
  // Load secrets before the server starts accepting traffic
  await secretLoader.reload();

  if (process.env.NODE_ENV === 'production' && config.secretLoader.source !== 'env') {
    let jwtSecret: string | undefined;
    try {
      jwtSecret = await secretLoader.get('JWT_SECRET');
    } catch {
      jwtSecret = undefined;
    }
    if (!jwtSecret || jwtSecret.length < 32) {
      throw new Error('JWT_SECRET resolved from secret loader must be at least 32 characters in production');
    }
  }

  await jwksManager.reload();

  // Start the HTTP server; `startServer` returns the `http.Server` instance
  const server = await startServer(PORT);
  const { closeAttestationStream } = await import('./ws/attestationStream.js');

  // ── Kafka revenue consumer (opt-in via KAFKA_ENABLED=true) ──────────────
  const kafkaConsumer = createRevenueConsumer(async (entry) => {
    // Placeholder: wire to your persistence layer or broadcast.
    // The normalized entry is ready for storage or downstream processing.
    logger.info("[kafka] revenue entry received", { id: entry.id, source: entry.source });
  });

  if (kafkaConsumer) {
    await kafkaConsumer.start();
    logger.info({ event: 'kafka_consumer_started' });
  }

  // ── Graceful shutdown ────────────────────────────────────────────────────
  //
  // `createShutdownOrchestrator` returns a thin object whose `.register()`
  // method attaches SIGTERM / SIGINT handlers.  The `timeoutMs` option can be
  // overridden via the `SHUTDOWN_TIMEOUT_MS` environment variable (default 15 s).
  //
  // Shutdown order: stop workers, close WebSockets and HTTP, then drain PostgreSQL.
  //
  // If the drain exceeds the deadline the process force-exits with code 1.
  // A repeated SIGTERM/SIGINT during an active shutdown triggers immediate exit.

  const shutdown = createShutdownOrchestrator({
    pool: getPgClient(),
    closeWebSockets: closeAttestationStream,
    onCleanup: async () => {
      if (kafkaConsumer) {
        try {
          await kafkaConsumer.stop();
        } catch (err) {
          logger.warn(
            { event: 'shutdown_worker_stop_failed', worker: 'kafka_consumer', error: err },
            '[Shutdown] Kafka consumer stop error',
          );
        }
      }
      // Stop the cooperative idempotency sweeper. The handle is
      // already cleared on the first successful stop, so re-invocation
      // (e.g. via repeated SIGINT) is a no-op.
      try {
        await stopIdempotencySweeper();
      } catch (err) {
        logger.warn(
          { event: 'shutdown_worker_stop_failed', worker: 'idempotency_sweeper', error: err },
          '[Shutdown] Idempotency sweeper stop error',
        );
      }
      // Stop the PgBouncer stats scraper
      try {
        await stopPgBouncerScraperIfNeeded();
      } catch (err) {
        logger.warn(
          { event: 'shutdown_worker_stop_failed', worker: 'pgbouncer_scraper', error: err },
          '[Shutdown] PgBouncer scraper stop error',
        );
      }
      try {
        const { stopSpiffeSvidProviderIfNeeded } = await import('./app.js');
        stopSpiffeSvidProviderIfNeeded();
      } catch (err) {
        logger.warn(
          { event: 'shutdown_worker_stop_failed', worker: 'spiffe_svid_provider', error: err },
          '[Shutdown] SPIFFE SVID provider stop error',
        );
      }
      try {
        await stopStatsdDualWriteIfNeeded();
      } catch (err) {
        logger.warn(
          { event: 'shutdown_worker_stop_failed', worker: 'statsd_dual_write', error: err },
          '[Shutdown] StatsD dual-write stop error',
        );
      }
    },
  });
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
    await jwksManager.reload();
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

if (process.env.NODE_ENV !== 'test' && !process.env.VITEST) {
  bootstrap().catch((error) => {
    const message = error instanceof Error ? error.message : 'Unknown startup error';
    logger.error(
      { event: 'startup_failed', error: message },
      `[Startup] ${message}`,
    );
    process.exit(1);
  });
}
