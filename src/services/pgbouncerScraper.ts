/**
 * PgBouncer stats scraper for real-time queue depth monitoring.
 *
 * Scrapes `SHOW STATS` from the PgBouncer admin database at second granularity
 * and exports metrics to Prometheus for alerting on queue depth spikes.
 *
 * Key metrics exposed:
 * - pgbouncer_waiting_clients (gauge): clients waiting for a server connection
 * - pgbouncer_avg_wait_time_seconds (gauge): average wait time in seconds
 * - pgbouncer_active_clients (gauge): active client connections
 * - pgbouncer_idle_clients (gauge): idle client connections
 * - pgbouncer_server_connections (gauge): active server connections
 * - pgbouncer_avg_query_time_seconds (gauge): average query execution time
 * - pgbouncer_total_requests_total (counter): total client requests
 * - pgbouncer_total_query_time_seconds_total (counter): cumulative query time
 *
 * Self-throttling: if scraping takes longer than the interval, skips the next
 * cycle to prevent overlapping scrapes under load.
 */

import pg from "pg";
import { config } from "../config/index.js";
import { logger } from "../utils/logger.js";
import {
  pgbouncerWaitingClients,
  pgbouncerAvgWaitTimeSeconds,
  pgbouncerActiveClients,
  pgbouncerIdleClients,
  pgbouncerServerConnections,
  pgbouncerAvgQueryTimeSeconds,
  pgbouncerTotalRequestsTotal,
  pgbouncerTotalQueryTimeSecondsTotal,
} from "../metrics.js";

export const SCRAPE_INTERVAL_MS = 1000;
export const SCRAPE_TIMEOUT_MS = 500;

interface PgBouncerStatsRow {
  database: string;
  total_requests: number;
  total_received: number;
  total_sent: number;
  total_query_time: number;
  avg_req: number;
  avg_recv: number;
  avg_sent: number;
  avg_query: number;
  avg_wait: number;
  waiting_clients: number;
  idle_clients: number;
  active_clients: number;
  servers: number;
}

let scrapeTimer: ReturnType<typeof setTimeout> | null = null;
let isScraping = false;
let pgbouncerPool: pg.Pool | null = null;

export function getPgBouncerAdminUrl(): string | null {
  const dbUrl = new URL(config.db.url);
  const adminUrl = new URL(dbUrl.toString());
  adminUrl.pathname = "/pgbouncer";
  adminUrl.searchParams.set("statement_cache_size", "0");
  return adminUrl.toString();
}

export async function scrapeOnce(): Promise<void> {
  if (isScraping) {
    logger.debug("PgBouncer scrape skipped: previous scrape still running");
    return;
  }

  const adminUrl = getPgBouncerAdminUrl();
  if (!adminUrl) {
    logger.debug("PgBouncer admin URL not configured, skipping scrape");
    return;
  }

  isScraping = true;
  const startTime = Date.now();

  try {
    if (!pgbouncerPool) {
      pgbouncerPool = new pg.Pool({
        connectionString: adminUrl,
        max: 1,
        idleTimeoutMillis: 5000,
        connectionTimeoutMillis: SCRAPE_TIMEOUT_MS,
      });
    }

    const client = await pgbouncerPool.connect();
    try {
      const result = await Promise.race([
        client.query<PgBouncerStatsRow>("SHOW STATS"),
        new Promise<never>((_, reject) =>
          setTimeout(() => reject(new Error("scrape timeout")), SCRAPE_TIMEOUT_MS),
        ),
      ]);

      for (const row of result.rows) {
        const dbLabel = row.database || "default";

        pgbouncerWaitingClients.set({ database: dbLabel }, row.waiting_clients);
        pgbouncerAvgWaitTimeSeconds.set({ database: dbLabel }, row.avg_wait / 1_000_000);
        pgbouncerActiveClients.set({ database: dbLabel }, row.active_clients);
        pgbouncerIdleClients.set({ database: dbLabel }, row.idle_clients);
        pgbouncerServerConnections.set({ database: dbLabel }, row.servers);
        pgbouncerAvgQueryTimeSeconds.set({ database: dbLabel }, row.avg_query / 1_000_000);
        pgbouncerTotalRequestsTotal.inc({ database: dbLabel }, row.total_requests);
        pgbouncerTotalQueryTimeSecondsTotal.inc(
          { database: dbLabel },
          row.total_query_time / 1_000_000,
        );
      }
    } finally {
      client.release();
    }
  } catch (error) {
    logger.debug({ err: error }, "PgBouncer scrape failed");
  } finally {
    isScraping = false;
    const elapsed = Date.now() - startTime;

    if (elapsed >= SCRAPE_INTERVAL_MS) {
      logger.warn(
        { elapsedMs: elapsed, intervalMs: SCRAPE_INTERVAL_MS },
        "PgBouncer scrape exceeded interval, skipping next cycle (self-throttling)",
      );
      scheduleNextScrape(SCRAPE_INTERVAL_MS * 2);
    } else {
      scheduleNextScrape(Math.max(0, SCRAPE_INTERVAL_MS - elapsed));
    }
  }
}

function scheduleNextScrape(delayMs: number): void {
  if (scrapeTimer) {
    clearTimeout(scrapeTimer);
  }
  scrapeTimer = setTimeout(scrapeOnce, delayMs);
}

export function startPgBouncerScraper(): void {
  const adminUrl = getPgBouncerAdminUrl();
  if (!adminUrl) {
    logger.info("PgBouncer admin URL not configured, scraper not started");
    return;
  }

  logger.info("Starting PgBouncer stats scraper (1s interval)");
  scrapeOnce();
}

export function stopPgBouncerScraper(): void {
  if (scrapeTimer) {
    clearTimeout(scrapeTimer);
    scrapeTimer = null;
  }
  if (pgbouncerPool) {
    pgbouncerPool.end();
    pgbouncerPool = null;
  }
  logger.info("PgBouncer stats scraper stopped");
}