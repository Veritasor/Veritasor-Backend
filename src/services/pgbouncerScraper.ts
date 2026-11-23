/**
 * Low-overhead PgBouncer admin-console scraper.
 *
 * The admin URL is deliberately independent from DATABASE_URL: an application
 * database credential must never be promoted to a PgBouncer admin credential.
 * One connection and a completion-based timer prevent overlap under load.
 */
import pg from "pg";
import { config } from "../config/index.js";
import { logger } from "../utils/logger.js";
import {
  pgbouncerActiveClients,
  pgbouncerAvgQueryTimeSeconds,
  pgbouncerLastSuccessfulScrapeTimestampSeconds,
  pgbouncerMaxWaitSeconds,
  pgbouncerScrapeDurationSeconds,
  pgbouncerScrapeErrorsTotal,
  pgbouncerScraperEnabled,
  pgbouncerScrapeSuccess,
  pgbouncerServerConnections,
  pgbouncerTotalQueryTimeSeconds,
  pgbouncerTotalRequests,
  pgbouncerWaitingClients,
} from "../metrics.js";

export const MIN_SCRAPE_INTERVAL_MS = 1_000;
export const MAX_SCRAPE_INTERVAL_MS = 300_000;
export const MIN_QUERY_TIMEOUT_MS = 100;
export const MAX_QUERY_TIMEOUT_MS = 30_000;

type AdminValue = string | number | null | undefined;
type AdminRow = Record<string, AdminValue>;

let pool: pg.Pool | null = null;
let timer: ReturnType<typeof setTimeout> | null = null;
let started = false;
let scrapeInProgress = false;

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

export function getPgBouncerScrapeIntervalMs(): number {
  return clamp(config.pgbouncerMetrics.scrapeIntervalMs, MIN_SCRAPE_INTERVAL_MS, MAX_SCRAPE_INTERVAL_MS);
}

export function getPgBouncerQueryTimeoutMs(): number {
  return clamp(
    config.pgbouncerMetrics.queryTimeoutMs,
    MIN_QUERY_TIMEOUT_MS,
    Math.min(MAX_QUERY_TIMEOUT_MS, getPgBouncerScrapeIntervalMs()),
  );
}

/** Return the explicitly configured admin URL without deriving or logging it. */
export function getPgBouncerAdminUrl(): string | null {
  const value = config.pgbouncerMetrics.adminUrl?.trim();
  if (!value) return null;
  const parsed = new URL(value);
  if (parsed.protocol !== "postgres:" && parsed.protocol !== "postgresql:") {
    throw new Error("PgBouncer admin URL must use postgres or postgresql");
  }
  return value;
}

function numeric(row: AdminRow, ...names: string[]): number {
  for (const name of names) {
    const value = row[name];
    if (value !== null && value !== undefined && value !== "") {
      const parsed = Number(value);
      if (Number.isFinite(parsed) && parsed >= 0) return parsed;
    }
  }
  return 0;
}

function label(value: AdminValue): string {
  const result = String(value ?? "unknown").trim();
  return result || "unknown";
}

function classifyError(error: unknown): string {
  const code = typeof error === "object" && error !== null && "code" in error
    ? String((error as { code?: unknown }).code ?? "")
    : "";
  if (code === "28P01" || code === "28000") return "authentication";
  if (code === "ETIMEDOUT" || code === "57014") return "timeout";
  if (["ECONNREFUSED", "ECONNRESET", "EHOSTUNREACH", "ENOTFOUND"].includes(code)) return "connection";
  if (code) return "query";
  return "unknown";
}

function getPool(): pg.Pool {
  if (!pool) {
    pool = new pg.Pool({
      connectionString: getPgBouncerAdminUrl()!,
      max: 1,
      idleTimeoutMillis: getPgBouncerScrapeIntervalMs(),
      connectionTimeoutMillis: getPgBouncerQueryTimeoutMs(),
      query_timeout: getPgBouncerQueryTimeoutMs(),
    });
    pool.on("error", (error) => {
      logger.warn({ event: "pgbouncer_admin_pool_error", code: classifyError(error) });
    });
  }
  return pool;
}

function publish(pools: AdminRow[], stats: AdminRow[]): void {
  pgbouncerWaitingClients.reset();
  pgbouncerMaxWaitSeconds.reset();
  pgbouncerActiveClients.reset();
  pgbouncerServerConnections.reset();
  pgbouncerAvgQueryTimeSeconds.reset();
  pgbouncerTotalRequests.reset();
  pgbouncerTotalQueryTimeSeconds.reset();

  for (const row of pools) {
    const labels = { database: label(row.database), user: label(row.user) };
    pgbouncerWaitingClients.set(labels, numeric(row, "cl_waiting"));
    pgbouncerMaxWaitSeconds.set(
      labels,
      numeric(row, "maxwait") + numeric(row, "maxwait_us") / 1_000_000,
    );
    pgbouncerActiveClients.set(labels, numeric(row, "cl_active"));
    for (const state of ["active", "idle", "used", "tested", "login"] as const) {
      pgbouncerServerConnections.set(
        { ...labels, state },
        numeric(row, `sv_${state}`),
      );
    }
  }

  for (const row of stats) {
    const labels = { database: label(row.database) };
    pgbouncerAvgQueryTimeSeconds.set(
      labels,
      numeric(row, "avg_query_time", "avg_query") / 1_000_000,
    );
    pgbouncerTotalRequests.set(
      labels,
      numeric(row, "total_query_count", "total_xact_count", "total_requests"),
    );
    pgbouncerTotalQueryTimeSeconds.set(
      labels,
      numeric(row, "total_query_time") / 1_000_000,
    );
  }
}

/** Perform one scrape. Failures are observable but never crash the application. */
export async function scrapeOnce(): Promise<boolean> {
  if (scrapeInProgress || !getPgBouncerAdminUrl()) return false;
  scrapeInProgress = true;
  const startedAt = Date.now();
  try {
    const adminPool = getPool();
    const [poolsResult, statsResult] = await Promise.all([
      adminPool.query("SHOW POOLS"),
      adminPool.query("SHOW STATS"),
    ]);
    publish(poolsResult.rows as AdminRow[], statsResult.rows as AdminRow[]);
    pgbouncerScrapeSuccess.set(1);
    pgbouncerLastSuccessfulScrapeTimestampSeconds.set(Date.now() / 1_000);
    return true;
  } catch (error) {
    const reason = classifyError(error);
    pgbouncerScrapeSuccess.set(0);
    pgbouncerScrapeErrorsTotal.inc({ reason });
    logger.warn({ event: "pgbouncer_scrape_failed", reason });
    return false;
  } finally {
    pgbouncerScrapeDurationSeconds.set((Date.now() - startedAt) / 1_000);
    scrapeInProgress = false;
  }
}

async function runCycle(): Promise<void> {
  await scrapeOnce();
  if (started) timer = setTimeout(runCycle, getPgBouncerScrapeIntervalMs());
  timer?.unref?.();
}

export function startPgBouncerScraper(): boolean {
  if (started || !getPgBouncerAdminUrl()) return false;
  started = true;
  pgbouncerScraperEnabled.set(1);
  logger.info({ intervalMs: getPgBouncerScrapeIntervalMs() }, "Starting PgBouncer metrics scraper");
  void runCycle();
  return true;
}

export async function stopPgBouncerScraper(): Promise<void> {
  started = false;
  pgbouncerScraperEnabled.set(0);
  if (timer) clearTimeout(timer);
  timer = null;
  const currentPool = pool;
  pool = null;
  if (currentPool) await currentPool.end();
}

export function startPgBouncerScraperIfNeeded(): void {
  if (process.env.NODE_ENV !== "test" && process.env.METRICS_ENABLED === "true") {
    startPgBouncerScraper();
  }
}

export async function stopPgBouncerScraperIfNeeded(): Promise<void> {
  await stopPgBouncerScraper();
}