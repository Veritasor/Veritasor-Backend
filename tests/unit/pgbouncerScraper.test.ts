import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { metricsRegistry } from "../../src/metrics.js";

const mocks = vi.hoisted(() => ({
  query: vi.fn(),
  end: vi.fn(),
  on: vi.fn(),
  config: {
    pgbouncerMetrics: {
      adminUrl: "postgresql://metrics:secret@localhost:6432/pgbouncer" as string | undefined,
      scrapeIntervalMs: 15_000,
      queryTimeoutMs: 2_000,
    },
  },
}));

vi.mock("pg", () => ({
  default: {
    Pool: vi.fn(function MockPool() { return { query: mocks.query, end: mocks.end, on: mocks.on }; }),
  },
}));
vi.mock("../../src/config/index.js", () => ({ config: mocks.config }));
vi.mock("../../src/utils/logger.js", () => ({
  logger: { debug: vi.fn(), info: vi.fn(), warn: vi.fn() },
}));

const scraper = await import("../../src/services/pgbouncerScraper.js");

const poolRows = [{
  database: "app", user: "app_user", cl_active: "3", cl_waiting: "2",
  sv_active: "2", sv_idle: "4", sv_used: "1", sv_tested: "0", sv_login: "1",
  maxwait: "1", maxwait_us: "250000",
}];
const statRows = [{
  database: "app", total_query_count: "42", total_query_time: "5000000", avg_query_time: "2500",
}];

beforeEach(async () => {
  await scraper.stopPgBouncerScraper();
  metricsRegistry.resetMetrics();
  mocks.query.mockReset();
  mocks.on.mockClear();
  mocks.end.mockReset().mockResolvedValue(undefined);
  mocks.config.pgbouncerMetrics.adminUrl = "postgresql://metrics:secret@localhost:6432/pgbouncer";
  mocks.config.pgbouncerMetrics.scrapeIntervalMs = 15_000;
  mocks.config.pgbouncerMetrics.queryTimeoutMs = 2_000;
});

afterEach(async () => {
  await scraper.stopPgBouncerScraper();
  vi.useRealTimers();
});

describe("PgBouncer scraper", () => {
  it("requires a separate explicit admin URL", () => {
    mocks.config.pgbouncerMetrics.adminUrl = undefined;
    expect(scraper.getPgBouncerAdminUrl()).toBeNull();
    expect(scraper.startPgBouncerScraper()).toBe(false);
    expect(mocks.query).not.toHaveBeenCalled();
  });

  it("clamps unsafe interval and timeout values", () => {
    mocks.config.pgbouncerMetrics.scrapeIntervalMs = 1;
    mocks.config.pgbouncerMetrics.queryTimeoutMs = 99_999;
    expect(scraper.getPgBouncerScrapeIntervalMs()).toBe(scraper.MIN_SCRAPE_INTERVAL_MS);
    expect(scraper.getPgBouncerQueryTimeoutMs()).toBe(scraper.MIN_SCRAPE_INTERVAL_MS);
  });

  it("scrapes SHOW POOLS and SHOW STATS and converts microseconds", async () => {
    mocks.query
      .mockResolvedValueOnce({ rows: poolRows })
      .mockResolvedValueOnce({ rows: statRows });

    await expect(scraper.scrapeOnce()).resolves.toBe(true);
    expect(mocks.query).toHaveBeenNthCalledWith(1, "SHOW POOLS");
    expect(mocks.query).toHaveBeenNthCalledWith(2, "SHOW STATS");
    const output = await metricsRegistry.metrics();
    expect(output).toContain('pgbouncer_waiting_clients{database="app",user="app_user"} 2');
    expect(output).toContain('pgbouncer_max_wait_seconds{database="app",user="app_user"} 1.25');
    expect(output).toContain('pgbouncer_server_connections{database="app",user="app_user",state="idle"} 4');
    expect(output).toContain('pgbouncer_avg_query_time_seconds{database="app"} 0.0025');
    expect(output).toContain('pgbouncer_total_requests{database="app"} 42');
    expect(output).toContain("pgbouncer_scrape_success 1");
  });

  it("removes series for pools that disappear", async () => {
    mocks.query.mockResolvedValueOnce({ rows: poolRows }).mockResolvedValueOnce({ rows: statRows });
    await scraper.scrapeOnce();
    mocks.query.mockResolvedValueOnce({ rows: [] }).mockResolvedValueOnce({ rows: [] });
    await scraper.scrapeOnce();
    expect(await metricsRegistry.metrics()).not.toContain('database="app"');
  });

  it("falls back safely on admin authentication failure without clearing last good data", async () => {
    mocks.query.mockResolvedValueOnce({ rows: poolRows }).mockResolvedValueOnce({ rows: statRows });
    await scraper.scrapeOnce();
    mocks.query.mockRejectedValueOnce(Object.assign(new Error("denied"), { code: "28P01" }));

    await expect(scraper.scrapeOnce()).resolves.toBe(false);
    const output = await metricsRegistry.metrics();
    expect(output).toContain("pgbouncer_scrape_success 0");
    expect(output).toContain('pgbouncer_scrape_errors_total{reason="authentication"} 1');
    expect(output).toContain('pgbouncer_waiting_clients{database="app",user="app_user"} 2');
  });

  it("does not overlap an in-progress scrape", async () => {
    let resolveFirst!: (value: { rows: typeof poolRows }) => void;
    mocks.query.mockImplementationOnce(() => new Promise((resolve) => { resolveFirst = resolve; }));
    mocks.query.mockResolvedValueOnce({ rows: statRows });
    const first = scraper.scrapeOnce();
    await expect(scraper.scrapeOnce()).resolves.toBe(false);
    resolveFirst({ rows: poolRows });
    await expect(first).resolves.toBe(true);
    expect(mocks.query).toHaveBeenCalledTimes(2);
  });

  it("rejects a non-PostgreSQL admin URL", () => {
    mocks.config.pgbouncerMetrics.adminUrl = "https://localhost/pgbouncer";
    expect(() => scraper.getPgBouncerAdminUrl()).toThrow("must use postgres or postgresql");
  });

  it("supports legacy stats columns and sanitizes missing or invalid values", async () => {
    mocks.query
      .mockResolvedValueOnce({ rows: [{ database: " ", user: null, cl_waiting: -1, maxwait: "bad" }] })
      .mockResolvedValueOnce({ rows: [{ database: null, total_requests: 7, total_query_time: "", avg_query: 1000 }] });
    expect(await scraper.scrapeOnce()).toBe(true);
    const output = await metricsRegistry.metrics();
    expect(output).toContain('pgbouncer_waiting_clients{database="unknown",user="unknown"} 0');
    expect(output).toContain('pgbouncer_total_requests{database="unknown"} 7');
    expect(output).toContain('pgbouncer_avg_query_time_seconds{database="unknown"} 0.001');
  });

  it.each([
    ["ETIMEDOUT", "timeout"],
    ["ECONNREFUSED", "connection"],
    ["42601", "query"],
    [undefined, "unknown"],
  ])("classifies %s scrape failures", async (code, reason) => {
    const error = code ? Object.assign(new Error("failed"), { code }) : new Error("failed");
    mocks.query.mockRejectedValueOnce(error);
    expect(await scraper.scrapeOnce()).toBe(false);
    expect(await metricsRegistry.metrics()).toContain(`pgbouncer_scrape_errors_total{reason="${reason}"} 1`);
  });

  it("redacts asynchronous pool error details", async () => {
    mocks.query.mockResolvedValue({ rows: [] });
    await scraper.scrapeOnce();
    const handler = mocks.on.mock.calls.find(([event]) => event === "error")?.[1];
    expect(handler).toBeTypeOf("function");
    expect(() => handler(Object.assign(new Error("contains secret"), { code: "ECONNRESET" }))).not.toThrow();
  });

  it("honors upper and lower configuration bounds", () => {
    mocks.config.pgbouncerMetrics.scrapeIntervalMs = 999_999;
    mocks.config.pgbouncerMetrics.queryTimeoutMs = 1;
    expect(scraper.getPgBouncerScrapeIntervalMs()).toBe(scraper.MAX_SCRAPE_INTERVAL_MS);
    expect(scraper.getPgBouncerQueryTimeoutMs()).toBe(scraper.MIN_QUERY_TIMEOUT_MS);
  });

  it("exercises production lifecycle wrappers", async () => {
    const original = process.env.NODE_ENV;
    process.env.NODE_ENV = "production";
    process.env.METRICS_ENABLED = "true";
    mocks.query.mockResolvedValue({ rows: [] });
    scraper.startPgBouncerScraperIfNeeded();
    await scraper.stopPgBouncerScraperIfNeeded();
    process.env.NODE_ENV = original;
    delete process.env.METRICS_ENABLED;
    expect(mocks.end).toHaveBeenCalledOnce();
  });

  it("starts once and closes its one-connection pool idempotently", async () => {
    mocks.query.mockResolvedValue({ rows: [] });
    expect(scraper.startPgBouncerScraper()).toBe(true);
    expect(scraper.startPgBouncerScraper()).toBe(false);
    await scraper.stopPgBouncerScraper();
    await scraper.stopPgBouncerScraper();
    expect(mocks.end).toHaveBeenCalledTimes(1);
  });
});