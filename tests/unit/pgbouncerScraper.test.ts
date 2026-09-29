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
// ---------------------------------------------------------------------------
// Regression suite — issue #1002
// Exercises the explicit branches at lines 58 and 61 of pgbouncerScraper.ts,
// asserts constant values, and covers boundary inputs not addressed above.
// ---------------------------------------------------------------------------

describe("regression #1002 — exported constant values", () => {
  it("MIN_SCRAPE_INTERVAL_MS is exactly 1 000 ms", () => {
    expect(scraper.MIN_SCRAPE_INTERVAL_MS).toBe(1_000);
  });

  it("MAX_SCRAPE_INTERVAL_MS is exactly 300 000 ms (5 minutes)", () => {
    expect(scraper.MAX_SCRAPE_INTERVAL_MS).toBe(300_000);
  });

  it("MIN_QUERY_TIMEOUT_MS is exactly 100 ms", () => {
    expect(scraper.MIN_QUERY_TIMEOUT_MS).toBe(100);
  });

  it("MAX_QUERY_TIMEOUT_MS is exactly 30 000 ms", () => {
    expect(scraper.MAX_QUERY_TIMEOUT_MS).toBe(30_000);
  });

  it("MIN_SCRAPE_INTERVAL_MS < MAX_SCRAPE_INTERVAL_MS (ordering invariant)", () => {
    expect(scraper.MIN_SCRAPE_INTERVAL_MS).toBeLessThan(scraper.MAX_SCRAPE_INTERVAL_MS);
  });

  it("MIN_QUERY_TIMEOUT_MS < MAX_QUERY_TIMEOUT_MS (ordering invariant)", () => {
    expect(scraper.MIN_QUERY_TIMEOUT_MS).toBeLessThan(scraper.MAX_QUERY_TIMEOUT_MS);
  });
});

describe("regression #1002 — getPgBouncerAdminUrl() empty/whitespace paths (line 58)", () => {
  it("returns null when adminUrl is an empty string", () => {
    mocks.config.pgbouncerMetrics.adminUrl = "";
    expect(scraper.getPgBouncerAdminUrl()).toBeNull();
  });

  it("returns null when adminUrl is whitespace-only (spaces)", () => {
    mocks.config.pgbouncerMetrics.adminUrl = "   ";
    expect(scraper.getPgBouncerAdminUrl()).toBeNull();
  });

  it("returns null when adminUrl is tab-only whitespace", () => {
    mocks.config.pgbouncerMetrics.adminUrl = "\t";
    expect(scraper.getPgBouncerAdminUrl()).toBeNull();
  });

  it("returns null for mixed whitespace (spaces, tabs, newlines)", () => {
    mocks.config.pgbouncerMetrics.adminUrl = "  \t\n  ";
    expect(scraper.getPgBouncerAdminUrl()).toBeNull();
  });

  it("does not throw when adminUrl is empty — returns null instead", () => {
    mocks.config.pgbouncerMetrics.adminUrl = "";
    expect(() => scraper.getPgBouncerAdminUrl()).not.toThrow();
  });

  it("does not throw when adminUrl is whitespace-only — returns null instead", () => {
    mocks.config.pgbouncerMetrics.adminUrl = "   ";
    expect(() => scraper.getPgBouncerAdminUrl()).not.toThrow();
  });
});

describe("regression #1002 — getPgBouncerAdminUrl() scheme validation (line 61)", () => {
  const EXPECTED_MSG = "PgBouncer admin URL must use postgres or postgresql";

  it.each([
    ["http",            "http://localhost:6432/pgbouncer"],
    ["mysql",           "mysql://user:pass@localhost:3306/db"],
    ["redis",           "redis://localhost:6379"],
    ["ftp",             "ftp://localhost/pgbouncer"],
    ["jdbc:postgresql", "jdbc:postgresql://localhost/pgbouncer"],
    ["file",            "file:///etc/pgbouncer/pgbouncer.ini"],
  ])("throws for scheme '%s'", (_scheme, url) => {
    mocks.config.pgbouncerMetrics.adminUrl = url;
    expect(() => scraper.getPgBouncerAdminUrl()).toThrow(EXPECTED_MSG);
  });

  it("error is an instance of Error with the exact message", () => {
    mocks.config.pgbouncerMetrics.adminUrl = "http://localhost/pgbouncer";
    let caught: unknown;
    try { scraper.getPgBouncerAdminUrl(); } catch (e) { caught = e; }
    expect(caught).toBeInstanceOf(Error);
    expect((caught as Error).message).toBe(EXPECTED_MSG);
  });

  it.each([
    ["postgres",    "postgres://user:pass@localhost:6432/pgbouncer"],
    ["postgresql",  "postgresql://metrics:secret@localhost:6432/pgbouncer"],
  ])("accepts scheme '%s' and returns the URL", (_scheme, url) => {
    mocks.config.pgbouncerMetrics.adminUrl = url;
    expect(scraper.getPgBouncerAdminUrl()).toBe(url);
  });

  it("trims surrounding whitespace from a valid URL", () => {
    const bare = "postgresql://metrics:secret@localhost:6432/pgbouncer";
    mocks.config.pgbouncerMetrics.adminUrl = `  ${bare}  `;
    expect(scraper.getPgBouncerAdminUrl()).toBe(bare);
  });
});

describe("regression #1002 — scrapeInterval boundary clamping", () => {
  it("clamps 0 up to MIN_SCRAPE_INTERVAL_MS", () => {
    mocks.config.pgbouncerMetrics.scrapeIntervalMs = 0;
    expect(scraper.getPgBouncerScrapeIntervalMs()).toBe(scraper.MIN_SCRAPE_INTERVAL_MS);
  });

  it("accepts exactly MIN_SCRAPE_INTERVAL_MS (at-boundary)", () => {
    mocks.config.pgbouncerMetrics.scrapeIntervalMs = scraper.MIN_SCRAPE_INTERVAL_MS;
    expect(scraper.getPgBouncerScrapeIntervalMs()).toBe(scraper.MIN_SCRAPE_INTERVAL_MS);
  });

  it("accepts MIN_SCRAPE_INTERVAL_MS + 1 without modification", () => {
    mocks.config.pgbouncerMetrics.scrapeIntervalMs = scraper.MIN_SCRAPE_INTERVAL_MS + 1;
    expect(scraper.getPgBouncerScrapeIntervalMs()).toBe(scraper.MIN_SCRAPE_INTERVAL_MS + 1);
  });

  it("accepts exactly MAX_SCRAPE_INTERVAL_MS (at-ceiling)", () => {
    mocks.config.pgbouncerMetrics.scrapeIntervalMs = scraper.MAX_SCRAPE_INTERVAL_MS;
    expect(scraper.getPgBouncerScrapeIntervalMs()).toBe(scraper.MAX_SCRAPE_INTERVAL_MS);
  });

  it("clamps MAX_SCRAPE_INTERVAL_MS + 1 down to MAX_SCRAPE_INTERVAL_MS", () => {
    mocks.config.pgbouncerMetrics.scrapeIntervalMs = scraper.MAX_SCRAPE_INTERVAL_MS + 1;
    expect(scraper.getPgBouncerScrapeIntervalMs()).toBe(scraper.MAX_SCRAPE_INTERVAL_MS);
  });
});

describe("regression #1002 — queryTimeout capped by scrapeInterval", () => {
  it("caps queryTimeout at scrapeInterval when scrapeInterval < MAX_QUERY_TIMEOUT_MS", () => {
    mocks.config.pgbouncerMetrics.scrapeIntervalMs = 5_000;
    mocks.config.pgbouncerMetrics.queryTimeoutMs = 10_000;
    expect(scraper.getPgBouncerQueryTimeoutMs()).toBe(5_000);
  });

  it("caps queryTimeout at MIN_SCRAPE_INTERVAL_MS when scrapeInterval is at its floor", () => {
    mocks.config.pgbouncerMetrics.scrapeIntervalMs = 1; // clamps to 1 000
    mocks.config.pgbouncerMetrics.queryTimeoutMs = 99_999;
    expect(scraper.getPgBouncerQueryTimeoutMs()).toBe(scraper.MIN_SCRAPE_INTERVAL_MS);
  });

  it("raises queryTimeout to MIN_QUERY_TIMEOUT_MS when configured below floor", () => {
    mocks.config.pgbouncerMetrics.scrapeIntervalMs = 15_000;
    mocks.config.pgbouncerMetrics.queryTimeoutMs = 1;
    expect(scraper.getPgBouncerQueryTimeoutMs()).toBe(scraper.MIN_QUERY_TIMEOUT_MS);
  });

  it("result is always ≤ getPgBouncerScrapeIntervalMs()", () => {
    mocks.config.pgbouncerMetrics.scrapeIntervalMs = 3_000;
    mocks.config.pgbouncerMetrics.queryTimeoutMs = 5_000;
    expect(scraper.getPgBouncerQueryTimeoutMs()).toBeLessThanOrEqual(
      scraper.getPgBouncerScrapeIntervalMs(),
    );
  });
});

describe("regression #1002 — null/empty adminUrl prevents scraping and starting", () => {
  it("scrapeOnce() returns false for empty-string adminUrl", async () => {
    mocks.config.pgbouncerMetrics.adminUrl = "";
    await expect(scraper.scrapeOnce()).resolves.toBe(false);
    expect(mocks.query).not.toHaveBeenCalled();
  });

  it("scrapeOnce() returns false for whitespace-only adminUrl", async () => {
    mocks.config.pgbouncerMetrics.adminUrl = "   ";
    await expect(scraper.scrapeOnce()).resolves.toBe(false);
    expect(mocks.query).not.toHaveBeenCalled();
  });

  it("startPgBouncerScraper() returns false for empty-string adminUrl", () => {
    mocks.config.pgbouncerMetrics.adminUrl = "";
    expect(scraper.startPgBouncerScraper()).toBe(false);
  });

  it("startPgBouncerScraper() returns false for whitespace-only adminUrl", () => {
    mocks.config.pgbouncerMetrics.adminUrl = "   ";
    expect(scraper.startPgBouncerScraper()).toBe(false);
  });
});
