import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { metricsRegistry } from "../../src/metrics.js";

// Set up mocks before importing the module
const mockQuery = vi.fn();
const mockConnect = vi.fn().mockResolvedValue({
  query: mockQuery,
  release: vi.fn(),
});
const mockPool = {
  connect: mockConnect,
  end: vi.fn().mockResolvedValue(undefined),
};

vi.mock("pg", () => ({
  default: {
    Pool: vi.fn().mockImplementation(() => mockPool),
  },
}));

vi.mock("../../config/index.js", () => ({
  config: {
    db: {
      url: "postgresql://user:pass@localhost:5432/veritasor",
    },
  },
}));

vi.mock("../../src/utils/logger.js", () => ({
  logger: {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
  },
}));

// Import after mocks are set up
const {
  getPgBouncerAdminUrl,
  startPgBouncerScraper,
  stopPgBouncerScraper,
  SCRAPE_INTERVAL_MS,
  SCRAPE_TIMEOUT_MS,
} = await import("../../src/services/pgbouncerScraper.js");

beforeEach(async () => {
  vi.useFakeTimers();
  await metricsRegistry.resetMetrics();
  mockQuery.mockReset();
  mockConnect.mockReset();
  mockPool.connect.mockResolvedValue({
    query: mockQuery,
    release: vi.fn(),
  });
  mockPool.end.mockResolvedValue(undefined);
  await stopPgBouncerScraper();
});

afterEach(async () => {
  vi.useRealTimers();
  await stopPgBouncerScraper();
});

describe("PgBouncer scraper", () => {
  it("exports SCRAPE_INTERVAL_MS as 1000", () => {
    expect(SCRAPE_INTERVAL_MS).toBe(1000);
  });

  it("exports SCRAPE_TIMEOUT_MS as 500", () => {
    expect(SCRAPE_TIMEOUT_MS).toBe(500);
  });

  it("getPgBouncerAdminUrl returns correct admin URL", () => {
    const url = getPgBouncerAdminUrl();
    expect(url).toContain("postgres://");
    expect(url).toContain("/pgbouncer");
    expect(url).toContain("statement_cache_size=0");
  });

  describe("startPgBouncerScraper", () => {
    it("starts scraper without error", async () => {
      await startPgBouncerScraper();
      // If we get here without throwing, the test passes
    });
  });

  describe("stopPgBouncerScraper", () => {
    it("stops scraper without error", async () => {
      await stopPgBouncerScraper();
    });

    it("is idempotent", async () => {
      await stopPgBouncerScraper();
      await stopPgBouncerScraper();
    });
  });
});