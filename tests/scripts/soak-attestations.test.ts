import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  buildConfig,
  parseArgs,
  buildPeriod,
  buildSubmitPayload,
  buildIdempotencyKey,
  extractLatencyBuckets,
  formatLatencyTable,
  formatSummary,
  evaluateThresholds,
  buildAutocannonOptions,
  main,
  type SoakConfig,
  type Result,
} from "../../scripts/soak-attestations.js";

// --- helpers ---

function makeResult(overrides: Partial<Result> = {}): Result {
  return {
    title: undefined,
    url: "http://127.0.0.1:3000/api/v1/attestations",
    socketPath: undefined,
    requests: {
      total: 1000,
      average: 50,
      mean: 50,
      stddev: 5,
      min: 30,
      max: 80,
      p0_001: 30,
      p0_01: 30,
      p0_1: 31,
      p1: 32,
      p2_5: 33,
      p10: 35,
      p25: 40,
      p50: 50,
      p75: 60,
      p90: 65,
      p95: 68,
      p97_5: 70,
      p99: 75,
      p99_9: 78,
      p99_99: 79,
      p99_999: 80,
      sent: 1000,
    },
    latency: {
      total: 50000,
      average: 50,
      mean: 50,
      stddev: 10,
      min: 5,
      max: 200,
      p0_001: 5,
      p0_01: 5,
      p0_1: 6,
      p1: 7,
      p2_5: 8,
      p10: 15,
      p25: 25,
      p50: 45,
      p75: 65,
      p90: 80,
      p95: 120,
      p97_5: 120,
      p99: 150,
      p99_9: 180,
      p99_99: 190,
      p99_999: 200,
    },
    throughput: {
      total: 512000,
      average: 10240,
      mean: 10240,
      stddev: 500,
      min: 8000,
      max: 12000,
      p0_001: 8000,
      p0_01: 8000,
      p0_1: 8200,
      p1: 8500,
      p2_5: 8800,
      p10: 9000,
      p25: 9500,
      p50: 10240,
      p75: 10800,
      p90: 11200,
      p95: 11400,
      p97_5: 11600,
      p99: 11800,
      p99_9: 11900,
      p99_99: 11950,
      p99_999: 12000,
    },
    duration: 30,
    errors: 2,
    timeouts: 1,
    start: new Date("2026-01-01T00:00:00Z"),
    finish: new Date("2026-01-01T00:00:30Z"),
    connections: 10,
    pipelining: 1,
    non2xx: 3,
    "1xx": 0,
    "2xx": 994,
    "3xx": 0,
    "4xx": 2,
    "5xx": 1,
    mismatches: 0,
    resets: 0,
    ...overrides,
  } as Result;
}

function defaultCfg(overrides: Partial<SoakConfig> = {}): SoakConfig {
  return {
    url: "http://127.0.0.1:3000",
    path: "/api/v1/attestations",
    token: "test-token",
    duration: 30,
    connections: 10,
    businessId: "",
    merkleRoot: `0x${"ab".repeat(32)}`,
    p95ThresholdMs: 500,
    errorRateThreshold: 0.01,
    writeRatio: 1.0,
    bailout: 0,
    timeout: 10,
    ...overrides,
  };
}

// --- parseArgs ---

describe("parseArgs", () => {
  it("returns empty object for no flags", () => {
    const result = parseArgs(["node", "script.ts"]);
    expect(result).toEqual({});
  });

  it("parses all recognized flags", () => {
    const result = parseArgs([
      "node", "script.ts",
      "--url", "http://example.com",
      "--path", "/api/v2/attestations",
      "--token", "my-jwt",
      "--duration", "60",
      "--connections", "20",
      "--businessId", "biz-123",
      "--merkleRoot", "0xcc".repeat(32),
      "--p95ThresholdMs", "300",
      "--errorRateThreshold", "0.05",
      "--writeRatio", "0.5",
      "--bailout", "100",
      "--timeout", "5",
    ]);
    expect(result.url).toBe("http://example.com");
    expect(result.path).toBe("/api/v2/attestations");
    expect(result.token).toBe("my-jwt");
    expect(result.duration).toBe(60);
    expect(result.connections).toBe(20);
    expect(result.businessId).toBe("biz-123");
    expect(result.merkleRoot).toBe("0xcc".repeat(32));
    expect(result.p95ThresholdMs).toBe(300);
    expect(result.errorRateThreshold).toBe(0.05);
    expect(result.writeRatio).toBe(0.5);
    expect(result.bailout).toBe(100);
    expect(result.timeout).toBe(5);
  });

  it("ignores unknown flags gracefully", () => {
    const result = parseArgs(["node", "script.ts", "--unknown", "val", "--url", "http://ok.com"]);
    expect(result.url).toBe("http://ok.com");
    expect(result).not.toHaveProperty("unknown");
  });
});

// --- buildConfig ---

describe("buildConfig", () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it("uses defaults when no env or args are set", () => {
    delete process.env.SOAK_BASE_URL;
    delete process.env.SOAK_AUTH_TOKEN;
    delete process.env.SOAK_DURATION;
    delete process.env.SOAK_CONNECTIONS;

    const cfg = buildConfig(["node", "script.ts"]);
    expect(cfg.url).toBe("http://127.0.0.1:3000");
    expect(cfg.path).toBe("/api/v1/attestations");
    expect(cfg.token).toBe("");
    expect(cfg.duration).toBe(30);
    expect(cfg.connections).toBe(10);
  });

  it("reads env vars", () => {
    process.env.SOAK_BASE_URL = "http://env-host:4000";
    process.env.SOAK_AUTH_TOKEN = "env-token";
    process.env.SOAK_DURATION = "120";
    process.env.SOAK_CONNECTIONS = "50";
    process.env.SOAK_P95_THRESHOLD_MS = "200";
    process.env.SOAK_ERROR_RATE_THRESHOLD = "0.02";

    const cfg = buildConfig(["node", "script.ts"]);
    expect(cfg.url).toBe("http://env-host:4000");
    expect(cfg.token).toBe("env-token");
    expect(cfg.duration).toBe(120);
    expect(cfg.connections).toBe(50);
    expect(cfg.p95ThresholdMs).toBe(200);
    expect(cfg.errorRateThreshold).toBeCloseTo(0.02);
  });

  it("CLI flags override env vars", () => {
    process.env.SOAK_BASE_URL = "http://env-host:4000";
    process.env.SOAK_DURATION = "120";

    const cfg = buildConfig(["node", "script.ts", "--url", "http://cli:9000", "--duration", "10"]);
    expect(cfg.url).toBe("http://cli:9000");
    expect(cfg.duration).toBe(10);
  });

  it("allows zero duration (exits cleanly in main)", () => {
    process.env.SOAK_DURATION = "0";
    const cfg = buildConfig(["node", "script.ts"]);
    expect(cfg.duration).toBe(0); // 0 is valid and triggers early exit in main()
  });

  it("clamps writeRatio between 0 and 1", () => {
    process.env.SOAK_WRITE_RATIO = "1.5";
    const cfg = buildConfig(["node", "script.ts"]);
    expect(cfg.writeRatio).toBe(1.0); // falls back to default
  });
});

// --- buildPeriod ---

describe("buildPeriod", () => {
  it("generates a period string containing the runId", () => {
    const period = buildPeriod("run123");
    expect(period).toContain("soak-run123-");
  });

  it("truncates to 50 characters", () => {
    const period = buildPeriod("a".repeat(100));
    expect(period.length).toBeLessThanOrEqual(50);
  });
});

// --- buildSubmitPayload ---

describe("buildSubmitPayload", () => {
  it("returns valid JSON with required fields", () => {
    const cfg = defaultCfg();
    const payload = JSON.parse(buildSubmitPayload(cfg, "run1"));
    expect(payload.merkleRoot).toBe(cfg.merkleRoot);
    expect(payload.period).toContain("soak-run1-");
    expect(payload.version).toBe("1.0.0");
    expect(payload.submit).toBe(false);
    expect(payload.businessId).toBeUndefined();
  });

  it("includes businessId when provided", () => {
    const cfg = defaultCfg({ businessId: "biz-abc" });
    const payload = JSON.parse(buildSubmitPayload(cfg, "run1"));
    expect(payload.businessId).toBe("biz-abc");
  });
});

// --- buildIdempotencyKey ---

describe("buildIdempotencyKey", () => {
  it("returns a string with the runId prefix", () => {
    const key = buildIdempotencyKey("run1", 0);
    expect(key).toContain("soak-run1-");
  });

  it("sanitizes special characters", () => {
    const key = buildIdempotencyKey("run/1@#$", 5);
    expect(key).toMatch(/^[a-zA-Z0-9_-]+$/);
  });

  it("truncates to 128 characters", () => {
    const key = buildIdempotencyKey("x".repeat(200), 0);
    expect(key.length).toBeLessThanOrEqual(128);
  });

  it("includes the iteration number", () => {
    const key0 = buildIdempotencyKey("r", 0);
    const key1 = buildIdempotencyKey("r", 1);
    expect(key0).not.toBe(key1);
  });
});

// --- extractLatencyBuckets ---

describe("extractLatencyBuckets", () => {
  it("returns all percentile buckets", () => {
    const result = makeResult();
    const buckets = extractLatencyBuckets(result);
    expect(buckets).toHaveLength(8);
    expect(buckets.map((b: { label: string }) => b.label)).toEqual([
      "min", "p50", "p75", "p90", "p95", "p99", "max", "average",
    ]);
  });

  it("extracts correct values from result", () => {
    const result = makeResult();
    const buckets = extractLatencyBuckets(result);
    const byLabel = Object.fromEntries(buckets.map((b) => [b.label, b.value]));
    expect(byLabel.min).toBe(5);
    expect(byLabel.p50).toBe(45);
    expect(byLabel.p95).toBe(120);
    expect(byLabel.p99).toBe(150);
    expect(byLabel.max).toBe(200);
    expect(byLabel.average).toBe(50);
  });
});

// --- formatLatencyTable ---

describe("formatLatencyTable", () => {
  it("returns a markdown-style table", () => {
    const buckets = [
      { label: "p50", value: 45.123 },
      { label: "p95", value: 120.456 },
    ];
    const table = formatLatencyTable(buckets);
    expect(table).toContain("| Percentile | Latency (ms) |");
    expect(table).toContain("|------------|-------------|");
    expect(table).toContain("| p50        |       45.12 |");
    expect(table).toContain("| p95        |      120.46 |");
  });
});

// --- formatSummary ---

describe("formatSummary", () => {
  it("contains all major sections", () => {
    const result = makeResult();
    const cfg = defaultCfg();
    const summary = formatSummary(result, cfg);
    expect(summary).toContain("Attestation Soak Test Results");
    expect(summary).toContain("Latency");
    expect(summary).toContain("Status Codes");
    expect(summary).toContain("Thresholds");
  });

  it("displays p95 pass when under threshold", () => {
    const result = makeResult({ latency: { ...makeResult().latency, p95: 100 } });
    const cfg = defaultCfg({ p95ThresholdMs: 500 });
    const summary = formatSummary(result, cfg);
    expect(summary).toContain("pass_actual:");
  });

  it("displays p95 fail when over threshold", () => {
    const result = makeResult({ latency: { ...makeResult().latency, p95: 600 } });
    const cfg = defaultCfg({ p95ThresholdMs: 500 });
    const summary = formatSummary(result, cfg);
    expect(summary).toContain("fail_actual:");
  });
});

// --- evaluateThresholds ---

describe("evaluateThresholds", () => {
  it("passes when p95 and error rate are within limits", () => {
    const result = makeResult();
    const cfg = defaultCfg({ p95ThresholdMs: 200, errorRateThreshold: 0.01 });
    const check = evaluateThresholds(result, cfg);
    expect(check.passed).toBe(true);
    expect(check.p95Passed).toBe(true);
    expect(check.errorRatePassed).toBe(true);
  });

  it("fails when p95 exceeds threshold", () => {
    const result = makeResult({ latency: { ...makeResult().latency, p95: 600 } });
    const cfg = defaultCfg({ p95ThresholdMs: 500 });
    const check = evaluateThresholds(result, cfg);
    expect(check.passed).toBe(false);
    expect(check.p95Passed).toBe(false);
    expect(check.errorRatePassed).toBe(true);
  });

  it("fails when error rate exceeds threshold", () => {
    const result = makeResult({
      errors: 50,
      timeouts: 20,
      non2xx: 30,
      requests: { ...makeResult().requests, total: 1000 },
    });
    const cfg = defaultCfg({ errorRateThreshold: 0.01 });
    const check = evaluateThresholds(result, cfg);
    expect(check.passed).toBe(false);
    expect(check.errorRatePassed).toBe(false);
  });

  it("handles zero total requests gracefully", () => {
    const result = makeResult({
      requests: { ...makeResult().requests, total: 0 },
    });
    const cfg = defaultCfg();
    const check = evaluateThresholds(result, cfg);
    expect(check.passed).toBe(true);
    expect(check.errorRateActual).toBe(0);
  });

  it("reports correct actual values", () => {
    const result = makeResult();
    const cfg = defaultCfg();
    const check = evaluateThresholds(result, cfg);
    expect(check.p95Actual).toBe(120);
    expect(check.errorRateActual).toBeCloseTo(0.006);
  });
});

// --- buildAutocannonOptions ---

describe("buildAutocannonOptions", () => {
  it("builds POST options for write requests", () => {
    vi.spyOn(Math, "random").mockReturnValue(0);
    const cfg = defaultCfg({ writeRatio: 1.0 });
    const opts = buildAutocannonOptions(cfg, "run1");
    expect(opts.method).toBe("POST");
    expect(opts.headers).toHaveProperty("Content-Type", "application/json");
    expect(opts.headers).toHaveProperty("Idempotency-Key");
    expect(opts.body).toBeDefined();
    vi.mocked(Math.random).mockRestore();
  });

  it("builds GET options for read requests", () => {
    vi.spyOn(Math, "random").mockReturnValue(0.99);
    const cfg = defaultCfg({ writeRatio: 0.0 });
    const opts = buildAutocannonOptions(cfg, "run1");
    expect(opts.method).toBe("GET");
    expect(opts.body).toBeUndefined();
    vi.mocked(Math.random).mockRestore();
  });

  it("includes auth header", () => {
    vi.spyOn(Math, "random").mockReturnValue(0);
    const cfg = defaultCfg({ token: "my-jwt" });
    const opts = buildAutocannonOptions(cfg, "run1");
    expect(opts.headers).toHaveProperty("Authorization", "Bearer my-jwt");
    vi.mocked(Math.random).mockRestore();
  });

  it("passes bailout when > 0", () => {
    vi.spyOn(Math, "random").mockReturnValue(0);
    const cfg = defaultCfg({ bailout: 50 });
    const opts = buildAutocannonOptions(cfg, "run1");
    expect(opts.bailout).toBe(50);
    vi.mocked(Math.random).mockRestore();
  });

  it("does not set bailout when 0", () => {
    vi.spyOn(Math, "random").mockReturnValue(0);
    const cfg = defaultCfg({ bailout: 0 });
    const opts = buildAutocannonOptions(cfg, "run1");
    expect(opts.bailout).toBeUndefined();
    vi.mocked(Math.random).mockRestore();
  });

  it("trims trailing slashes from URL", () => {
    vi.spyOn(Math, "random").mockReturnValue(0);
    const cfg = defaultCfg({ url: "http://localhost:3000///" });
    const opts = buildAutocannonOptions(cfg, "run1");
    expect(opts.url).toBe("http://localhost:3000/api/v1/attestations");
    vi.mocked(Math.random).mockRestore();
  });
});

// --- main ---

describe("main", () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    process.env = { ...originalEnv };
    process.env.SOAK_AUTH_TOKEN = "test-token";
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it("returns 1 when token is missing", async () => {
    delete process.env.SOAK_AUTH_TOKEN;
    const code = await main(["node", "script.ts"]);
    expect(code).toBe(1);
  });

  it("returns 0 for zero-duration (exits cleanly)", async () => {
    const code = await main(["node", "script.ts", "--duration", "0"]);
    expect(code).toBe(0);
  });

  it("returns 0 for zero-connections (exits cleanly)", async () => {
    const code = await main(["node", "script.ts", "--connections", "0"]);
    expect(code).toBe(0);
  });

  it("accepts CLI --token flag", async () => {
    process.env.SOAK_DURATION = "0";
    const code = await main(["node", "script.ts", "--token", "cli-token"]);
    expect(code).toBe(0);
  });
});
