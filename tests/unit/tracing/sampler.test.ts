import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SamplingDecision } from "@opentelemetry/api";
import {
  RouteAwareSampler,
  loadSamplerConfig,
  tracingSampledTotal,
  type SamplerConfig,
} from "../../../src/tracing/sampler.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeSampler(config: Partial<SamplerConfig> = {}): RouteAwareSampler {
  return new RouteAwareSampler({
    defaultRate: 1,
    hotRoutes: [],
    rareRoutes: [],
    ...config,
  });
}

/** Call shouldSample with only the attributes we care about. */
function sample(
  sampler: RouteAwareSampler,
  route: string,
): ReturnType<RouteAwareSampler["shouldSample"]> {
  return sampler.shouldSample(
    {} as never,
    "trace-id",
    "span-name",
    0 as never,
    route ? { "http.route": route } : {},
    [],
  );
}

// ---------------------------------------------------------------------------
// _resolveRate — pure logic, no randomness
// ---------------------------------------------------------------------------

describe("RouteAwareSampler._resolveRate", () => {
  it("returns defaultRate when no rules match", () => {
    const s = makeSampler({ defaultRate: 0.5 });
    expect(s._resolveRate("/api/v1/users")).toEqual({
      rate: 0.5,
      ruleType: "default",
    });
  });

  it("matches a hot-path rule and returns its rate", () => {
    const s = makeSampler({
      hotRoutes: [{ route: "/health", rate: 0.01 }],
    });
    expect(s._resolveRate("/health")).toEqual({ rate: 0.01, ruleType: "hot" });
  });

  it("matches a rare-path rule and returns its rate", () => {
    const s = makeSampler({
      rareRoutes: [{ route: "/admin", rate: 1 }],
    });
    expect(s._resolveRate("/admin/users")).toEqual({
      rate: 1,
      ruleType: "rare",
    });
  });

  it("rare-path rule wins over hot-path rule for the same prefix", () => {
    const s = makeSampler({
      hotRoutes: [{ route: "/api", rate: 0.01 }],
      rareRoutes: [{ route: "/api/v1/admin", rate: 1 }],
    });
    expect(s._resolveRate("/api/v1/admin/settings")).toEqual({
      rate: 1,
      ruleType: "rare",
    });
  });

  it("selects the most specific (longest) prefix among hot routes", () => {
    const s = makeSampler({
      hotRoutes: [
        { route: "/api", rate: 0.1 },
        { route: "/api/v1/health", rate: 0.001 },
      ],
    });
    expect(s._resolveRate("/api/v1/health")).toEqual({
      rate: 0.001,
      ruleType: "hot",
    });
  });

  it("falls back to default when route is an empty string", () => {
    const s = makeSampler({ defaultRate: 0.2 });
    expect(s._resolveRate("")).toEqual({ rate: 0.2, ruleType: "default" });
  });

  it("does not match a route that only shares a substring, not a prefix", () => {
    const s = makeSampler({
      hotRoutes: [{ route: "/metrics", rate: 0 }],
    });
    // "/not-metrics" does NOT start with "/metrics"
    expect(s._resolveRate("/not-metrics")).toEqual({
      rate: 1,
      ruleType: "default",
    });
  });
});

// ---------------------------------------------------------------------------
// shouldSample — sampling decisions
// ---------------------------------------------------------------------------

describe("RouteAwareSampler.shouldSample", () => {
  it("always samples when rate is 1", () => {
    const s = makeSampler({ defaultRate: 1 });
    for (let i = 0; i < 20; i++) {
      expect(sample(s, "/api/v1/users").decision).toBe(
        SamplingDecision.RECORD_AND_SAMPLED,
      );
    }
  });

  it("never samples when rate is 0", () => {
    const s = makeSampler({
      hotRoutes: [{ route: "/health", rate: 0 }],
    });
    for (let i = 0; i < 20; i++) {
      expect(sample(s, "/health").decision).toBe(
        SamplingDecision.NOT_RECORD,
      );
    }
  });

  it("uses http.target attribute when http.route is absent", () => {
    const s = makeSampler({
      hotRoutes: [{ route: "/metrics", rate: 0 }],
    });
    const result = s.shouldSample(
      {} as never,
      "t",
      "n",
      0 as never,
      { "http.target": "/metrics" },
      [],
    );
    expect(result.decision).toBe(SamplingDecision.NOT_RECORD);
  });

  it("applies probabilistic sampling correctly at 50 %", () => {
    const s = makeSampler({ defaultRate: 0.5 });
    let sampled = 0;
    const N = 10_000;

    // Seed Math.random so we exercise the branch, not just mock it.
    for (let i = 0; i < N; i++) {
      if (sample(s, "/route").decision === SamplingDecision.RECORD_AND_SAMPLED) {
        sampled++;
      }
    }

    // Within 5 % of expected mean (4750–5250) with very high probability.
    expect(sampled).toBeGreaterThan(N * 0.45);
    expect(sampled).toBeLessThan(N * 0.55);
  });

  it("returns no additional attributes or traceState in the result", () => {
    const s = makeSampler();
    const result = sample(s, "/api/v1/attestations");
    expect(result.attributes).toBeUndefined();
    expect(result.traceState).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Metrics emission
// ---------------------------------------------------------------------------

describe("RouteAwareSampler metrics", () => {
  beforeEach(() => {
    tracingSampledTotal.reset();
  });

  it("increments sampled counter with 'sampled' decision and correct rule_type", () => {
    const s = makeSampler({ defaultRate: 1 });
    sample(s, "/api/v1/users");

    const values = tracingSampledTotal.hashMap;
    const key = Object.keys(values).find((k) => k.includes("sampled"));
    expect(key).toBeDefined();
  });

  it("increments counter with 'dropped' decision when rate is 0", () => {
    const s = makeSampler({
      hotRoutes: [{ route: "/health", rate: 0 }],
    });
    sample(s, "/health");

    const values = tracingSampledTotal.hashMap;
    const key = Object.keys(values).find((k) => k.includes("dropped"));
    expect(key).toBeDefined();
  });

  it("uses rule_type=rare for rare-path matches", () => {
    const s = makeSampler({
      rareRoutes: [{ route: "/webhooks", rate: 1 }],
    });
    sample(s, "/webhooks/stripe");

    const values = tracingSampledTotal.hashMap;
    const rareKey = Object.keys(values).find((k) => k.includes("rare"));
    expect(rareKey).toBeDefined();
  });

  it("uses rule_type=hot for hot-path matches", () => {
    const s = makeSampler({
      hotRoutes: [{ route: "/metrics", rate: 0.01 }],
    });
    // Force a "sampled" decision for the metric
    vi.spyOn(Math, "random").mockReturnValue(0);
    sample(s, "/metrics");
    vi.restoreAllMocks();

    const values = tracingSampledTotal.hashMap;
    const hotKey = Object.keys(values).find((k) => k.includes("hot"));
    expect(hotKey).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// Hot-reload
// ---------------------------------------------------------------------------

describe("RouteAwareSampler.reload", () => {
  it("picks up new config immediately after reload()", () => {
    const s = makeSampler({ defaultRate: 1 });

    // /health is not hot yet — should be sampled
    expect(sample(s, "/health").decision).toBe(
      SamplingDecision.RECORD_AND_SAMPLED,
    );

    s.reload({
      defaultRate: 1,
      hotRoutes: [{ route: "/health", rate: 0 }],
      rareRoutes: [],
    });

    // After reload /health is hot and rate=0 → always dropped
    expect(sample(s, "/health").decision).toBe(SamplingDecision.NOT_RECORD);
  });

  it("reload() reads env vars when no config is passed", () => {
    const original = process.env.OTEL_SAMPLING_DEFAULT_RATE;
    process.env.OTEL_SAMPLING_DEFAULT_RATE = "0";

    const s = new RouteAwareSampler();
    s.reload(); // re-read env

    for (let i = 0; i < 10; i++) {
      expect(sample(s, "/any").decision).toBe(SamplingDecision.NOT_RECORD);
    }

    process.env.OTEL_SAMPLING_DEFAULT_RATE = original;
  });
});

// ---------------------------------------------------------------------------
// loadSamplerConfig — env var parsing
// ---------------------------------------------------------------------------

describe("loadSamplerConfig", () => {
  const saved: Record<string, string | undefined> = {};

  beforeEach(() => {
    for (const k of [
      "OTEL_SAMPLING_DEFAULT_RATE",
      "OTEL_SAMPLING_HOT_ROUTES",
      "OTEL_SAMPLING_RARE_ROUTES",
    ]) {
      saved[k] = process.env[k];
      delete process.env[k];
    }
  });

  afterEach(() => {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  });

  it("returns defaults when env vars are unset", () => {
    const cfg = loadSamplerConfig();
    expect(cfg.defaultRate).toBe(1.0);
    expect(cfg.hotRoutes).toEqual([]);
    expect(cfg.rareRoutes).toEqual([]);
  });

  it("parses OTEL_SAMPLING_DEFAULT_RATE", () => {
    process.env.OTEL_SAMPLING_DEFAULT_RATE = "0.25";
    expect(loadSamplerConfig().defaultRate).toBe(0.25);
  });

  it("parses OTEL_SAMPLING_HOT_ROUTES from JSON", () => {
    process.env.OTEL_SAMPLING_HOT_ROUTES = JSON.stringify([
      { route: "/health", rate: 0.01 },
    ]);
    const cfg = loadSamplerConfig();
    expect(cfg.hotRoutes).toEqual([{ route: "/health", rate: 0.01 }]);
  });

  it("parses OTEL_SAMPLING_RARE_ROUTES from JSON", () => {
    process.env.OTEL_SAMPLING_RARE_ROUTES = JSON.stringify([
      { route: "/admin", rate: 1 },
    ]);
    const cfg = loadSamplerConfig();
    expect(cfg.rareRoutes).toEqual([{ route: "/admin", rate: 1 }]);
  });

  it("accepts rate=0 and rate=1 as valid boundary values", () => {
    process.env.OTEL_SAMPLING_DEFAULT_RATE = "0";
    expect(loadSamplerConfig().defaultRate).toBe(0);

    process.env.OTEL_SAMPLING_DEFAULT_RATE = "1";
    expect(loadSamplerConfig().defaultRate).toBe(1);
  });

  it("throws on OTEL_SAMPLING_DEFAULT_RATE out of range", () => {
    process.env.OTEL_SAMPLING_DEFAULT_RATE = "1.5";
    expect(() => loadSamplerConfig()).toThrow(/between 0 and 1/);
  });

  it("throws on OTEL_SAMPLING_DEFAULT_RATE that is not a number", () => {
    process.env.OTEL_SAMPLING_DEFAULT_RATE = "lots";
    expect(() => loadSamplerConfig()).toThrow(/between 0 and 1/);
  });

  it("throws on OTEL_SAMPLING_HOT_ROUTES that is not valid JSON", () => {
    process.env.OTEL_SAMPLING_HOT_ROUTES = "not-json";
    expect(() => loadSamplerConfig()).toThrow(/valid JSON/);
  });

  it("throws on OTEL_SAMPLING_HOT_ROUTES that is not an array", () => {
    process.env.OTEL_SAMPLING_HOT_ROUTES = JSON.stringify({ route: "/x" });
    expect(() => loadSamplerConfig()).toThrow(/JSON array/);
  });

  it("throws when a route rule is missing the rate field", () => {
    process.env.OTEL_SAMPLING_HOT_ROUTES = JSON.stringify([
      { route: "/health" },
    ]);
    expect(() => loadSamplerConfig()).toThrow(/rate/);
  });

  it("throws when a route rule has an out-of-range rate", () => {
    process.env.OTEL_SAMPLING_HOT_ROUTES = JSON.stringify([
      { route: "/health", rate: 2 },
    ]);
    expect(() => loadSamplerConfig()).toThrow(/between 0 and 1/);
  });

  it("ignores empty string env vars and falls back to defaults", () => {
    process.env.OTEL_SAMPLING_DEFAULT_RATE = "";
    process.env.OTEL_SAMPLING_HOT_ROUTES = "";
    process.env.OTEL_SAMPLING_RARE_ROUTES = "";
    const cfg = loadSamplerConfig();
    expect(cfg.defaultRate).toBe(1.0);
    expect(cfg.hotRoutes).toEqual([]);
    expect(cfg.rareRoutes).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// toString
// ---------------------------------------------------------------------------

describe("RouteAwareSampler.toString", () => {
  it("includes the sampler class name and default rate", () => {
    const s = makeSampler({ defaultRate: 0.42 });
    expect(s.toString()).toContain("RouteAwareSampler");
    expect(s.toString()).toContain("0.42");
  });
});
