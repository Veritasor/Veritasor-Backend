/**
 * Regression suite for src/tracing/sampler.ts
 *
 * Covers:
 *  • buildRouteRules() – happy path, failure paths (invalid JSON, non-array JSON),
 *    and boundary inputs (empty env var, missing env var, single rule, many rules)
 *  • getSampleRate()   – happy path, first-match wins, no-match fallback,
 *    boundary rates (0, 1), invalid default rate throws
 *  • createSampler()   – integration of both helpers via env vars
 *
 * All env-var state is isolated: each test saves/restores process.env so that
 * tests remain order-independent.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  buildRouteRules,
  getSampleRate,
  createSampler,
  RouteRule,
} from "../../../src/tracing/sampler.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Save and restore a single env var around one test. */
function withEnv(key: string, value: string | undefined, fn: () => void): void {
  const original = process.env[key];
  if (value === undefined) {
    delete process.env[key];
  } else {
    process.env[key] = value;
  }
  try {
    fn();
  } finally {
    if (original === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = original;
    }
  }
}

// ---------------------------------------------------------------------------
// buildRouteRules
// ---------------------------------------------------------------------------

describe("buildRouteRules", () => {
  const ENV = "TRACE_ROUTE_RULES";

  // ── Success paths ──────────────────────────────────────────────────────────

  it("returns an empty array when the env var is not set", () => {
    withEnv(ENV, undefined, () => {
      expect(buildRouteRules(ENV)).toEqual([]);
    });
  });

  it("returns an empty array when the env var is an empty string", () => {
    withEnv(ENV, "", () => {
      expect(buildRouteRules(ENV)).toEqual([]);
    });
  });

  it("returns an empty array when the env var holds an empty JSON array", () => {
    withEnv(ENV, "[]", () => {
      expect(buildRouteRules(ENV)).toEqual([]);
    });
  });

  it("parses a single valid RouteRule", () => {
    const rules: RouteRule[] = [{ pattern: "/health", rate: 0 }];
    withEnv(ENV, JSON.stringify(rules), () => {
      expect(buildRouteRules(ENV)).toEqual(rules);
    });
  });

  it("parses multiple RouteRules in declaration order", () => {
    const rules: RouteRule[] = [
      { pattern: "/api", rate: 0.5 },
      { pattern: "/health", rate: 0 },
      { pattern: "/", rate: 1 },
    ];
    withEnv(ENV, JSON.stringify(rules), () => {
      expect(buildRouteRules(ENV)).toEqual(rules);
    });
  });

  it("accepts rules with rate boundary value 0", () => {
    const rules: RouteRule[] = [{ pattern: "/noop", rate: 0 }];
    withEnv(ENV, JSON.stringify(rules), () => {
      const result = buildRouteRules(ENV);
      expect(result[0].rate).toBe(0);
    });
  });

  it("accepts rules with rate boundary value 1", () => {
    const rules: RouteRule[] = [{ pattern: "/everything", rate: 1 }];
    withEnv(ENV, JSON.stringify(rules), () => {
      const result = buildRouteRules(ENV);
      expect(result[0].rate).toBe(1);
    });
  });

  it("uses a custom env var name when provided", () => {
    const rules: RouteRule[] = [{ pattern: "/custom", rate: 0.25 }];
    withEnv("MY_RULES", JSON.stringify(rules), () => {
      expect(buildRouteRules("MY_RULES")).toEqual(rules);
    });
  });

  // ── Failure paths (evidence lines 74, 87, 91) ─────────────────────────────

  it("throws with env-var name and raw value when JSON is invalid — line 74 regression", () => {
    withEnv(ENV, "not-valid-json", () => {
      expect(() => buildRouteRules(ENV)).toThrowError(
        `${ENV} must be valid JSON, got: not-valid-json`,
      );
    });
  });

  it("throws on malformed JSON (unclosed bracket) — line 87 regression", () => {
    withEnv(ENV, '[{"pattern":"/x","rate":0.1}', () => {
      expect(() => buildRouteRules(ENV)).toThrowError(
        /must be valid JSON/,
      );
    });
  });

  it("throws on a plain JSON string (valid JSON but not a rule list) — line 87 regression", () => {
    withEnv(ENV, '"just-a-string"', () => {
      expect(() => buildRouteRules(ENV)).toThrowError(
        `${ENV} must be valid JSON, got: "just-a-string"`,
      );
    });
  });

  it("throws when JSON is a number — line 91 regression (non-array)", () => {
    withEnv(ENV, "42", () => {
      expect(() => buildRouteRules(ENV)).toThrowError(
        `${ENV} must be a JSON array`,
      );
    });
  });

  it("throws when JSON is a plain object — line 91 regression (non-array)", () => {
    withEnv(ENV, '{"pattern":"/x","rate":0.5}', () => {
      expect(() => buildRouteRules(ENV)).toThrowError(
        `${ENV} must be a JSON array`,
      );
    });
  });

  it("throws when JSON is a boolean — line 91 regression (non-array)", () => {
    withEnv(ENV, "true", () => {
      expect(() => buildRouteRules(ENV)).toThrowError(
        /must be a JSON array/,
      );
    });
  });

  it("throws when JSON is null — line 91 regression (non-array)", () => {
    withEnv(ENV, "null", () => {
      expect(() => buildRouteRules(ENV)).toThrowError(
        /must be a JSON array/,
      );
    });
  });

  // ── Error contract is an Error instance ───────────────────────────────────

  it("throws an instance of Error for invalid JSON, not an arbitrary object", () => {
    withEnv(ENV, "{bad}", () => {
      expect(() => buildRouteRules(ENV)).toThrow(Error);
    });
  });

  it("throws an instance of Error for non-array JSON", () => {
    withEnv(ENV, "99", () => {
      expect(() => buildRouteRules(ENV)).toThrow(Error);
    });
  });
});

// ---------------------------------------------------------------------------
// getSampleRate
// ---------------------------------------------------------------------------

describe("getSampleRate", () => {
  const rules: RouteRule[] = [
    { pattern: "/health", rate: 0 },
    { pattern: "/api/v1", rate: 0.1 },
    { pattern: "/api", rate: 0.5 },
  ];

  // ── Success / normal paths ─────────────────────────────────────────────────

  it("returns the defaultRate when rules array is empty", () => {
    expect(getSampleRate("/anything", [], 0.8)).toBe(0.8);
  });

  it("returns the defaultRate (1) when no rules are provided and default is omitted", () => {
    expect(getSampleRate("/anything", [])).toBe(1);
  });

  it("returns the rate of the first matching rule (first-match wins)", () => {
    // "/api/v1" matches both the second and third rules; the second must win.
    expect(getSampleRate("/api/v1/users", rules, 1)).toBe(0.1);
  });

  it("returns the rate for an exact prefix match", () => {
    expect(getSampleRate("/health", rules, 1)).toBe(0);
  });

  it("returns the defaultRate when no rule pattern matches", () => {
    expect(getSampleRate("/unknown/path", rules, 0.25)).toBe(0.25);
  });

  it("matches when the pattern appears anywhere in the URL (substring match)", () => {
    // "/api" appears inside "/deep/nested/api/endpoint"
    expect(getSampleRate("/deep/nested/api/endpoint", rules, 1)).toBe(0.5);
  });

  it("evaluates an empty rules array and falls back to default", () => {
    expect(getSampleRate("/api/v1", [], 0.7)).toBe(0.7);
  });

  // ── Boundary rates ─────────────────────────────────────────────────────────

  it("accepts defaultRate of exactly 0", () => {
    expect(getSampleRate("/x", [], 0)).toBe(0);
  });

  it("accepts defaultRate of exactly 1", () => {
    expect(getSampleRate("/x", [], 1)).toBe(1);
  });

  it("returns 0 for a rule with rate 0", () => {
    expect(getSampleRate("/health", rules, 1)).toBe(0);
  });

  // ── Failure paths ──────────────────────────────────────────────────────────

  it("throws when defaultRate is negative", () => {
    expect(() => getSampleRate("/x", [], -0.1)).toThrowError(
      /Default sample rate must be between 0 and 1/,
    );
  });

  it("throws when defaultRate is greater than 1", () => {
    expect(() => getSampleRate("/x", [], 1.1)).toThrowError(
      /Default sample rate must be between 0 and 1/,
    );
  });

  it("throws an instance of Error for out-of-range defaultRate", () => {
    expect(() => getSampleRate("/x", [], 2)).toThrow(Error);
  });

  it("includes the bad value in the error message for defaultRate", () => {
    expect(() => getSampleRate("/x", [], 5)).toThrowError(/got: 5/);
  });
});

// ---------------------------------------------------------------------------
// createSampler (integration of buildRouteRules + getSampleRate)
// ---------------------------------------------------------------------------

describe("createSampler", () => {
  const RULES_ENV = "TRACE_ROUTE_RULES";
  const RATE_ENV = "TRACE_SAMPLE_RATE";

  beforeEach(() => {
    delete process.env[RULES_ENV];
    delete process.env[RATE_ENV];
  });

  afterEach(() => {
    delete process.env[RULES_ENV];
    delete process.env[RATE_ENV];
  });

  it("returns a function", () => {
    expect(typeof createSampler()).toBe("function");
  });

  it("defaults to rate 1 when no env vars are set", () => {
    const sample = createSampler();
    expect(sample("/any/route")).toBe(1);
  });

  it("respects TRACE_SAMPLE_RATE env var for default rate", () => {
    process.env[RATE_ENV] = "0.2";
    const sample = createSampler();
    expect(sample("/unmatched")).toBe(0.2);
  });

  it("applies route rules from TRACE_ROUTE_RULES env var", () => {
    const rules: RouteRule[] = [{ pattern: "/health", rate: 0 }];
    process.env[RULES_ENV] = JSON.stringify(rules);
    const sample = createSampler();
    expect(sample("/health")).toBe(0);
    expect(sample("/other")).toBe(1); // default
  });

  it("throws at construction time when TRACE_ROUTE_RULES is invalid JSON", () => {
    process.env[RULES_ENV] = "INVALID";
    expect(() => createSampler()).toThrowError(/must be valid JSON/);
  });

  it("throws at construction time when TRACE_ROUTE_RULES is a JSON object", () => {
    process.env[RULES_ENV] = '{"pattern":"/x","rate":0}';
    expect(() => createSampler()).toThrowError(/must be a JSON array/);
  });

  it("uses custom env var names when provided", () => {
    const customRules: RouteRule[] = [{ pattern: "/metrics", rate: 0.05 }];
    process.env["MY_RULES"] = JSON.stringify(customRules);
    process.env["MY_RATE"] = "0.9";

    try {
      const sample = createSampler("MY_RULES", "MY_RATE");
      expect(sample("/metrics")).toBe(0.05);
      expect(sample("/other")).toBe(0.9);
    } finally {
      delete process.env["MY_RULES"];
      delete process.env["MY_RATE"];
    }
  });
});
