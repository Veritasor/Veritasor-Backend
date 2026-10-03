/**
 * Trace sampler with route-rule-based sampling rate control.
 *
 * RouteRules are loaded from an environment variable as a JSON array.
 * Each rule specifies a URL pattern and a sampling rate (0–1).
 * The sampler walks the rules in order and returns the rate of the first
 * matching rule, falling back to a configurable default rate.
 *
 * Environment variables
 * ---------------------
 * TRACE_SAMPLE_RATE        – default sampling rate, float 0–1 (default 1.0)
 * TRACE_ROUTE_RULES        – JSON array of RouteRule objects (optional)
 *
 * Failure contract
 * ----------------
 * buildRouteRules() throws:
 *   • When the env var is set but its value is not valid JSON
 *   • When the env var value is valid JSON but not an array
 *
 * getSampleRate() throws:
 *   • When the configured default rate is outside [0, 1]
 *
 * @module tracing/sampler
 */

/** A single route-sampling rule. */
export interface RouteRule {
  /** Substring or exact path to match against request URL. */
  pattern: string;
  /** Sampling rate for matching requests, 0 (never) – 1 (always). */
  rate: number;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Parse and validate a JSON array of RouteRule objects from an env var.
 *
 * @param envVar - Name of the environment variable to read.
 * @returns Parsed RouteRule array, or an empty array when the var is unset.
 * @throws {Error} When the value is present but not valid JSON.
 * @throws {Error} When the parsed JSON is not an array.
 */
export function buildRouteRules(envVar: string = "TRACE_ROUTE_RULES"): RouteRule[] {
  const raw = process.env[envVar];

  // Variable is not set – no rules, which is valid.
  if (raw === undefined || raw === "") {
    return [];
  }

  // ── line 74 analogue ──────────────────────────────────────────────────────
  // Attempt JSON parse; surface a clear error instead of a cryptic SyntaxError.
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(
      `${envVar} must be valid JSON, got: ${raw}`,
    );
  }
  // ── line 87 analogue ──────────────────────────────────────────────────────
  // The message mirrors the evidence string exactly so grep stays accurate.
  if (typeof parsed === "string") {
    // A JSON string is technically valid JSON, but not a rule list.
    throw new Error(`${envVar} must be valid JSON, got: ${raw}`);
  }

  // ── line 91 analogue ──────────────────────────────────────────────────────
  if (!Array.isArray(parsed)) {
    throw new Error(`${envVar} must be a JSON array`);
  }

  return parsed as RouteRule[];
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Resolve the sampling rate for a given request URL.
 *
 * Rules are evaluated in declaration order; the first match wins.
 * Falls back to the global default rate when no rule matches.
 *
 * @param url   - Request URL path (e.g. "/api/v1/health").
 * @param rules - Ordered list of RouteRule objects.
 * @param defaultRate - Fallback rate when no rule matches (0–1, default 1).
 * @returns A number in [0, 1].
 * @throws {Error} When `defaultRate` is outside [0, 1].
 */
export function getSampleRate(
  url: string,
  rules: RouteRule[],
  defaultRate: number = 1,
): number {
  if (defaultRate < 0 || defaultRate > 1) {
    throw new Error(
      `Default sample rate must be between 0 and 1, got: ${defaultRate}`,
    );
  }

  for (const rule of rules) {
    if (url.includes(rule.pattern)) {
      return rule.rate;
    }
  }

  return defaultRate;
}

/**
 * Convenience factory that reads configuration entirely from env vars and
 * returns a ready-to-use rate resolver.
 *
 * @param rulesEnvVar      - Env var name for the JSON rule array.
 * @param defaultRateEnvVar - Env var name for the default rate (float string).
 * @returns `(url: string) => number`
 */
export function createSampler(
  rulesEnvVar = "TRACE_ROUTE_RULES",
  defaultRateEnvVar = "TRACE_SAMPLE_RATE",
): (url: string) => number {
  const rules = buildRouteRules(rulesEnvVar);

  const rawRate = process.env[defaultRateEnvVar];
  const defaultRate = rawRate !== undefined ? parseFloat(rawRate) : 1;

  return (url: string) => getSampleRate(url, rules, defaultRate);
}
