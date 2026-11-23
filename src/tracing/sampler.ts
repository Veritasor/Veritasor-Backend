/**
 * Per-route OTel sampler.
 *
 * Solves two complementary problems with uniform sampling:
 *  - Hot paths (e.g. /health, /metrics) produce noise at 100 % — decimate them.
 *  - Rare paths (e.g. /admin/*, webhook callbacks) get dropped entirely at low
 *    global rates — oversample them so every incident is visible.
 *
 * Configuration is loaded from three env vars at construction time and can be
 * reloaded at runtime by calling `reload()` (useful for hot config without restart):
 *
 *   OTEL_SAMPLING_DEFAULT_RATE   float 0–1, default 1.0
 *   OTEL_SAMPLING_HOT_ROUTES     JSON array of { route, rate } objects
 *   OTEL_SAMPLING_RARE_ROUTES    JSON array of { route, rate } objects
 *
 * Route matching is by prefix — the most specific prefix wins.  If a span's
 * http.route (or http.target) matches multiple rules the longest prefix takes
 * priority.  When no rule matches the default rate is used.
 *
 * Example env values:
 *   OTEL_SAMPLING_DEFAULT_RATE=0.1
 *   OTEL_SAMPLING_HOT_ROUTES=[{"route":"/health","rate":0.01},{"route":"/metrics","rate":0}]
 *   OTEL_SAMPLING_RARE_ROUTES=[{"route":"/api/v1/admin","rate":1},{"route":"/webhooks","rate":1}]
 */

import {
  SamplingDecision,
  type Sampler,
  type SamplingResult,
  type Attributes,
  type Context,
  type SpanKind,
  type Link,
} from "@opentelemetry/api";
import { Counter } from "prom-client";
import { metricsRegistry } from "../metrics.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface RouteRule {
  /** URL prefix to match (e.g. "/api/v1/admin"). */
  route: string;
  /** Sampling rate 0–1 (0 = never sample, 1 = always sample). */
  rate: number;
}

export interface SamplerConfig {
  defaultRate: number;
  hotRoutes: RouteRule[];
  rareRoutes: RouteRule[];
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

export const tracingSampledTotal = new Counter({
  name: "tracing_sampled_total",
  help: "Total spans processed by the route-aware sampler",
  labelNames: ["decision", "rule_type"] as const,
  registers: [metricsRegistry],
});

// ---------------------------------------------------------------------------
// Config parsing
// ---------------------------------------------------------------------------

function parseRate(raw: string | undefined, defaultValue: number): number {
  if (raw === undefined || raw.trim() === "") return defaultValue;
  const n = Number(raw.trim());
  if (!Number.isFinite(n) || n < 0 || n > 1) {
    throw new Error(
      `OTEL_SAMPLING_DEFAULT_RATE must be a number between 0 and 1, got: ${raw}`,
    );
  }
  return n;
}

function parseRouteRules(raw: string | undefined, envVar: string): RouteRule[] {
  if (!raw || raw.trim() === "") return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(`${envVar} must be valid JSON, got: ${raw}`);
  }

  if (!Array.isArray(parsed)) {
    throw new Error(`${envVar} must be a JSON array`);
  }

  return parsed.map((item, i) => {
    if (
      typeof item !== "object" ||
      item === null ||
      typeof (item as RouteRule).route !== "string" ||
      typeof (item as RouteRule).rate !== "number"
    ) {
      throw new Error(
        `${envVar}[${i}] must have string "route" and number "rate"`,
      );
    }
    const { route, rate } = item as RouteRule;
    if (!Number.isFinite(rate) || rate < 0 || rate > 1) {
      throw new Error(
        `${envVar}[${i}].rate must be between 0 and 1, got: ${rate}`,
      );
    }
    return { route, rate };
  });
}

export function loadSamplerConfig(): SamplerConfig {
  return {
    defaultRate: parseRate(process.env.OTEL_SAMPLING_DEFAULT_RATE, 1.0),
    hotRoutes: parseRouteRules(
      process.env.OTEL_SAMPLING_HOT_ROUTES,
      "OTEL_SAMPLING_HOT_ROUTES",
    ),
    rareRoutes: parseRouteRules(
      process.env.OTEL_SAMPLING_RARE_ROUTES,
      "OTEL_SAMPLING_RARE_ROUTES",
    ),
  };
}

// ---------------------------------------------------------------------------
// Route matching
// ---------------------------------------------------------------------------

/**
 * Find the most specific (longest) prefix rule that matches `route`.
 * Returns the matched rule or undefined.
 */
function matchRule(
  route: string,
  rules: RouteRule[],
): RouteRule | undefined {
  let best: RouteRule | undefined;
  for (const rule of rules) {
    if (route.startsWith(rule.route)) {
      if (!best || rule.route.length > best.route.length) {
        best = rule;
      }
    }
  }
  return best;
}

// ---------------------------------------------------------------------------
// Sampler
// ---------------------------------------------------------------------------

export class RouteAwareSampler implements Sampler {
  private config: SamplerConfig;

  constructor(config?: SamplerConfig) {
    this.config = config ?? loadSamplerConfig();
  }

  /** Hot-reload config from env (or a new config object). */
  reload(config?: SamplerConfig): void {
    this.config = config ?? loadSamplerConfig();
  }

  shouldSample(
    _context: Context,
    _traceId: string,
    _spanName: string,
    _spanKind: SpanKind,
    attributes: Attributes,
    _links: Link[],
  ): SamplingResult {
    const route =
      (attributes["http.route"] as string | undefined) ??
      (attributes["http.target"] as string | undefined) ??
      "";

    const { rate, ruleType } = this._resolveRate(route);

    const sampled = rate >= 1 || (rate > 0 && Math.random() < rate);
    const decision = sampled
      ? SamplingDecision.RECORD_AND_SAMPLED
      : SamplingDecision.NOT_RECORD;

    tracingSampledTotal.inc({
      decision: sampled ? "sampled" : "dropped",
      rule_type: ruleType,
    });

    return { decision };
  }

  toString(): string {
    return `RouteAwareSampler(default=${this.config.defaultRate})`;
  }

  /** Exposed for testing. */
  _resolveRate(route: string): { rate: number; ruleType: string } {
    // Rare-path rules take priority (they are intentionally oversampled).
    const rareMatch = matchRule(route, this.config.rareRoutes);
    if (rareMatch) {
      return { rate: rareMatch.rate, ruleType: "rare" };
    }

    const hotMatch = matchRule(route, this.config.hotRoutes);
    if (hotMatch) {
      return { rate: hotMatch.rate, ruleType: "hot" };
    }

    return { rate: this.config.defaultRate, ruleType: "default" };
  }
}
