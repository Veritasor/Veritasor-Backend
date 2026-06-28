import { Registry, Histogram, Counter, Gauge } from "prom-client";

export const metricsRegistry = new Registry();

export const httpRequestDuration = new Histogram({
  name: "http_request_duration_seconds",
  help: "HTTP request duration in seconds",
  labelNames: ["method", "route", "status_code"] as const,
  buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5],
  registers: [metricsRegistry],
});

export const rateLimitRejections = new Counter({
  name: "http_rate_limit_rejections_total",
  help: "Total number of requests rejected by the rate limiter (HTTP 429)",
  labelNames: ["bucket"] as const,
  registers: [metricsRegistry],
});

export const sorobanRetryTotal = new Counter({
  name: "soroban_retry_total",
  help: "Total number of Soroban RPC retry attempts",
  labelNames: ["operation"] as const,
  registers: [metricsRegistry],
});

export const sorobanRetryBudgetExhaustedTotal = new Counter({
  name: "soroban_retry_budget_exhausted_total",
  help: "Total number of Soroban retry attempts refused because the retry budget was exhausted",
  registers: [metricsRegistry],
});

export const wsConnections = new Gauge({
  name: "ws_attestation_connections",
  help: "Number of active WebSocket connections on /api/v1/ws/attestations",
  registers: [metricsRegistry],
});

export const wsMessagesTotal = new Counter({
  name: "ws_attestation_messages_total",
  help: "Total attestation events broadcast over WebSocket",
  labelNames: ["type"] as const,
  registers: [metricsRegistry],
});
