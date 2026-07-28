import { Registry, Histogram, Counter, Gauge } from "prom-client";
import { getActiveTraceExemplarLabels } from "./tracing.js";

export const metricsRegistry = new Registry();
metricsRegistry.setContentType(Registry.OPENMETRICS_CONTENT_TYPE);

export const httpRequestDuration = new Histogram({
  name: "http_request_duration_seconds",
  help: "HTTP request duration in seconds",
  labelNames: ["method", "route", "status_code"] as const,
  buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5],
  enableExemplars: true,
  registers: [metricsRegistry],
});

export function observeHttpRequestDuration(
  labels: Record<string, string>,
  durationSec: number,
): void {
  const exemplarLabels = getActiveTraceExemplarLabels();
  if (Object.keys(exemplarLabels).length === 0) {
    httpRequestDuration.observe({ labels, value: durationSec });
    return;
  }

  httpRequestDuration.observe({
    labels,
    value: durationSec,
    exemplarLabels,
  });
}

export const rateLimitRejections = new Counter({
  name: "http_rate_limit_rejections_total",
  help: "Total number of requests rejected by the rate limiter (HTTP 429)",
  labelNames: ["bucket"] as const,
  registers: [metricsRegistry],
});

export const redisClusterRedirectionsTotal = new Counter({
  name: "redis_cluster_redirections_total",
  help: "Total number of Redis Cluster MOVED/ASK redirections handled in rateLimiter",
  labelNames: ["type", "store"] as const,
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

export const submissionReplayProgress = new Gauge({
  name: "submission_replay_progress",
  help: "Progress of failed Soroban submission replay (0 = not started, 1 = completed)",
  labelNames: ["phase"] as const,
  registers: [metricsRegistry],
});

/**
 * Storage pressure for the idempotency key store.
 *
 * - `idempotency_keys_count` (gauge, labels: backend): current number of
 *   tracked keys in the store. `backend` is `memory` or `redis` so SREs
 *   can split pressure per backend.
 *
 * - `idempotency_evictions_total` (counter, labels: backend, reason):
 *   keys removed from the store. `reason` is `expired` (TTL sweep),
 *   `overflow` (capacity pruning in `set`) or `manual` (explicit delete).
 *
 * The gauge and counter together let SREs plot retention vs churn and
 * decide whether the sweeper interval or the TTL is mis-tuned.
 */
export const idempotencyKeysCount = new Gauge({
  name: "idempotency_keys_count",
  help: "Current number of entries in the idempotency key store",
  labelNames: ["backend"] as const,
  registers: [metricsRegistry],
});

export const idempotencyEvictionsTotal = new Counter({
  name: "idempotency_evictions_total",
  help: "Total number of idempotency keys evicted from the store",
  labelNames: ["backend", "reason"] as const,
  registers: [metricsRegistry],
});

export const idempotencySweepRunsTotal = new Counter({
  name: "idempotency_sweep_runs_total",
  help: "Total number of idempotency sweeper cycles executed",
  labelNames: ["backend", "outcome"] as const,
  registers: [metricsRegistry],
});

/**
 * PgBouncer queue depth and latency metrics.
 *
 * Scraped from `SHOW STATS` on the PgBouncer admin database at second granularity.
 * Key metrics exposed:
 *
 * - `pgbouncer_waiting_clients` (gauge, labels: database): clients waiting for a server connection.
 *   Spikes here precede tail-latency incidents.
 * - `pgbouncer_avg_wait_time_seconds` (gauge, labels: database): average wait time in seconds.
 *   Spikes indicate pool saturation.
 * - `pgbouncer_active_clients` (gauge, labels: database): currently active client connections.
 * - `pgbouncer_idle_clients` (gauge, labels: database): idle client connections.
 * - `pgbouncer_server_connections` (gauge, labels: database): active server connections.
 * - `pgbouncer_avg_query_time_seconds` (gauge, labels: database): average query execution time.
 * - `pgbouncer_total_requests_total` (counter, labels: database): total client requests.
 * - `pgbouncer_total_query_time_seconds_total` (counter, labels: database): cumulative query time.
 */
export const pgbouncerWaitingClients = new Gauge({
  name: "pgbouncer_waiting_clients",
  help: "Number of clients waiting for a server connection in PgBouncer pool",
  labelNames: ["database"] as const,
  registers: [metricsRegistry],
});

export const pgbouncerAvgWaitTimeSeconds = new Gauge({
  name: "pgbouncer_avg_wait_time_seconds",
  help: "Average wait time for a server connection in seconds",
  labelNames: ["database"] as const,
  registers: [metricsRegistry],
});

export const pgbouncerActiveClients = new Gauge({
  name: "pgbouncer_active_clients",
  help: "Number of active client connections in PgBouncer",
  labelNames: ["database"] as const,
  registers: [metricsRegistry],
});

export const pgbouncerIdleClients = new Gauge({
  name: "pgbouncer_idle_clients",
  help: "Number of idle client connections in PgBouncer",
  labelNames: ["database"] as const,
  registers: [metricsRegistry],
});

export const pgbouncerServerConnections = new Gauge({
  name: "pgbouncer_server_connections",
  help: "Number of active server connections in PgBouncer",
  labelNames: ["database"] as const,
  registers: [metricsRegistry],
});

export const pgbouncerAvgQueryTimeSeconds = new Gauge({
  name: "pgbouncer_avg_query_time_seconds",
  help: "Average query execution time in seconds",
  labelNames: ["database"] as const,
  registers: [metricsRegistry],
});

export const pgbouncerTotalRequestsTotal = new Counter({
  name: "pgbouncer_total_requests_total",
  help: "Total number of client requests processed by PgBouncer",
  labelNames: ["database"] as const,
  registers: [metricsRegistry],
});

export const pgbouncerTotalQueryTimeSecondsTotal = new Counter({
  name: "pgbouncer_total_query_time_seconds_total",
  help: "Cumulative query execution time in seconds",
  labelNames: ["database"] as const,
  registers: [metricsRegistry],
});

/**
 * Adaptive batch-size tuning metrics for Soroban submissions.
 *
 * - `soroban_adaptive_batch_size` (gauge): current batch size after tuning.
 * - `soroban_fee_ewma` (gauge): EWMA-smoothed Soroban inclusion fee (p50 stroops).
 * - `soroban_current_fee` (gauge): latest raw p50 fee (stroops).
 * - `soroban_fee_volatility` (gauge): fee coefficient of variation (p90-p10)/p50.
 * - `soroban_fee_spike_protection_activations_total` (counter): spike-protection events.
 */
export const sorobanAdaptiveBatchSize = new Gauge({
  name: "soroban_adaptive_batch_size",
  help: "Current adaptive batch size for Soroban submissions, tuned by fee volatility",
  registers: [metricsRegistry],
});

export const sorobanFeeEwma = new Gauge({
  name: "soroban_fee_ewma",
  help: "EWMA-smoothed Soroban network inclusion fee in stroops",
  registers: [metricsRegistry],
});

export const sorobanCurrentFee = new Gauge({
  name: "soroban_current_fee",
  help: "Latest observed Soroban inclusion fee p50 in stroops",
  registers: [metricsRegistry],
});

export const sorobanFeeVolatility = new Gauge({
  name: "soroban_fee_volatility",
  help: "Soroban fee coefficient of variation (p90-p10)/p50",
  registers: [metricsRegistry],
});

export const sorobanFeeSpikeProtectionsTotal = new Counter({
  name: "soroban_fee_spike_protection_activations_total",
  help: "Total number of Soroban fee spike protection activations that reduced batch size to minimum",
  registers: [metricsRegistry],
});

export const webhookRetryAttempts = new Histogram({
  name: "webhook_retry_attempts",
  help: "Number of retry attempts made when processing a webhook event",
  labelNames: ["provider"] as const,
  buckets: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
  registers: [metricsRegistry],
});

export const webhookRetryExhaustedTotal = new Counter({
  name: "webhook_retry_exhausted_total",
  help: "Total number of webhook events that exhausted all retry attempts and were sent to DLQ",
  labelNames: ["provider"] as const,
  registers: [metricsRegistry],
});

export const redisCircuitBreakerState = new Gauge({
  name: "redis_circuit_breaker_state",
  help: "Redis circuit breaker state (0=CLOSED, 1=OPEN, 2=HALF_OPEN)",
  registers: [metricsRegistry],
});

export const redisCircuitBreakerFailuresTotal = new Counter({
  name: "redis_circuit_breaker_failures_total",
  help: "Total number of Redis circuit breaker failures recorded",
  registers: [metricsRegistry],
});
