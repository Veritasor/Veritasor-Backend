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

export const mtlsHandshakeFailuresTotal = new Counter({
  name: "mtls_handshake_failures_total",
  help: "Total number of mTLS handshake failures",
  labelNames: ["reason"] as const,
  registers: [metricsRegistry],
});

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
 * PgBouncer admin-console metrics. Pool series use the bounded
 * (database,user) key returned by SHOW POOLS; stats use database only.
 */
export const pgbouncerWaitingClients = new Gauge({
  name: "pgbouncer_waiting_clients",
  help: "Clients waiting for a server connection in a PgBouncer pool",
  labelNames: ["database", "user"] as const,
  registers: [metricsRegistry],
});

export const pgbouncerMaxWaitSeconds = new Gauge({
  name: "pgbouncer_max_wait_seconds",
  help: "Age in seconds of the oldest waiting client in a PgBouncer pool",
  labelNames: ["database", "user"] as const,
  registers: [metricsRegistry],
});

export const pgbouncerActiveClients = new Gauge({
  name: "pgbouncer_active_clients",
  help: "Active client connections in a PgBouncer pool",
  labelNames: ["database", "user"] as const,
  registers: [metricsRegistry],
});

export const pgbouncerServerConnections = new Gauge({
  name: "pgbouncer_server_connections",
  help: "Server connections in a PgBouncer pool by state",
  labelNames: ["database", "user", "state"] as const,
  registers: [metricsRegistry],
});

export const pgbouncerAvgQueryTimeSeconds = new Gauge({
  name: "pgbouncer_avg_query_time_seconds",
  help: "Average PgBouncer query execution time in seconds",
  labelNames: ["database"] as const,
  registers: [metricsRegistry],
});

export const pgbouncerTotalRequests = new Gauge({
  name: "pgbouncer_total_requests",
  help: "Current PgBouncer cumulative request count (may reset on restart or RELOAD)",
  labelNames: ["database"] as const,
  registers: [metricsRegistry],
});

export const pgbouncerTotalQueryTimeSeconds = new Gauge({
  name: "pgbouncer_total_query_time_seconds",
  help: "Current PgBouncer cumulative query time in seconds (may reset on restart or RELOAD)",
  labelNames: ["database"] as const,
  registers: [metricsRegistry],
});

export const pgbouncerScraperEnabled = new Gauge({
  name: "pgbouncer_scraper_enabled",
  help: "Whether the PgBouncer admin scraper is configured and running (1 or 0)",
  registers: [metricsRegistry],
});

export const pgbouncerScrapeSuccess = new Gauge({
  name: "pgbouncer_scrape_success",
  help: "Whether the most recent PgBouncer admin scrape succeeded (1 or 0)",
  registers: [metricsRegistry],
});

export const pgbouncerScrapeDurationSeconds = new Gauge({
  name: "pgbouncer_scrape_duration_seconds",
  help: "Duration of the most recent PgBouncer admin scrape in seconds",
  registers: [metricsRegistry],
});

export const pgbouncerLastSuccessfulScrapeTimestampSeconds = new Gauge({
  name: "pgbouncer_last_successful_scrape_timestamp_seconds",
  help: "Unix timestamp of the most recent successful PgBouncer admin scrape",
  registers: [metricsRegistry],
});

export const pgbouncerScrapeErrorsTotal = new Counter({
  name: "pgbouncer_scrape_errors_total",
  help: "Total failed PgBouncer admin scrapes",
  labelNames: ["reason"] as const,
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

/**
 * Deficit Round-Robin (DRR) fair-batch-scheduler metrics.
 *
 * - `soroban_drr_queue_wait_ms` (histogram, labels: tenant): milliseconds an
 *   item spent waiting in the per-tenant queue before being dequeued into a
 *   batch. Useful for detecting starvation (tail latency per tenant).
 *
 * - `soroban_drr_queue_depth` (gauge, labels: tenant): current number of
 *   items in the tenant's queue. Spikes indicate a noisy tenant is
 *   enqueueing faster than the scheduler can drain.
 *
 * - `soroban_drr_scheduler_rounds_total` (counter): total DRR rounds
 *   executed. One round visits every non-empty tenant once.
 *
 * - `soroban_drr_dequeues_total` (counter, labels: tenant): total items
 *   removed from a tenant's queue and placed into a batch.
 */
export const sorobanDrrQueueWaitMs = new Histogram({
  name: 'soroban_drr_queue_wait_ms',
  help: 'Milliseconds an attestation item spent waiting in the DRR batch queue per tenant',
  labelNames: ['tenant'] as const,
  buckets: [5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000],
  registers: [metricsRegistry],
});

export const sorobanDrrQueueDepth = new Gauge({
  name: 'soroban_drr_queue_depth',
  help: 'Current number of attestation items waiting in the DRR batch queue per tenant',
  labelNames: ['tenant'] as const,
  registers: [metricsRegistry],
});

export const sorobanDrrSchedulerRoundsTotal = new Counter({
  name: 'soroban_drr_scheduler_rounds_total',
  help: 'Total number of Deficit Round-Robin scheduler rounds executed',
  registers: [metricsRegistry],
});

export const sorobanDrrDequeuesTotal = new Counter({
  name: 'soroban_drr_dequeues_total',
  help: 'Total number of items dequeued from tenant queues by the DRR scheduler',
  labelNames: ['tenant'] as const,
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

/**
 * Webhook secret rotation rollout status.
 *
 * - `webhook_secret_rotation_status` (gauge, labels: subscription_id, business_id, status):
 *   1 = subscription has adopted the latest secret version, 0 = lagging behind.
 *
 * Operators can sum or count by `status` to see how many subscriptions are
 * current vs. lagging, and drill into individual lagging subscriptions by
 * `subscription_id` / `business_id`.
 *
 * Implementation in `src/services/webhooks/secretRotation.ts` — see that
 * module for the update loop and per-subscription resolution.
 */
export const webhookSecretRotationStatus = new Gauge({
  name: "webhook_secret_rotation_status",
  help:
    "Rollout status of webhook secret rotation per subscription " +
    "(1 = current / 0 = lagging)",
  labelNames: ["subscription_id", "business_id", "status"] as const,
  registers: [metricsRegistry],
});
