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
 * Vault dynamic-secret lease renewal metrics.
 *
 * See `VaultAdapter` in `src/utils/secret-loader.ts`: dynamic Vault secrets
 * carry a time-bounded lease that must be renewed before it expires, or the
 * secret silently stops working. `outcome` is one of "success" (lease
 * extended), "denied" (Vault refused renewal; a full secret reload was
 * attempted as fallback), or "error" (the renewal request itself failed,
 * e.g. Vault unreachable).
 */
export const vaultLeaseRenewalTotal = new Counter({
  name: "vault_lease_renewal_total",
  help: "Total number of Vault dynamic-secret lease renewal attempts, by outcome",
  labelNames: ["outcome"] as const,
  registers: [metricsRegistry],
});

export const vaultLeaseRenewalDurationSeconds = new Histogram({
  name: "vault_lease_renewal_duration_seconds",
  help: "Duration of a Vault lease renewal HTTP call in seconds",
  buckets: [0.05, 0.1, 0.25, 0.5, 1, 2.5, 5],
  registers: [metricsRegistry],
});

export const vaultLeaseSecondsRemaining = new Gauge({
  name: "vault_lease_seconds_remaining",
  help: "Seconds remaining on the current Vault dynamic-secret lease as of the last renewal or load",
  registers: [metricsRegistry],
});
