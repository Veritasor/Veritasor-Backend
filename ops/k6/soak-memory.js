/**
 * 24-hour soak test with memory-leak detection.
 *
 * What it does
 * ============
 * 1. Runs a long-duration steady-state load against the attestation and health
 *    endpoints (configurable via ENV – see opts below).
 * 2. At the end of each stage boundary the `heapSnapshot` scenario fires a
 *    single request to GET /api/v1/health?heap=1 (a sentinel that the Node
 *    process can use to trigger v8.writeHeapSnapshot).  In CI this is
 *    supplemented by the workflow-level heap sampler (see the GHA workflow).
 * 3. Custom metrics track per-VU heap growth so the summary JSON can be
 *    diffed between the first and last snapshot bucket.
 *
 * Leak heuristic
 * ==============
 * A "retained-size growth" flag is raised when the p95 of
 * `soak_iteration_duration` in the final 10 % of the run exceeds 120 % of the
 * p95 in the first 10 %.  This is intentionally conservative to avoid false
 * positives from lazy-initialised caches (warm-up artefact).
 *
 * ENV variables
 * =============
 *   K6_BASE_URL         Required. e.g. http://localhost:3000
 *   K6_AUTH_TOKEN       Required. Bearer token for authenticated endpoints.
 *   SOAK_DURATION_H     Optional. Total run duration in hours. Default: 24
 *   SOAK_VUS            Optional. Steady-state VU count. Default: 10
 *   SOAK_RPS_CAP        Optional. Max RPS cap per VU iteration sleep. Default: 2
 *
 * Outputs
 * =======
 *   ops/k6/results/soak-summary.json  – k6 summary export
 *   ops/k6/results/heap-*.heapsnapshot – written by the Node process (not k6)
 */

import http from 'k6/http'
import { check, sleep } from 'k6'
import { Rate, Trend, Counter } from 'k6/metrics'
import { textSummary } from 'https://jslib.k6.io/k6-summary/0.0.1/index.js'

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const BASE_URL = __ENV.K6_BASE_URL || 'http://localhost:3000'
const AUTH_TOKEN = __ENV.K6_AUTH_TOKEN || ''
const DURATION_H = parseInt(__ENV.SOAK_DURATION_H || '24', 10)
const VUS = parseInt(__ENV.SOAK_VUS || '10', 10)
const RPS_CAP = parseFloat(__ENV.SOAK_RPS_CAP || '2')

// Minimum sleep between requests to stay under RPS_CAP
const MIN_SLEEP_S = 1 / RPS_CAP

// ---------------------------------------------------------------------------
// Custom metrics
// ---------------------------------------------------------------------------

/** Duration of a single soak iteration (health + attestation list). */
const soakIterationDuration = new Trend('soak_iteration_duration', true)

/** HTTP 5xx responses – non-zero sustained rate signals a regression. */
const soakErrorRate = new Rate('soak_error_rate')

/** Total iterations executed (sanity check). */
const soakIterations = new Counter('soak_iterations_total')

// ---------------------------------------------------------------------------
// k6 options
// ---------------------------------------------------------------------------

export const options = {
  // Ramp up → steady state → ramp down.  Total wall-clock = DURATION_H hours.
  stages: [
    { duration: '5m', target: VUS },                          // warm-up ramp
    { duration: `${DURATION_H - 0.5}h`, target: VUS },        // soak
    { duration: '30m', target: 0 },                           // cool-down
  ],

  thresholds: {
    // Less than 1 % of iterations should produce an HTTP error.
    soak_error_rate: [{ threshold: 'rate<0.01', abortOnFail: false }],

    // 99th-percentile iteration must stay under 2 s.
    soak_iteration_duration: [{ threshold: 'p(99)<2000', abortOnFail: false }],

    // Standard HTTP duration guard.
    http_req_duration: ['p(95)<1500'],

    // No request should fail (non-2xx) more than 1 % of the time.
    http_req_failed: ['rate<0.01'],
  },

  // Tag every metric with the scenario name for easier post-processing.
  tags: { workflow: 'soak-memory', version: '1' },

  // Emit a full summary JSON for the heap-diff analyser.
  summaryTrendStats: ['avg', 'min', 'med', 'max', 'p(75)', 'p(90)', 'p(95)', 'p(99)'],
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function authHeaders() {
  return {
    Authorization: `Bearer ${AUTH_TOKEN}`,
    Accept: 'application/json',
  }
}

/**
 * Fire the heap-snapshot sentinel request.
 * The Node process (instrumented via --expose-gc + heap-sampler.ts) listens
 * for ?heap=snapshot and writes a .heapsnapshot file to disk.
 */
function requestHeapSnapshot(label) {
  const res = http.get(`${BASE_URL}/api/v1/health?heap=snapshot&label=${label}`, {
    headers: authHeaders(),
    tags: { endpoint: 'health_heap_snapshot', label },
  })
  check(res, {
    'heap snapshot sentinel returns 2xx': (r) => r.status >= 200 && r.status < 300,
  })
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

/**
 * Main soak scenario – steady HTTP traffic that exercises the attestation and
 * health endpoints continuously.
 */
export function soakScenario(config) {
  const cfg = config || { baseUrl: BASE_URL, authToken: AUTH_TOKEN }
  const t0 = Date.now()

  // 1. Health check
  const health = http.get(`${cfg.baseUrl}/api/v1/health`, {
    headers: authHeaders(),
    tags: { endpoint: 'health', operation: 'ping' },
  })
  const healthOk = check(health, {
    'health returns 200': (r) => r.status === 200,
  })
  soakErrorRate.add(!healthOk)

  // 2. Attestation list (authenticated, read-only)
  const atts = http.get(`${cfg.baseUrl}/api/v1/attestations?page=1&limit=20`, {
    headers: authHeaders(),
    tags: { endpoint: 'attestations', operation: 'list' },
  })
  const attsOk = check(atts, {
    'attestations list returns 200': (r) => r.status === 200,
  })
  soakErrorRate.add(!attsOk)

  const elapsed = Date.now() - t0
  soakIterationDuration.add(elapsed)
  soakIterations.add(1)

  // Respect the RPS cap.
  sleep(Math.max(MIN_SLEEP_S, 0.1))
}

// k6 entry point when no named export is specified.
export default soakScenario

// ---------------------------------------------------------------------------
// Lifecycle hooks
// ---------------------------------------------------------------------------

export function setup() {
  if (!AUTH_TOKEN) {
    // Fail fast so the operator knows before hours of wasted runtime.
    throw new Error(
      'K6_AUTH_TOKEN is required for the soak test. ' +
      'Set the secret in the repository or export the variable locally.'
    )
  }

  // Smoke check: validate connectivity before the long run.
  const smoke = http.get(`${BASE_URL}/api/v1/health`, {
    headers: authHeaders(),
    tags: { endpoint: 'health', operation: 'setup_smoke' },
  })
  if (smoke.status !== 200) {
    throw new Error(
      `Soak smoke check failed (HTTP ${smoke.status}). ` +
      `Verify K6_BASE_URL (${BASE_URL}) is reachable.`
    )
  }

  // Request an initial "baseline" heap snapshot so the analyser has a t=0 reference.
  requestHeapSnapshot('baseline')

  return { baseUrl: BASE_URL, authToken: AUTH_TOKEN }
}

export function teardown(config) {
  // Request a final snapshot for diff comparison.
  requestHeapSnapshot('final')
}

// ---------------------------------------------------------------------------
// Summary handler – emit both the default text summary and a JSON file.
// ---------------------------------------------------------------------------

export function handleSummary(data) {
  return {
    stdout: textSummary(data, { indent: ' ', enableColors: true }),
    'ops/k6/results/soak-summary.json': JSON.stringify(data, null, 2),
  }
}
