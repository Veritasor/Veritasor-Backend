# Chaos Testing with Toxiproxy

Property-based and scenario-based chaos tests using
[Toxiproxy](https://github.com/Shopify/toxiproxy) to simulate downstream
faults.  These tests validate that the API degrades gracefully when
dependencies (Postgres, Redis) experience turbulence.

---

## Test files

| File | Coverage |
| :--- | :--- |
| `tests/chaos/toxiproxy-client.ts` | Minimal native-fetch HTTP client for Toxiproxy + toxic builder helpers. Replaces the deprecated `toxiproxy-node` package. |
| `tests/chaos/toxiproxy.spec.ts` | Smoke suite — basic proxy reachability, Postgres reset/timeout, Redis PING latency. |
| `tests/chaos/redis-chaos.spec.ts` | Redis scenarios: latency+jitter, timeout, reset_peer, limit_data truncation, bandwidth throttling, TCP slicer fragmentation, circuit-breaker OPEN→HALF→CLOSED transitions, rate-limiter store fallback (Redis → memory), idempotency store no-op fallback, pipeline integrity under load. |
| `tests/chaos/postgres-chaos.spec.ts` | Postgres scenarios: latency+jitter sweeps, timeout near connectionTimeout, reset_peer classification by `isTransientConnectionError`, `withPgBouncerRetry` retry+succeed, retry exhaustion with bounded total latency, `pgBouncerBackoffMs` jitter shape + determinism, limit_data truncated responses, bandwidth throttled large result sets, TCP slicer fragmentation, concurrent-query survival, concurrent + reset_peer with retry, slow-query detection firing, module-level singleton smoke checks. |
| `tests/chaos/docker-compose.yml` | Standalone stack: Postgres 15, Redis 7, Toxiproxy 2.9 with healthchecks and dedicated ports. |

---

## Execution

### Local (Docker Compose)

```bash
# 1. Start the stack
docker compose -f tests/chaos/docker-compose.yml up -d

# 2. Optional — run migrations against the proxied DB if a test needs schema:
#    DATABASE_URL=postgresql://veritasor:testpassword@localhost:5432/veritasor_test \
#    pnpm migrate

# 3. Run all chaos suites
CHAOS_TESTS=true \
  TOXIPROXY_URL=http://localhost:8474 \
  PG_UPSTREAM=localhost:5433 \
  REDIS_UPSTREAM=localhost:6380 \
  CHAOS_DATABASE_URL=postgresql://veritasor:testpassword@localhost:15432/veritasor_test \
  pnpm test tests/chaos/

# 4. Clean up
docker compose -f tests/chaos/docker-compose.yml down -v
```

### Single-suite runs

```bash
# Smoke only
CHAOS_TESTS=true pnpm test tests/chaos/toxiproxy.spec.ts

# Redis chaos only
CHAOS_TESTS=true \
  REDIS_UPSTREAM=localhost:6380 \
  pnpm test tests/chaos/redis-chaos.spec.ts

# Postgres chaos only
CHAOS_TESTS=true \
  PG_UPSTREAM=localhost:5433 \
  CHAOS_DATABASE_URL=postgresql://veritasor:testpassword@localhost:15432/veritasor_test \
  pnpm test tests/chaos/postgres-chaos.spec.ts
```

### In CI

The chaos tests are behind a separate workflow (`chaos-tests.yml`) and a
`CHAOS_TESTS=true` gate so they never run as part of the default fast PR
check.  They must be explicitly triggered:

* **Nightly** — runs against `main` via the scheduled workflow.
* **On-demand** — `workflow_dispatch` on `chaos-tests.yml` with any branch.
* **Label-gated** — adding the `run-chaos-tests` label to a PR triggers the
  workflow on the PR head SHA.

---

## Port layout

| Port | Service | Description |
| :--- | :--- | :--- |
| `8474` | Toxiproxy HTTP API | Create proxies, add toxics, inspect state. |
| `5432` | Postgres (shared proxy) | Used by `toxiproxy.spec.ts`. Upstream → `postgres:5432`. |
| `5433` | Postgres (raw) | Bypasses Toxiproxy — use for setup, migrations, `pg_isready`. |
| `6379` | Redis (shared proxy) | Used by `toxiproxy.spec.ts`. Upstream → `redis:6379`. |
| `6380` | Redis (raw) | Bypasses Toxiproxy — use for diagnostics / `redis-cli`. |
| `8000` | Soroban (shared proxy) | Reserved for future Soroban RPC chaos scenarios. |
| `15432` | Postgres (`postgres_chaos` proxy) | Dedicated to `postgres-chaos.spec.ts` so toxics don't leak. |
| `16379` | Redis (`redis_chaos` proxy) | Dedicated to `redis-chaos.spec.ts` so toxics don't leak. |

---

## Failure scenarios & expected behaviour

| Downstream | Toxic | What we assert |
| :--- | :--- | :--- |
| **Postgres** | `latency` with `jitter` | Query completes, measured wall-clock ≥ latency floor. |
| **Postgres** | `latency` sweep 10→250 ms | Pool stays healthy, no false connection-terminated errors. |
| **Postgres** | `latency` near `connectionTimeoutMillis` | Query resolves to OK or ERR within a strict 15 s outer deadline — no hangs. |
| **Postgres** | `timeout` during `pg_sleep` | Driver throws; message/code matches transient regex. |
| **Postgres** | `reset_peer` (ECONNRESET) | `isTransientConnectionError(err) === true` or message matches transient regex. |
| **Postgres** | synthetic ECONNRESET × 2, then success | `withPgBouncerRetry` retries exactly 2 times and returns the successful result. |
| **Postgres** | synthetic persistent ECONNRESET | Retry budget exhausted after `PGBOUNCER_MAX_RETRIES`; total elapsed bounded by `MAX_DELAY × retries`, error re-thrown unchanged. |
| **Postgres** | `limit_data` (truncated response) | Query either errors cleanly or completes within 10 s — no parser deadlock. |
| **Postgres** | `bandwidth` 50 KB/s | 10k-row SELECT slower than clean baseline, all rows intact. |
| **Postgres** | `slicer` 20 B segments × 2 ms | 500 rows × 2 columns all present, md5 hashes match. |
| **Postgres** | concurrent 20× SELECT + 80/160 ms jitter | All 20 values returned, sorted, no pool exhaustion. |
| **Postgres** | concurrent 20× SELECT + 25 % synthetic ECONNRESET | Retry wrapper absorbs all transient errors, all 20 results intact. |
| **Postgres** | (threshold override) + latency toxic | `slow_query_detected` warn event is emitted with duration ≥ threshold. |
| **Redis** | `latency` with `jitter` | `PING` returns `PONG` within the latency envelope. |
| **Redis** | `latency` + jitter < 1 s | `redisHealthProbe()` returns `"ok"`. |
| **Redis** | wide jitter (20 ±80 ms) | `SET`/`GET` round-trip returns the exact value. |
| **Redis** | `timeout` 10 ms | `redisHealthProbe()` returns `"error:…"` string (never throws). |
| **Redis** | `timeout` 50 ms | Health probe completes faster than its own 1 s deadline. |
| **Redis** | `reset_peer` | Error message/code matches transient regex; test harness does not hang. |
| **Redis** | `reset_peer` × N against `RedisCircuitBreaker` | Breaker trips to `OPEN` after `failureThreshold` failures. |
| **Redis** | `limit_data` (truncated PONG) | Parser/connection surfaces an error within a 2 s race deadline. |
| **Redis** | `bandwidth` 50 KB/s | 200 KB `GET` > 1.5 s slower than baseline, payload length intact. |
| **Redis** | `slicer` 10 B × 5 ms | 20-command pipeline with 20 results all succeed; cleanup pipeline succeeds. |
| **Redis** | timeout → wait reset window → toxic removed | Circuit-breaker transitions `CLOSED → OPEN → HALF_OPEN → CLOSED`; probe call after window returns real `PONG`. |
| **Redis** | breaker OPEN with fallback registered | `execute()` returns the fallback value synchronously (fast — < 50 ms, no network). |
| **Redis** | fixed-window rate limiter + jitter | Two `increment()` calls return counts 1 and 2. |
| **Redis** | sliding-window rate limiter + aggressive jitter | 3 concurrent increments; max observed count == 3. |
| **Redis** | init-time timeout in `getStore()` | `getStore('fixed')` falls back to `MemoryStore`; 2 increments work. |
| **Redis** | circuit breaker OPEN + idempotency `set()` | Call resolves (no throw); circuit-breaker fallback no-op used. |
| **Redis** | latency+jitter + idempotency store | `set()` then `get()` returns identical entry with matching `status` / `requestHash`. |
| **Redis** | pipeline 50× SET+GET with latency+jitter | All 100 results OK; all GETs equal the expected value. |
| **Redis** | primary/readonly clients through proxy | Both handles see the same value for the same key. |

---

## Backoff / retry properties asserted by `postgres-chaos.spec.ts`

* Every `pgBouncerBackoffMs(n)` sample lands in `[0, min(MAX_DELAY, BASE*2^n)]`.
* 5 000-sample mean is in `(0.2 × window, 0.8 × window)` — i.e. the
  distribution is genuinely jittered, not collapsed to an endpoint.
* Same deterministic `randomFn` → identical numeric output across calls.
* `PGBOUNCER_MAX_RETRIES` is a finite non-negative integer (default 3).

---

## SLO expectations enforced

1. **No infinite hangs.** Every scenario that injects a delay or failure
   uses a `Promise.race(…, deadline)` safety net so the suite terminates
   even if a regression accidentally deadlocks the driver.
2. **Data integrity on retry.** Only transient connection errors are
   retried (`isTransientConnectionError`); query-level errors bubble
   immediately.
3. **Strict timeouts.** No single test can exceed the Vitest default
   timeout; per-test wall-clock budgets are enforced in the assertions.
4. **Clean teardown.** All toxics are removed in `afterEach` and proxies
   are removed in `afterAll`; Compose healthchecks block Toxiproxy start
   until Postgres/Redis are actually ready.

---

## Safety & security

* Tests are gated on `CHAOS_TESTS=true` so they never run by default on
  developer laptops or fast-PR pipelines.
* The dedicated proxies (`postgres_chaos`, `redis_chaos`) use separate
  ports from the shared smoke suite so parallel CI jobs never share a
  toxic state.
* The Toxiproxy HTTP API listens on `0.0.0.0` inside the Compose network
  only; it is never exposed to the public internet in CI.
* All secrets (`testpassword`, Redis without auth) are test-only — the
  Compose stack is ephemeral and destroyed after the run with `-v`.
* Schema credentials live exclusively in CI environment variables; no
  credentials are hard-coded in the scenario sources.
