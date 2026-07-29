# Incident Template — Redis / Cache Incident

> **When to use.** High miss rate, OOM evictions, circuit-breaker OPEN on
> Redis operations, slot-migration rollback, rate-limiter falling back to
> memory store, idempotency key lookup misses.
>
> Companion runbooks:
> - [src/redis.ts — circuit breaker, cluster redirects](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/src/redis.ts)
> - [Redis chaos scenarios (Toxiproxy)](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/tests/chaos/redis-chaos.spec.ts)

---

## 1. Header

| Field | Value |
| :--- | :--- |
| SEV | |
| Triggering alert | e.g. `RedisCircuitBreakerOpen`, `RedisHealthProbeFail`, `RateLimiterFallbackCountHigh` |
| Redis topology | ⬜ single-node · ⬜ cluster (`N` primaries · `M` replicas) |
| TLS enabled? | ⬜ yes · ⬜ no · ⬜ partial (some clients) |
| Recent deploy / topology change? | ⬜ yes (describe) · ⬜ no |

## 1.1 Dashboards — OPEN THESE NOW

| Panel | Grafana deep link |
| :--- | :--- |
| Redis cluster memory / connected_clients / key count | `https://grafana/d/redis-overview?from=now-3h&to=now` |
| Redis circuit-breaker state gauge + failures_total counter | `https://grafana/d/veritasor-backend?viewPanel=21&from=now-3h&to=now` |
| Rate limiter: Redis → memory fallback events | `https://grafana/d/veritasor-backend?viewPanel=40&from=now-3h&to=now` |
| Idempotency: keys count + sweeper evictions | `https://grafana/d/veritasor-backend?viewPanel=55&from=now-3h&to=now` |
| Health probe (PING) error rate | `https://grafana/explore?datasource=Prometheus&expr=rate(redis_health_probe_failures_total[5m])` |
| Cluster MOVED / ASK redirect rate | `https://grafana/d/veritasor-backend?viewPanel=25&from=now-3h&to=now` |
| (If slot migration in-flight) `redis-slot-migration.test` | → [integration test](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/tests/integration/redis-slot-migration.test.ts) |

---

## 2. Timeline

| UTC time | Who | Action | Result

---

## 3. Investigation (in order)

### Step 1: Circuit breaker state?

- [ ] Run:
  ```
  curl https://api.prod/health/redis  # or /health/ready
  ```
  Expected:
  ```json
  {"redis": "ok"} or {"redis": "error:Circuit breaker is OPEN"}
  ```
- [ ] State recorded:
  - `redisCircuitBreaker.state = [CLOSED | OPEN | HALF_OPEN]`
  - `failures_total since [start] = [N]`
- [ ] If OPEN → **skip to Step 3 (containment) first; root-cause after circuit is half-open again.**

### Step 2: Underlying Redis health (bypass Toxiproxy / LB)

- [ ] Direct PING via `redis-cli` (not through the app):
  ```
  redis-cli -h $REDIS_HOST -p $PORT --no-auth-warning ping
  # or with auth:
  redis-cli -h $HOST -a $AUTH --tls --no-auth-warning ping
  ```
  Result: `[PONG | error: … | hangs]`
- [ ] Memory usage:
  ```
  redis-cli -h $HOST INFO memory
  ```
  used_memory_human = `[ ]` · maxmemory = `[ ]` · maxmemory_policy = `[ ]`
- [ ] Key evictions rate rising? `INFO stats | grep evicted_keys` → delta over 60 s = `[N/min]`
- [ ] Connected clients vs max: `clients = [N] / maxclients = [M]`

### Step 3: If cluster → slot map sanity

- [ ] Any `MOVED` / `ASK` error flood in logs?  Search last 10 min:
  ```
  {app="veritasor-backend"} |="MOVED" OR |="ASK"
  ```
  Count ~= `[N] / min`.
- [ ] `CLUSTER SLOTS` matches `REDIS_CLUSTER_NODES` env?
  ```
  redis-cli -h $ANY_NODE CLUSTER SLOTS | head -n 40
  ```
  Compare with configured nodes; slots covered: `[0–16383: all covered? ⬜ yes · ⬜ no (gap at slots …)]`

### Step 4: Rate-limiter + idempotency impact

- [ ] Is rate limiter falling back to memory store?  Counter `rate_limiter_store_init_failures_total` rising?
  - ⬜ yes → **cross-pod rate limits NO LONGER APPLY during fallback window.** Raise alert for potential abuse.
- [ ] Is idempotency store silently dropping writes? (`RedisIdempotencyStore.set` with fallback no-op when breaker OPEN).
  - ⬜ yes → duplicate submissions MAY succeed if retried within breaker reset window.  Coordinate with support.

---

## 4. Containment → Remediation → Verification

### Containment (fastest first)

- [ ] ⬜ Open circuit?  Temporarily raise `resetTimeoutMs`? (default 10 s) **or** lower `failureThreshold` via env + redeploy.
- [ ] ⬜ Memory evictions causing miss rate spike?
  - Temporarily raise `maxmemory` (if headroom).
  - Switch eviction policy → `allkeys-lfu` if currently `volatile-lru` and many non-TTL keys.
- [ ] ⬜ Slot migration mid-incident?  Pause migration tool and validate final slot map.

### Remediation

- [ ] Root cause 1-line: `[ ]`
- [ ] Fix / config change (env var set, PR merged):
  ```
  [copy exact change]
  ```
- [ ] Deployed at `[UTC]`, SHA `[ ]`

### Verification after fix

- [ ] `redisCircuitBreaker.state == CLOSED` for `10` min.
- [ ] Health probe error rate == `0` for `5` min.
- [ ] Miss rate back to baseline.
- [ ] Cluster redirects back to baseline (near 0 per minute).
- [ ] Rate limiter now using Redis store again (no new fallback events).
- [ ] Idempotency writes succeeding → gauge `idempotency_keys_count` matching last known good value.

---

## 5. Post-mortem

- Root cause (5 whys):
  1. Paged because: `[ ]`
  2. Because: `[ ]`
  3. Because: `[ ]`
  4. Because: `[ ]`
  5. Because: `[ ]`
- Action items:
  - P1: `[TBD] @owner  YYYY-MM-DD`
  - P2: `[TBD] @owner  YYYY-MM-DD`
