# Incident Template — Performance Investigation

> **When to use.** Tail latency regression (p95/p99 up), SLO burn on API
> latency or error rate, slow-query pattern, heap / CPU growth without a
> clear alert firing.  Use when you *suspect* a performance problem but
> haven't yet declared a SEV incident.
>
> Also used to document periodic SLO burn reviews.

Related docs:
- [Observability & tracing (spans / attributes)](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/observability.md)
- [Metrics exemplars → trace links](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/metrics-exemplars.md)
- [SLO dashboard recording rules](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/ops/alerts/backend.rules.yaml)
- [k6 peak-attestation load-test baseline](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/ops/k6/peak-attestation.config.js) · [dashboard](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/ops/k6/grafana/peak-attestation-dashboard.json)
- [Heap regression check config](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/ops/heap-regression/config.ts)

---

## 1. Header

| Field | Value |
| :--- | :--- |
| Symptom (what tipped us off) | e.g. "p95 /attestations POST latency climbed from 140 ms → 310 ms after v1.23.0 deploy" |
| Start time (UTC) | first timestamp where deviation sustained > 10 min: `[YYYY-MM-DD HH:MM]` |
| Reporter | `@who` |
| SLO burn so far | burned `[X]` min of `[30-day budget name]` · estimate: `[Y]` days until full burn |
| Env(s) | ⬜ prod · ⬜ staging · ⬜ both |
| Is there a correlated deploy? | ⬜ yes (SHA `[ ]`, deployed `[UTC]`) · ⬜ no · ⬜ unclear |

## 1.1 Dashboards — OPEN THESE NOW

| Panel | Grafana deep link (adjust env / time window) |
| :--- | :--- |
| Backend overview — RPS · p50 · p95 · p99 · error % per route | `https://grafana/d/veritasor-backend?from=now-24h&to=now&var-env=prod` |
| Per-endpoint latency breakdown | `https://grafana/d/veritasor-backend?viewPanel=3&from=now-24h&to=now` |
| Slow query detected events (Loki) | `https://grafana/explore?datasource=Loki&expr={app="veritasor-backend"} |= "slow_query_detected"` |
| DB pool + wait times | `https://grafana/d/veritasor-backend?viewPanel=7&from=now-24h&to=now` |
| Redis circuit breaker + hit/miss | `https://grafana/d/veritasor-backend?viewPanel=21&from=now-24h&to=now` |
| Exemplar trace drill-down (spike → p99 histogram bucket exemplar → trace) | `https://grafana/d/veritasor-backend?viewPanel=3&from=now-24h&to=now` · [docs](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/metrics-exemplars.md) |
| k6 peak-attestation regression baseline | `https://grafana/d/k6-peak-attestation?from=now-7d&to=now` |
| Heap regression check (Node.js RSS vs baseline) | `https://grafana/d/heap-regression` |

---

## 2. Timeline of investigation (append-only)

| UTC | Who | Step | Observation / hypothesis |
| :--- | :--- | :--- | :--- |

---

## 3. SLO burn quantification

> If this is a real regression, it is *burning* SLO budget.  Record burn
> rate up-front so we know how urgent triage is.  Burn rate = 1.0 means
> we are using budget exactly as fast as the 30-day SLO allows.  Burn
> rate **> 14.4** = "page now, this will burn the whole budget in < 2 days".

- [ ] Budget window (default 30 d) · Target SLO: 99.9 % latency / 99.95 % availability.
- [ ] Current burn rate = `[N]`x.
- [ ] Hours remaining at this burn rate = `[H]` h.
- [ ] Decision: ⬜ close (false positive / negligible burn) · ⬜ monitor (low burn) · ⬜ escalate (SEV-2 if burn > 2x)

---

## 4. The "4 windows" method

Compare these 4 time windows.  Write down what *changed* between them.

| Window | When | p95 latency | p99 latency | RPS | error % | slow queries / min |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Baseline (pre-incident)** | `-24 h → -12 h` | | | | | |
| **Gradual change window** | `-6 h → -3 h` | | | | | |
| **Spike / deviation start** | `-2 h → -1 h` | | | | | |
| **Now** | last 15 minutes | | | | | |

→ What changed between windows: `[TBD]`

---

## 5. Drill-down (pick the matching scenario, run checklists)

### Scenario A: p95/p99 up, RPS stable → single slow endpoint

- [ ] **Identify the endpoint.** Top 5 routes by latency delta:
  ```
  [ paste from per-endpoint panel ]
  ```
  Worst offender: `[METHOD /path]`
- [ ] **Pick an exemplar from the histogram bucket**, click through to the trace.
  - Trace ID: `[ ]`
  - Which span dominates total duration? → `[span.name]` · `[ ]` ms (p99 of `[endpoint]`)
- [ ] If span is `db.*` → go to Scenario C (DB).
- [ ] If span is `queue.*` / `batch.*` → go to Scenario D (queue / batching).
- [ ] If span is outbound HTTP → Scenario E (downstream call).

### Scenario B: RPS spike (traffic change)

- [ ] Top user agents / tenants / IPs: `[TBD]`
- [ ] Is this a good spike (organic growth) or abuse?
  - ⬜ Organic → scale, then document.
  - ⬜ Abuse → rate-limit / WAF rule (see business-authorization-boundary-checks docs).
- [ ] Rate-limit rules deployed: `[rule IDs]`

### Scenario C: Slow query / DB path

→ Also apply [Postgres incident template](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/runbooks/incident-postgres-template.md) §3.

- [ ] Top 5 SQL by total time:
  ```sql
  SELECT queryid, calls, total_exec_time, mean_exec_time, rows,
         shared_blks_hit, shared_blks_read, left(query, 200)
  FROM pg_stat_statements
  ORDER BY total_exec_time DESC LIMIT 5;
  ```
  Paste here:
  ```
  ```
- [ ] EXPLAIN ANALYZE BUFFERS on worst:
  ```
  [paste output]
  ```
- [ ] Hypothesis: `[TBD]` (missing index? seq scan? bad join order? vacuum needed? work_mem low?)
- [ ] Remediation candidate: `CREATE INDEX CONCURRENTLY / REINDEX / VACUUM ANALYZE / rewrite query`

### Scenario D: Queue / batching (attestation submit)

→ Refer to [capacity-alerts.md AttestationSubmitLatencyHigh](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/runbooks/capacity-alerts.md#attestationsubmitlatencyhigh)

- [ ] Queue size: `avg [N]`, max `[M]`
- [ ] Batch size: `avg [N] items`
- [ ] `queue.wait_time_ms` p95 = `[ms]`; target < 500 ms
- [ ] Adaptive batch size controller throttled? → fee pressure (Stellar/Soroban network)

### Scenario E: Downstream call slow (Stripe, Soroban RPC, …)

- [ ] Service: `[TBD]` · p95 call time = `[ms]` (baseline: `[ms]`)
- [ ] Provider status page: `[status URL]` → `[state: ok/degraded/outage]`
- [ ] Retries / exponential-backoff: retries today `[N]` / success rate after retries `[%]`
- [ ] Retry budget exhausted? → alert `SorobanRetryBudgetExhausted` or equivalent.

### Scenario F: CPU / heap growth without traffic growth

- [ ] Run heap regression check against baseline:
  ```bash
  pnpm --cwd ops/heap-regression run check
  ```
  Result: RSS delta = `[MB]` vs baseline (`[MB]`). ⬜ within tolerance · ⬜ regression
- [ ] CPU per route profile (V8 CpuProfiler via `/admin/debug/profile` if enabled):
  ```
  [top 5 hot functions]
  ```
- [ ] OpenTelemetry span attributes showing skew: e.g., `queue.batch.size` unusual distribution.

---

## 6. Remediation plan

- Step 1 (hotfix if possible): `[TBD]`
- Step 2 (code/config change): PR `[#TBD]`
- Step 3 (long-term): `[TBD]`
- Deployed at `[UTC]` · SHA `[ ]`

---

## 7. Verification

- p95 back to baseline for ≥ 1 hour: ⬜ yes (value: `[ms]`)
- p99 back to baseline for ≥ 1 hour: ⬜ yes (value: `[ms]`)
- Slow-query count / min = `[N]` (pre-incident: `[M]`)
- SLO burn-rate now: `[X]`x (target ≤ 1.0x)
- k6 regression gate passes if this caused test changes: ⬜ yes · SHA of load-test run: `[ ]`

---

## 8. Post-mortem + action items

| # | Action | Owner | Due |
| :-- | :--- | :--- | :--- |
| P1 | | |
| P2 | | |
| P3 | | |
