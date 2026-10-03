# Incident Template — Postgres / Database Incident

> **When to use.** Lock waits, slow migrations, connection-pool exhaustion,
> PgBouncer queuing, replication lag, failovers, slow queries that
> trigger PgPoolHighUtilization / PgPoolSaturated / PgBouncerQueueDepth alerts.
> Also use the [capacity-alerts.md runbook first; this is the _incident log_ that
> accompanies it.

Related runbook → [capacity-alerts.md (PgPool & PgBouncer)](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/runbooks/capacity-alerts.md)

---

## 1. Header

| Field                                                                                                                                                                                         | Value                                                            |
| :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :--------------------------------------------------------------- |
| SEV (copy-paste from [SEV template header](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/runbooks/incident-sev-template.md#1-header-fill-in-within-5-minutes-of-declaration)) |                                                                  |
| Triggering alert(s)                                                                                                                                                                           | e.g. `PgPoolSaturated` (critical)`·`PgBouncerQueueDepthCritical` |
| PG cluster / shard                                                                                                                                                                            | `[primary: TBD · replicas: TBD · pgbouncer: TBD]`                |
| Was there a deploy / migration in the last 30 min?                                                                                                                                            | ⬜ yes (sha `[TBD]`) · ⬜ no · ⬜ unknown                        |

## 1.1 Dashboards — OPEN THESE NOW

| Panel                                               | Grafana deep link                                                                                                                      |
| :-------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------- | ------------------------ |
| PgBouncer pool (clients / avg_wait / avg_query time | `https://grafana/d/veritasor-backend?viewPanel=7&from=now-3h&to=now&var-env=prod`                                                      |
| pg_stat_activity (long runners)                     | `https://grafana/d/pg-overview?from=now-3h&to=now`                                                                                     |
| DB size + replication lag                           | `https://grafana/d/pg-overview?viewPanel=14&from=now-3h&to=now`                                                                        |
| Slow-query explain logs                             | `https://grafana/explore?datasource=Loki&expr={app="veritasor-backend"}                                                                | = "slow_query_detected"` |
| Slow-query docs + EXPLAIN                           | [slow query design](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/src/db/client.ts#L6-L94) (SLOW_QUERY_MS threshold)        |
| Migration rollback verify docs                      | [migration-rollback-verification.md](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/migration-rollback-verification.md) |
| Migration timeout docs                              | [migration-timeouts.md](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/migration-timeouts.md)                           |

---

## 2. Timeline

| UTC time | Who | Action | Result

---

## 3. Investigation checklist (in ORDER — do not skip steps)

### Step 1: Measure (0–5 min) — Is the pool full or is the query slow?

- [ ] Run `SHOW STATS;` on PgBouncer admin port 6432, dbname=pgbouncer.
  ```
  psql "postgresql://pgbouncer_user:$PGBOUNCER_PW@$PGBOUNCER_HOST:6432/pgbouncer
  pgbouncer=# SHOW STATS;
  pgbouncer=# SHOW POOLS;
  pgbouncer=# SHOW CLIENTS;
  ```
  Key numbers to record:
  - `waiting_clients = [ ]` (queue depth)
  - `avg_wait (s = [ ]` (how long clients sit in queue before getting a conn)
  - `avg_query (s) = [ ]` (how long queries run once they get a conn) —
    → If `avg_query` is high → **queries themselves slow, go to Step 3.**
    → If `avg_wait` high but `avg_query` normal → **pool starved, go to Step 2.**

### Step 2: Pool-starved path (PgBouncer queueing)

- [ ] Compare `pgbouncer_server_connections` vs `default_pool_size` / `max_db_connections`.
      Are we at the cap? ⬜ yes → raise `default_pool_size` (RELOAD pgbouncer).
- [ ] Current `PGPOOL_MAX` / `max_client_conn` values recorded here:
  ```
  PGPOOL_MAX=[ ]   max_client_conn=[ ]   default_pool_size=[ ]
  ```
- [ ] Did we just scale down backend pods? ⬜ yes (more clients per-pool cap) → scale app back.
- [ ] Does `pg_stat_activity` show hung transactions (state != 'idle', old) holding conns?
  ```sql
  SELECT pid, age(now(), xact_start) AS xact_age, state, left(query, 120) AS q
  FROM pg_stat_activity
  WHERE state <> 'idle'
  ORDER BY xact_start IS NOT NULL DESC, xact_age DESC NULLS LAST
  LIMIT 20;
  ```
  Hung pids: `[ list pids ]`

### Step 3: Slow-query path

- [ ] Top 10 slow queries captured from `pg_stat_statements` OR from logs:
  ```sql
  SELECT queryid, calls, total_exec_time, mean_exec_time, rows,
         left(query, 200)
  FROM pg_stat_statements
  ORDER BY total_exec_time DESC
  LIMIT 10;
  ```
  Paste top offenders here:
  ```
  [ ]
  ```
- [ ] EXPLAIN (ANALYZE, BUFFERS) on worst offender:
  ```
  [ paste EXPLAIN output
  ```
  Expected vs actual: `[ ]`
- [ ] Missing / unused index? ⬜ yes → candidate index: `CREATE INDEX CONCURRENTLY …`
      Concurrently-safe? ⬜ yes (run outside tx) · ⬜ no (requires downtime / lock).

### Step 4: Lock-wait path

- [ ] Blocking + blocked pids + queries + durations:
  ```sql
  SELECT pid, usename, pg_blocking_pids(pid) AS blocked_by,
         wait_event_type, wait_event, age(now(), xact_start) AS xact_age,
         left(query, 160) AS q
  FROM pg_stat_activity
  WHERE cardinality(pg_blocking_pids(pid)) > 0
      OR wait_event_type = 'Lock'
  ORDER BY xact_age DESC NULLS LAST;
  ```
  Blocker pid = `[ ]` · blocked count = `[ ]`

---

## 4. Remediation playbook — pick ONE lane, do not mix

### Lane A: Emergency pool-queue back-pressure (fastest win first)

- [ ] Kill ONLY if queue > 50 waiting for > 5 min → ⬜ scaled `PGPOOL_MAX` = from `[ ]` to `[ ]`.
- [ ] ⬜ scaled PgBouncer `default_pool_size` from `[ ]` to `[ ]` (RELOAD).
- [ ] ⬜ rollback bad deploy (if incident start ≈ deploy start).
- [ ] ⬜ terminate runaway pids:
  ```sql
  SELECT pg_terminate_backend(pid)
  FROM pg_stat_activity
  WHERE pid IN (/* blocker pids above */);
  ```

### Lane B: Slow-query / missing index

- [ ] ⬜ create index CONCURRENTLY: `[ SQL ]`
  - Started: `[UTC]` · Expected duration: `[ ]` · Finished: `[UTC]`
- [ ] ⬜ hotfix deploy of app code path removing / rewritten query.
      SHA deployed: `[TBD]`

### Lane C: Lock wait / long-running transaction

- [ ] ⬜ kill blocker pid(s). Result: queue drained within `[X]` min.
- [ ] ⬜ app code fix preventing similar locks — PR `[#TBD]`.

---

## 5. Verification

- [ ] PgBouncer `waiting_clients = 0 sustained 5 minutes.
- [ ] PgPool utilisation < 60 % sustained 10 minutes.
- [ ] Top offending query gone or p95 back to baseline.
- [ ] No new slow_query_detected events at a rate above baseline.
- [ ] Replication lag (if replicas) caught up < 1 s.

---

## 6. Post-mortem capture (copy into SEV template §5)

- Root cause 1-liner:

```
[TBD — e.g. "Missing index on webhook_dead_letters(provider, error_code caused seq scan under 2min query holding 10 pool conns.]
```

- Schema / index / DB parameter changed list of action items:
- [#TBD] Fix X → owner due date
- [#TBD] Fix Y → owner due date
