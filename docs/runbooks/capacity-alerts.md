# Runbook: capacity & saturation alerts

## WebhookDlqDepthWarning / WebhookDlqDepthCritical

**Metric:** `webhook_dlq_depth{provider}`
**Thresholds:** warning > 50 for 5 m · critical > 200 for 2 m

**What it means.** The `webhook_dead_letters` table is accumulating rows that
the consumer has not retried successfully.

**Steps:**
1. Check recent errors in the `webhook_dead_letters` table:
   ```sql
   SELECT provider, error_code, COUNT(*) FROM webhook_dead_letters GROUP BY 1,2;
   ```
2. Inspect application logs for the relevant provider (e.g. `razorpay`).
3. If the consumer is crashing, redeploy or roll back the last deploy.
4. Once fixed, the admin retry endpoint will drain the queue automatically.
   For a manual flush: `POST /api/admin/webhooks/:provider/:eventId/retry`.
5. If the queue is stale junk, delete safely:
   ```sql
   DELETE FROM webhook_dead_letters WHERE updated_at < NOW() - INTERVAL '7 days';
   ```

---

## PgPoolHighUtilization / PgPoolSaturated

**Metric:** `pg_pool_active_connections / pg_pool_max_connections`
**Thresholds:** warning > 80 % for 3 m · critical > 95 % for 1 m

**What it means.** The pg connection pool is near or at capacity. New requests
will block on `connectionTimeoutMillis` (default 2 s) then fail with 503.

**Steps:**
1. Check `pg_pool_active_connections` against `PGPOOL_MAX` (default 10).
2. If traffic has grown legitimately, increase `PGPOOL_MAX` in the deployment
   environment and redeploy.
3. Look for long-running queries holding connections:
   ```sql
   SELECT pid, now() - query_start AS age, state, query
   FROM pg_stat_activity
   WHERE state != 'idle' ORDER BY age DESC LIMIT 10;
   ```
4. Kill runaway queries with `SELECT pg_terminate_backend(<pid>)` if needed.
5. If caused by a slow migration, roll it back or kill the transaction.

---

## SorobanSubmitLagHigh / SorobanSubmitLagCritical / SorobanRetryBudgetExhausted

**Metrics:** `soroban_submit_lag_seconds` (histogram) · `soroban_retry_budget_exhausted_total`
**SLO:** p95 on-chain confirmation < 60 s (warning) / < 180 s (critical)

**What it means.** Attestations are taking longer than expected to confirm on
the Stellar network, or the retry budget is being exhausted and submissions
are being silently dropped.

**Steps:**
1. Check the Stellar network status: <https://status.stellar.org>
2. Check the configured Soroban RPC endpoint (`SOROBAN_RPC_URL`):
   ```sh
   curl "$SOROBAN_RPC_URL" -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}' -H 'Content-Type: application/json'
   ```
3. If the RPC node is healthy, look at `soroban_retry_total` to see if retries
   are spiking — may indicate a contract issue or ledger backlog.
4. For `SorobanRetryBudgetExhausted`: increase `SOROBAN_RETRY_BUDGET_MAX_RETRIES`
   temporarily, or switch to a different RPC endpoint.
5. Unconfirmed attestations remain with `status: pending` in the DB. Re-submit
   them once the network recovers via `PATCH /api/attestations/:id/resubmit`
   (admin only).

---

## AttestationSubmitLatencyHigh

**Metrics:** `attestation_submit_latency_seconds` (histogram) · `sli:attestation_submit_latency_seconds:p95` (recording rule)
**SLO:** p95 attestation API latency < 200ms

**What it means.** The internal process for attestation submission (building, signing, and dispatching the transaction) is taking too long. This typically indicates resource starvation or an RPC slowdown before transaction confirmation.

**Steps:**
1. Check if PgBouncer queues or DB CPU are saturated. Database operations during the attestation process could be stalling.
2. Check the Soroban RPC server responsiveness.
3. Review if the adaptive batch size controller has throttled batch sizes due to high fees, which might cause queue build-up.
4. Scale up the backend tasks to distribute the load.

---

## PgBouncerQueueDepthWarning / PgBouncerQueueDepthCritical / PgBouncerMaxWaitTimeHigh

**Metrics:** `pgbouncer_waiting_clients` (gauge) · `pgbouncer_max_wait_seconds` (gauge)
**Thresholds:** warning > 10 waiting for 30 s · critical > 50 waiting for 15 s · avg wait > 0.5 s for 30 s

**What it means.** Clients are queuing for server connections in PgBouncer.
This is a leading indicator of tail-latency incidents: when the pool is
saturated, new requests wait for a connection slot, inflating p99 latency.
The scraper runs at 1-second granularity, so these alerts fire before
application-level symptoms appear.

**Steps:**
1. Check current queue depth and wait time:
   ```sql
   -- Connect to PgBouncer admin DB (port 6432, dbname=pgbouncer)
   SHOW STATS;
   ```
   Look at `waiting_clients`, `avg_wait`, `active_clients`, `servers`.

2. Correlate with PostgreSQL backend:
   ```sql
   -- On the PostgreSQL primary
   SELECT pid, now() - query_start AS age, state, query
   FROM pg_stat_activity
   WHERE state != 'idle' ORDER BY age DESC LIMIT 10;
   ```
   Long-running queries hold server connections, starving the pool.

3. If traffic has grown legitimately, scale PgBouncer:
   - Increase `max_client_conn` in `pgbouncer.ini`
   - Increase `default_pool_size` / `max_db_connections`
   - Reload PgBouncer: `RELOAD;` on admin console or SIGHUP.

4. If caused by a slow migration or runaway query, kill it:
   ```sql
   SELECT pg_terminate_backend(<pid>);
   ```

5. Consider enabling `pool_mode = transaction` (already default) and
   `max_client_conn` headroom. Monitor `pgbouncer_server_connections`
   gauge — if it hits `max_db_connections`, the pool is at hard capacity.

6. For `PgBouncerMaxWaitTimeHigh`: average wait > 500 ms means clients
   spend significant time queued. Check `pgbouncer_avg_query_time_seconds`
   — if queries are slow, fix the query or add read replicas.

## PgBouncer metrics scrape failure

Check `pgbouncer_scrape_errors_total` by reason. For `authentication`, verify the
dedicated exporter user is in PgBouncer `stats_users` and rotate its secret if
needed. For `connection` or `timeout`, verify the application pod can reach the
PgBouncer admin port and that the configured timeout is below the scrape
interval. Never substitute the normal application database credential. The
application continues serving traffic and retains the last good pool samples
while the exporter is degraded.