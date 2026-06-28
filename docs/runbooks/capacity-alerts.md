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
