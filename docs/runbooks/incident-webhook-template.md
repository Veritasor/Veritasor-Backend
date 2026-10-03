# Incident Template — Webhook / Integration Outage

> **When to use.** Provider-wide webhook failures, DLQ depth explosion,
> quarantine growth, OAuth token expiry, or signature-verification
> regressions for Stripe, Shopify, Razorpay, etc.

Companion runbooks / docs:
- [capacity-alerts.md — DLQ depth alerts](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/runbooks/capacity-alerts.md#webhookdlqdepthwarning--webhookdlqdepthcritical)
- [DLQ quarantine design](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/dlq-quarantine.md)
- [DLQ sharding design](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/dlq-sharding.md)
- [Webhook signature negotiation](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/webhook-signature-negotiation.md)
- [Webhook EWMA decay dashboard & metrics](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/webhook-ewma-decay-dashboard.md)

---

## 1. Header

| Field | Value |
| :--- | :--- |
| SEV | |
| Providers affected (tick all) | ⬜ Stripe · ⬜ Shopify · ⬜ Razorpay · ⬜ Other: `[ ]` |
| DLQ depth at detection | `[N]` rows in `webhook_dead_letters` |
| Quarantine rows at detection | `[N]` rows in `webhook_quarantine` |
| Oldest DLQ entry age | `[hh:mm or timestamp]` |
| Recent deploy touching webhook path? | ⬜ yes (sha) · ⬜ no · ⬜ unknown |

## 1.1 Dashboards

| Panel | Grafana link |
| :--- | :--- |
| Webhook EWMA health + DLQ depth by provider | `https://grafana/d/webhook-decay?from=now-3h&to=now` · [dashboard JSON](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/ops/grafana/webhook-decay-dashboard.json) |
| Dead-letter / quarantine counts + age (Prometheus recording rules) | `https://grafana/d/webhook-decay?viewPanel=4&from=now-3h&to=now` |
| Alert: `WebhookDlqDepthWarning/Critical` firing? | `https://alertmanager/alerts?filter=name=~WebhookDlq` |
| Admin endpoints for retry / release | `GET /api/admin/webhooks/quarantine?provider=…` (perms required) |

---

## 2. Timeline

| UTC time | Who | Action | Result

---

## 3. Investigation steps

### Step 1: Is it *one* provider or *all* providers?

- [ ] SQL breakdown by provider + error_code:
  ```sql
  SELECT provider,
         error_code,
         integration_shard,
         COUNT(*)                                AS n,
         MIN(created_at)                         AS oldest,
         MAX(created_at)                         AS newest
  FROM webhook_dead_letters
  WHERE created_at > NOW() - INTERVAL '24 hours'
  GROUP BY 1, 2, 3
  ORDER BY n DESC
  LIMIT 20;
  ```
  Top provider: `[ ]` · top error_code: `[ ]` (e.g. `ECONNRESET`, `401 invalid_token`, `SIG_MISMATCH`, `TIMEOUT`)
- [ ] All providers failing similarly → **network / egress / TLS / DNS** path (Step 2).
- [ ] One provider only → **downstream / OAuth / signature / webhook-handler code path** (Step 3).

### Step 2: All providers down → egress / platform

- [ ] Egress IPs on allowlist for providers?  List used: [webhookEgressIps](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/src/routes/webhookEgressIps.ts) → call endpoint `GET /api/admin/webhooks/egress-ips`
- [ ] mTLS / SPIFFE: any recent SVID rotation / OCSP revocation check failing?
  Check `spiffe_svid_ttl_seconds` metric and [mtls-ocsp docs](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/mtls-ocsp.md).
- [ ] DNS / TLS: from a pod shell, curl each provider's webhook endpoint.

### Step 3: Single provider → triage by error pattern

#### A. `401 invalid_token` / `token expired` / OAuth refresh failing

→ Jump to [integration-oauth-token-refresh.md](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/runbooks/integration-oauth-token-refresh.md).

#### B. `SIG_MISMATCH` (signature verification)

→ Jump to [webhook signature negotiation docs](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/webhook-signature-negotiation.md).
- [ ] Did provider rotate signing secret *without* notifying us? → re-rotate locally, update secret store.
- [ ] Did we recently change algo (HMAC-SHA256 → RSA, etc.)? → roll back, reconcile.

#### C. `ECONNRESET` / `TIMEOUT` / `502 503 504`

→ Provider-side degradation or egress.  Provider status page check.
- [ ] Status page URLs:
  - Stripe:  https://status.stripe.com
  - Shopify:  https://status.shopify.com  · webhook-specific panel
  - Razorpay:  https://status.razorpay.com
- [ ] Temporarily widen `WEBHOOK_HTTP_TIMEOUT_MS` from default (`[ ]`) → (`[suggest]`) ms if pure latency.

#### D. Poison pills in quarantine

→ Fingerprint-based quarantine.  See [DLQ quarantine docs](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/dlq-quarantine.md).

---

## 4. Remediation (copy-paste commands)

### Lane 1: Replay the DLQ

- [ ] Admin retry endpoint (rate-limited, respects quarantine):
  ```bash
  curl -X POST https://api.prod/api/admin/webhooks/retry \
    -H "Authorization: Bearer $ADMIN_TOKEN" -H "Idempotency-Key: $(uuidgen)" \
    -d '{"provider":"razorpay","maxBatch":500}'
  ```
  Result: `[OK / N rows retried / errors: …]`
- [ ] Repeat batches of 500 until depth decreasing.  **Do NOT parallelize above concurrency 2 per provider — you'll hammer downstream.**

### Lane 2: Release poison pills from quarantine (manually verified only)

Only do this after confirming the root cause is fixed and the released
event *will* succeed — otherwise you bounce it right back into quarantine
and burn the counter:

```sql
-- 1. Inspect a few quarantined rows (PII masked):
SELECT id, provider, event_id, failure_fingerprint, created_at,
       left(event_payload::text, 40) AS payload_prefix
FROM webhook_quarantine
WHERE provider = 'stripe' AND created_at > NOW() - INTERVAL '2 days'
LIMIT 10;

-- 2. Release via admin endpoint (generates audit log entry RELEASE_QUARANTINED_WEBHOOK):
curl -X POST https://api.prod/api/admin/webhooks/quarantine/release \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"ids": ["<id1>", "<id2>"]}'
```

### Lane 3: OAuth token refresh

→ Use [integration-oauth-token-refresh.md runbook](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/runbooks/integration-oauth-token-refresh.md).

---

## 5. Verification

- [ ] DLQ depth now **monotonically decreasing** for 10 minutes.
- [ ] Oldest DLQ entry age < 15 minutes.
- [ ] Quarantine growth rate stopped (no new entries in 10 min).
- [ ] EWMA decay metric: `webhook_ewma_health{provider="…"}` back to ≥ 0.9 (healthy range).
- [ ] 50 freshly-queued webhooks, 100 % delivered on first attempt.
- [ ] Signature-mismatch rate = 0 for 10 min.
- [ ] OAuth token expiry in provider dashboard > 48 h from now.

---

## 6. Post-mortem

- 5-whys:
  1. `[ ]`
  2. `[ ]`
  3. `[ ]`
  4. `[ ]`
  5. `[ ]`
- Action items:
  - P1: `[ ]` → `@owner` · `YYYY-MM-DD`
  - P2: `[ ]` → `@owner` · `YYYY-MM-DD`
