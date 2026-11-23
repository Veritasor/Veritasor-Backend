# Runbooks Index

> The single source of truth for **on-call runbooks**, incident-response
> **templates**, and **operator-facing documentation** for the Veritasor
> backend. If you are paged or investigating an incident, start here.

This index is a curated landing page. Scattered design docs, threat
models, and specs live elsewhere under `docs/`; only _operational_ content
goes in `docs/runbooks/`.

---

## ⚡ Quick-nav – What page do you need?

| I am …                                                            | Jump to                                                                            |
| :---------------------------------------------------------------- | :--------------------------------------------------------------------------------- |
| Paged right now by an alert                                       | **[Alert & Incident Runbooks](#alert--incident-runbooks)** → match your alert name |
| Opening a new incident post-mortem / ticket                       | **[Incident Templates](#incident-templates)** → copy the template that matches     |
| Running a deploy / migration / operational change                 | **[Change & Release Runbooks](#change--release-runbooks)**                         |
| Investigating a performance regression, slow API, or tail latency | **[Performance & Capacity Runbooks](#performance--capacity-runbooks)**             |
| Dealing with a failed webhook, DLQ backlog, or quarantined event  | **[Integration & DLQ Runbooks](#integration--dlq-runbooks)**                       |
| Looking for on-call tool links (dashboards, logs, traces, alerts) | **[On-Call Toolkit & Quick Links](#on-call-toolkit--quick-links)**                 |
| Writing a new runbook or adding a template                        | **[Contributing Runbooks](#contributing-runbooks)**                                |

---

## On-Call Toolkit & Quick Links

> Copy these into your bookmarks bar. They are ordered by how often an
> operator reaches for them.

| Tool                                | Link                                                                                                                                                                                                                                                   | Notes                                                                                                                                                                                                                  |
| :---------------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---- | ------------------------- |
| **📊 Backend overview dashboard**   | Grafana → `/d/veritasor-backend`                                                                                                                                                                                                                       | Golden signals: RPS, p50/p95/p99 latency, error %, pod count                                                                                                                                                           |
| **⏱️ Webhook EWMA decay dashboard** | [webhook-decay-dashboard.json](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/ops/grafana/webhook-decay-dashboard.json) · [docs](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/webhook-ewma-decay-dashboard.md)              | Per-provider delivery rate, EWMA health, DLQ depth, retry counts                                                                                                                                                       |
| **🚨 Active alerts**                | Alertmanager → `/alerts?receiver=backend-oncall`                                                                                                                                                                                                       | Filter `team=backend`                                                                                                                                                                                                  |
| **📜 Alert recording rules**        | [backend.rules.yaml](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/ops/alerts/backend.rules.yaml) · [tests.yaml](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/ops/alerts/tests.yaml)                                            | Recording + alerting rules with Prometheus unit tests                                                                                                                                                                  |
| **🔍 Search traces**                | Tempo/Jaeger → `/search`                                                                                                                                                                                                                               | Filter by `service.name = veritasor-backend`; use `correlationId` from response headers                                                                                                                                |
| **📋 Logs**                         | Loki → `{app="veritasor-backend"}`                                                                                                                                                                                                                     | Pivot: `                                                                                                                                                                                                               | json | line_format "{{.event}}"` |
| **🛡️ Security / audit logs**        | `/d/security-audit` dashboard + `/api/admin/audit-logs` endpoint                                                                                                                                                                                       | [Security provenance docs](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/security-provenance.md) · [SLSA provenance](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/slsa-provenance.md) |
| **💳 Integration health**           | `/d/integrations-health` dashboard                                                                                                                                                                                                                     | Stripe / Shopify / Razorpay webhook success rates, OAuth token freshness                                                                                                                                               |
| **🌊 Chaos Mesh experiments**       | [ops/chaos-mesh/](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/ops/chaos-mesh/)                                                                                                                                                            | Network partition scenarios + recovery verification                                                                                                                                                                    |
| **🧪 Chaos scenarios (Toxiproxy)**  | [tests/chaos/](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/tests/chaos/toxiproxy.md)                                                                                                                                                      | Redis / Postgres jitter, latency, slow-query scenarios                                                                                                                                                                 |
| **📈 k6 peak-attestation baseline** | [ops/k6/peak-attestation.config.js](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/ops/k6/peak-attestation.config.js) · [dashboard](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/ops/k6/grafana/peak-attestation-dashboard.json) | Load-regression gate configuration                                                                                                                                                                                     |
| **🧱 Heap regression baseline**     | [ops/heap-regression/](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/ops/heap-regression/config.ts)                                                                                                                                         | Node.js memory regression check config + baseline                                                                                                                                                                      |

---

## Alert & Incident Runbooks

> Each runbook corresponds 1:1 to the Prometheus alert annotations in
> [backend.rules.yaml](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/ops/alerts/backend.rules.yaml).
> Alert `annotations.runbook` links **directly** into the anchors below,
> so clicking the runbook URL from a page takes you to the exact section.

### Capacity & Saturation

| Alert name(s)                                                                             | Runbook                                                                                                                                                                                                                 | Severity           |
| :---------------------------------------------------------------------------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :----------------- |
| `PgPoolHighUtilization` · `PgPoolSaturated`                                               | [capacity-alerts.md → PgPoolHighUtilization](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/runbooks/capacity-alerts.md#pgpoolhighutilization--pgpoolsaturated)                                          | warning / critical |
| `PgBouncerQueueDepthWarning` · `PgBouncerQueueDepthCritical` · `PgBouncerAvgWaitTimeHigh` | [capacity-alerts.md → PgBouncerQueueDepth](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/runbooks/capacity-alerts.md#pgbouncerqueuedepthwarning--pgbouncerqueuedepthcritical--pgbounceravgwaittimehigh) | warning / critical |
| `AttestationSubmitLatencyHigh`                                                            | [capacity-alerts.md → AttestationSubmitLatencyHigh](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/runbooks/capacity-alerts.md#attestationsubmitlatencyhigh)                                             | warning            |
| _(coming)_ `RedisMemoryHighWarning` · `RedisMemoryHighCritical`                           | [redis-operations.md](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/runbooks/redis-operations.md)                                                                                                       | warning / critical |
| _(coming)_ `SorobanRpcRateLimited`                                                        | [soroban-operations.md](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/runbooks/soroban-operations.md)                                                                                                   | warning            |

### Webhooks & Integrations

| Alert name(s)                                        | Runbook                                                                                                                                                                                | Severity           |
| :--------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :----------------- |
| `WebhookDlqDepthWarning` · `WebhookDlqDepthCritical` | [capacity-alerts.md → WebhookDlqDepth](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/runbooks/capacity-alerts.md#webhookdlqdepthwarning--webhookdlqdepthcritical)      | warning / critical |
| `WebhookDlqAgeWarning` · `WebhookDlqAgeCritical`     | [webhook-dlq-recovery.md → DLQ age alerts](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/runbooks/webhook-dlq-recovery.md#webhookdlqagewarning--webhookdlqagecritical) | warning / critical |
| `WebhookQuarantineGrowth`                            | [webhook-dlq-recovery.md → Quarantine](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/runbooks/webhook-dlq-recovery.md#quarantine-growth-poison-pills)                  | warning            |
| `IntegrationOAuthTokenExpiring`                      | [integration-oauth-token-refresh.md](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/runbooks/integration-oauth-token-refresh.md)                                        | warning            |

### Soroban / On-Chain

| Alert name(s)                                                                       | Runbook                                                                                                                                                                                                            | Severity           |
| :---------------------------------------------------------------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :----------------- |
| `SorobanSubmitLagHigh` · `SorobanSubmitLagCritical` · `SorobanRetryBudgetExhausted` | [capacity-alerts.md → SorobanSubmitLagHigh](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/runbooks/capacity-alerts.md#sorobansubmitlaghigh--sorobansubmitlagcritical--sorobanretrybudgetexhausted) | warning / critical |
| _(coming)_ `SorobanFeesSpiking`                                                     | [soroban-operations.md](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/runbooks/soroban-operations.md)                                                                                              | warning            |

### Availability

| Alert name(s)                                               | Runbook                                                                                                                                                                                      | Severity           |
| :---------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :----------------- |
| _(coming)_ `ReadinessProbeFailing` · `LivenessProbeFailing` | [service-degradation-outage.md](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/runbooks/service-degradation-outage.md)                                                        | critical           |
| _(coming)_ `ErrorRateHigh` · `ErrorRateCritical`            | [service-degradation-outage.md → error-rate spike](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/runbooks/service-degradation-outage.md#error-rate-spike--availability-drop) | warning / critical |
| _(coming)_ `DeploymentRolloutStuck`                         | [deployment-rollout-rollback.md](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/runbooks/deployment-rollout-rollback.md)                                                      | critical           |

---

## Change & Release Runbooks

| Scenario                                                      | Runbook                                                                                                                                                                                    | Owner              |
| :------------------------------------------------------------ | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :----------------- |
| Deploying a release to production (canary → full)             | [deployment-rollout-rollback.md](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/runbooks/deployment-rollout-rollback.md)                                                    | Release engineer   |
| Rolling back a bad deploy                                     | [deployment-rollout-rollback.md → Rollback](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/runbooks/deployment-rollout-rollback.md#rollback-playbook)                       | On-call            |
| Running a DB migration safely (incl. CONCURRENTLY)            | [database-migration.md](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/runbooks/database-migration.md)                                                                      | Backend            |
| Verifying a migration rollback before shipping                | [migration-rollback-verification.md docs](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/migration-rollback-verification.md)                                                | CI                 |
| Rotating / revoking Stripe/Shopify/Razorpay OAuth credentials | [integration-oauth-token-refresh.md](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/runbooks/integration-oauth-token-refresh.md)                                            | Backend + Security |
| Rotating JWT / encryption keys                                | [key-rotation-secret-scram.md](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/runbooks/key-rotation-secret-scram.md)                                                        | Security           |
| SPIFFE / mTLS SVID rotation (OCSP / revocation)               | [mTLS OCSP docs](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/mtls-ocsp.md) · [SPIFFE docs](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/spiffe-svid.md) | Platform           |

---

## Performance & Capacity Runbooks

| Scenario                                              | Runbook                                                                                                                                                                                                               |
| :---------------------------------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| API tail latency regression (p95 / p99 up)            | [capacity-alerts.md](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/runbooks/capacity-alerts.md) + [Performance Investigation template](#performance-investigation-template)                           |
| Slow query detected (> `SLOW_QUERY_MS`)               | [database-migration.md → Slow-query triage](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/runbooks/database-migration.md#slow-query-triage)                                                           |
| k6 load-test gate fails (peak-attestation regression) | [ops/k6/README.md](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/ops/k6/README.md)                                                                                                                         |
| Heap regression alert (Node.js memory growth)         | [ops/heap-regression/README.md](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/ops/heap-regression/README.md)                                                                                               |
| Redis cluster reshard / slot migration                | [redis-operations.md](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/runbooks/redis-operations.md)                                                                                                     |
| PgBouncer vertical/horizontal scaling                 | [capacity-alerts.md → PgBouncer section](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/runbooks/capacity-alerts.md#pgbouncerqueuedepthwarning--pgbouncerqueuedepthcritical--pgbounceravgwaittimehigh) |

---

## Integration & DLQ Runbooks

| Scenario                                       | Runbook                                                                                                                                                                                  | Background docs                                                                                                                                                                                   |
| :--------------------------------------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Webhook DLQ backlog growing (depth alerts)     | [webhook-dlq-recovery.md](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/runbooks/webhook-dlq-recovery.md)                                                                | [DLQ sharding](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/dlq-sharding.md) · [DLQ quarantine](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/dlq-quarantine.md) |
| Poison pills piling up in `webhook_quarantine` | [webhook-dlq-recovery.md → Quarantine](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/runbooks/webhook-dlq-recovery.md#quarantine-growth-poison-pills)                    | [DLQ quarantine design](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/dlq-quarantine.md)                                                                                          |
| Shopify webhook signature verification failing | [webhook-dlq-recovery.md → Signature mismatches](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/runbooks/webhook-dlq-recovery.md#webhook-signature-negotiation-failure)   | [Webhook signature negotiation](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/webhook-signature-negotiation.md)                                                                   |
| Stripe Connect OAuth token near expiry         | [integration-oauth-token-refresh.md](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/runbooks/integration-oauth-token-refresh.md)                                          | [Integration permissions](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/integrations-permissions.md)                                                                              |
| Razorpay webhook handler misbehaving           | [webhook-dlq-recovery.md → Provider-specific triage](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/runbooks/webhook-dlq-recovery.md#provider-specific-triage-checklists) |                                                                                                                                                                                                   |

---

## Incident Templates

Copy the matching template into a new issue / Google Doc / post-mortem
page _immediately_ when you declare an incident. Fill in sections as you
go — an incomplete template is better than reconstructing memory after the
fact.

### 1. SEV Template (generic severity-based incident)

For any incident that triggers a SEV-1/SEV-2/SEV-3 declaration.

→ **[`incident-sev-template.md`](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/runbooks/incident-sev-template.md)**

### 2. Postgres / Database Incident Template

Lock wait, slow migration, connection-pool exhaustion, PgBouncer queuing,
replication lag, failover, etc.

→ **[`incident-postgres-template.md`](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/runbooks/incident-postgres-template.md)**

### 3. Redis / Cache Incident Template

High miss rate, OOM evictions, slot-migration rollback, circuit-breaker
trips, rate-limiter fallback events, idempotency store miss.

→ **[`incident-redis-template.md`](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/runbooks/incident-redis-template.md)**

### 4. Webhook / Integration Outage Template

Provider-wide webhook failures, DLQ depth explosion, quarantine growth,
OAuth token expiry, signature-verification regressions.

→ **[`incident-webhook-template.md`](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/runbooks/incident-webhook-template.md)**

### 5. Performance Investigation Template

Tail latency regression, error-rate climb, p95 SLO burn, slow queries,
heap/CPU anomalies without an explicit page.

→ **[`incident-performance-template.md`](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/runbooks/incident-performance-template.md)**

### 6. Deployment / Release Incident Template

Bad deploy, stuck rollout, flaky health checks, readiness probe failures
that correlate with a release tag.

→ **[`incident-deployment-template.md`](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/runbooks/incident-deployment-template.md)**

### 7. Security Incident Template

Suspected credential leak, auth bypass, audit-log anomalies,
webhook-replay attack, mTLS / SPIFFE trust boundary concern.

→ **[`incident-security-template.md`](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/runbooks/incident-security-template.md)**

---

## Contributing Runbooks

### Before you write a new runbook

1. **Check the index above** — is there already a closely related runbook
   you can extend instead of splitting?
2. **Link to dashboards.** Every runbook must have a _Dashboards_ section
   at the top with deep links into the panels the operator will stare at.
   Use `?from=now-6h&to=now&var-env=prod`-style query strings so the
   operator lands pre-scoped.
3. **Give it a test run.** If the runbook includes SQL, curl, or CLI
   commands, run them once against staging before merging.
4. **Keep it prescriptive**, not descriptive. "Run `X`" > "You may wish
   to consider looking at `X` as a possible next step".

### File naming convention

```
docs/runbooks/
├── README.md                          ← this index (do not rename)
├── capacity-alerts.md                 ← existing, alert-anchored content
├── {topic}-{action|context}.md        ← operator runbooks
│   ├── webhook-dlq-recovery.md
│   ├── integration-oauth-token-refresh.md
│   ├── database-migration.md
│   ├── deployment-rollout-rollback.md
│   ├── service-degradation-outage.md
│   ├── redis-operations.md
│   ├── soroban-operations.md
│   └── key-rotation-secret-scram.md
└── incident-{topic}-template.md       ← response templates (7 files)
    ├── incident-sev-template.md
    ├── incident-postgres-template.md
    ├── incident-redis-template.md
    ├── incident-webhook-template.md
    ├── incident-performance-template.md
    ├── incident-deployment-template.md
    └── incident-security-template.md
```

### Every runbook MUST contain

A runbook is only useful if it's usable under stress. Every file in
`docs/runbooks/*.md` (excluding templates) must have, in order:

1. **H1 title** that matches exactly the anchor name alert annotations
   link to.
2. **Dashboards** block — a 2-column table of `Panel name | Grafana link`.
3. **Alert names** that map here (if applicable).
4. **What this alert means** — 2 sentences max, no jargon.
5. **Customer impact** — what the user sees if we do nothing.
6. **Remediation steps** — numbered, copy-pasteable CLI / SQL snippets
   with a clear STOP condition.
7. **Escalation** — who to page if steps 1–N don't recover it in
   `T minutes` (spell out T).
8. **False-positive checklist** — how to tell if the alert itself is
   wrong.

### Every incident template MUST contain

A template is _filled in during the incident_, not read. Use checklists,
not paragraphs:

1. **Incident header** (SEV level, commander, comms, scribe, start time,
   detecting alert).
2. **Timeline log** — markdown table, append-only.
3. **Checklists** — Detection → Containment → Remediation → Verification
   → Post-mortem.
4. **Dashboard deep links** — pre-filled time ranges.
5. **SQL / CLI commands** specific to the incident type.
6. **Escalation matrix** — who to pull in by SEV level.
7. **Post-mortem capture** — 5-why, action items, owners, due dates.

---

## Index Health (housekeeping)

This README is the landing page; if the links above start rotting, the
whole runbook library loses trust. Basic rules:

1. **Every runbook in this directory is linked from one of the tables
   above.** If you add a new `*.md` file, update the relevant table in the
   same PR.
2. **Every alert in `ops/alerts/backend.rules.yaml` has its
   `annotations.runbook` point at an anchor inside one of these files.**
   Use Prometheus unit tests in `ops/alerts/tests.yaml` to assert the
   runbook URL matches.
3. **Once per quarter:** the on-call lead does a link audit by running
   `find docs/runbooks -name '*.md'` and comparing with the index table.
4. **After every SEV-1 or SEV-2 incident:** update the relevant runbook
   with whatever step you _wished_ existed during the fire. The runbook
   is the institutional memory — don't rely on Slack threads.
