# Incident Template — Generic SEV (SEV-1 / SEV-2 / SEV-3)

> **When to use this template.** Any incident that triggers a severity
> declaration (customer impact, availability drop, data integrity concern).
> Duplicate this file / copy the body into a new issue or incident doc,
> fill in the `[TBD]` blocks immediately, and keep appending to the
> timeline *as the incident unfolds* — not after.

---

## 1. Header (fill in within 5 minutes of declaration)

| Field | Value |
| :--- | :--- |
| **Incident ID / ticket** | `INC-[TBD]` |
| **Severity** | ⬜ SEV-1 (critical / outage) · ⬜ SEV-2 (major / SLO burn) · ⬜ SEV-3 (minor / partial) |
| **Incident commander (IC)** | `@[TBD]` |
| **Scribe / note-taker** | `@[TBD]` |
| **Comms lead** (customer / status-page updates) | `@[TBD]` |
| **Detected by alert** (paste link) | `[TBD]` — `[grafana alert URL]` |
| **Started at** (UTC) | `[YYYY-MM-DD HH:MM UTC]` |
| **Declared at** (UTC) | `[YYYY-MM-DD HH:MM UTC]` |
| **Environment(s) affected** | ⬜ prod · ⬜ staging · ⬜ both · ⬜ specific `[env]` |
| **Regions / shards affected** | `[TBD — e.g. us-east-1, tenant shard 3]` |
| **Services / components affected** | `[TBD — e.g. attestation submit, auth, webhooks]` |
| **Customer-facing status page update sent?** | ⬜ yes (link) · ⬜ no · ⬜ not needed (SEV-3) |
| **Related runbook(s)** | → [Runbooks index](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/runbooks/README.md) · match from alert |

### 1.1 Dashboards (OPEN THESE NOW)

Open each tab.  The links use `from=now-6h` prefilled so you land on the
right window — adjust ranges up if the incident started earlier.

| Panel | Grafana deep link |
| :--- | :--- |
| Backend overview (RPS, latency %, errors) | `https://grafana/d/veritasor-backend?from=now-6h&to=now&var-env=prod` |
| Error envelope breakdown by status | `https://grafana/d/veritasor-backend?viewPanel=12&from=now-6h&to=now` |
| PgBouncer + pool utilisation | `https://grafana/d/veritasor-backend?viewPanel=7&from=now-6h&to=now` |
| Redis circuit-breaker state + cache hit/miss | `https://grafana/d/veritasor-backend?viewPanel=21&from=now-6h&to=now` |
| Webhook DLQ depth + EWMA decay | `https://grafana/d/webhook-decay?from=now-6h&to=now` · [dashboard JSON](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/ops/grafana/webhook-decay-dashboard.json) · [docs](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/webhook-ewma-decay-dashboard.md) |
| Soroban submit lag p95 + retry budget | `https://grafana/d/veritasor-backend?viewPanel=33&from=now-6h&to=now` |
| Active alerts (Alertmanager) | `https://alertmanager/alerts?receiver=backend-oncall` |
| Audit log (admin endpoint) | `https://api.prod/admin/audit-logs?from=[start_ts]` |

---

## 2. Timeline (APPEND-ONLY, UTC timestamps, 1 entry per action)

> ⚠️ **Rule: 1 action per row.** Do not edit past rows — if you later
> discover a timing was wrong, add a *correction* row at the bottom
> marked `(correction)`.  During the post-mortem we reconcile, not
> rewrite history.

| UTC time | Who | Event / action taken | Outcome observed |
| :--- | :--- | :--- | :--- |
| `[HH:MM]` | `@[detector]` | **Detected.** `[Alert X fired, or customer Y reported Z]` | |
| `[HH:MM]` | `@[IC]` | **Declared SEV-2.** IC = `@a`, Scribe = `@b`, Comms = `@c`. | |
| `[HH:MM]` | `@[who]` | Ran `[SQL / curl / deploy-rollback-command …]` | Result: `[OK / error: … / partial]` |
| `[HH:MM]` | | **Mitigated.** `[Primary symptom stopped worsening]` | |
| `[HH:MM]` | | **Resolved.** `[All metrics green, customer-visible symptoms gone]` | |
| `[HH:MM+]` | | *(correction)* Earlier `[HH:MM]` action — actual outcome was `[X]`, not `[Y]` | |

---

## 3. Detection → Containment → Remediation → Verification checklist

### Detection (0–10 min)

- [ ] Incident declared + header (§1) filled in — severity assigned.
- [ ] Dashboards from §1.1 are open in the IC's browser.
- [ ] Scope confirmed: **affected services, env, regions, estimated
      customer count.**  Write that here: `[TBD]`.
- [ ] Is this *still getting worse*?  ⬜ yes · ⬜ plateaued · ⬜ already recovering.

### Containment (10–30 min target — stop the bleeding first)

Pick whatever is fastest: rollback, feature-flag off, rate-limit,
quarantine the bad input, kill the runaway query.  You can investigate
root cause *after* the bleed stops.

- [ ] ⬜ Rolled back last deploy (if incident correlates with a deploy).
  Command:
  ```
  [copy-paste the exact command used]
  ```
  Result: `[TBD]`
- [ ] ⬜ Toggled feature flag `[FLAG_NAME]` to `false`.  Result: `[TBD]`
- [ ] ⬜ Rate-limited / shed traffic from offending path: `[TBD]`
- [ ] ⬜ Killed runaway DB queries (pids: `[ ... ]`).  Result: `[TBD]`
- [ ] ⬜ Flushed DLQ / quarantined poison pills: `[TBD]`
- [ ] ⬜ Other containment action: `[TBD]`.  Result: `[TBD]`
- [ ] **Containment checkpoint:** error / lag / saturation graphs have
      *stopped climbing*.  ⬜ yes · ⬜ no (loop ↑, escalate).

### Remediation (30–120 min — fix the underlying cause)

- [ ] Root cause identified in one sentence: `[TBD]`.
- [ ] Linked PRs / commits with the fix: `[#TBD]`.
- [ ] Fix validated in staging ⬜ yes · ⬜ no · ⬜ hotfix to prod directly with post-validation.
- [ ] Fix deployed to production.
      Deployed SHA: `[TBD]` · Deployed at (UTC): `[TBD]`.
- [ ] If migration-related, rollback verification ran: `pnpm migrate:verify-rollback`.
      Runbook: [migration rollback verification](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/migration-rollback-verification.md).

### Verification (until green)

- [ ] All firing alerts in Alertmanager resolved.
- [ ] SLO graphs back inside budget for ≥ 15 continuous minutes:
  - RPS ≈ baseline +- 20 %  ⬜
  - p50 / p95 / p99 latency back to baseline  ⬜
  - Error rate < SLO threshold  ⬜
  - DLQ depth decreasing monotonically  ⬜
  - Soroban submit lag p95 < 60 s  ⬜
- [ ] Customer-visible symptoms confirmed cleared (status page update ⬜,
      affected customers contacted ⬜).
- [ ] **Mitigation artefacts cleaned up.**
  - Toggled feature flags restored ⬜
  - Emergency rate-limit rules removed ⬜
  - Manually-quarantined DLQ entries replayed or purged ⬜

---

## 4. Escalation matrix

If after `[ T ]` minutes of trying containment you cannot stop the
bleed — **page early.** Don't hero-solo for 2 hours then escalate.

| If SEV is | and after | escalate to | via |
| :--- | :--- | :--- | :--- |
| SEV-1 | 15 min, not contained | Backend lead + Platform on-call + Security rep | PagerDuty high-urgency |
| SEV-2 | 30 min, not contained | Backend lead | Slack + PagerDuty low-urgency |
| SEV-3 | 60 min, plateaued but no fix | Pull in relevant domain owner | Slack |

---

## 5. Post-mortem (fill in within 48 hours of resolution)

### 5.1 Impact summary

- **Start / end / MTTR** (UTC): `[YYYY-MM-DD HH:MM]` → `[YYYY-MM-DD HH:MM]` · **MTTR = [X] min**
- **User-visible impact (best estimate):**
  - Customers affected: `[TBD]` (count or % of base)
  - Failed requests / transactions: `[TBD]`
  - Data integrity impact: ⬜ none · ⬜ soft (replayable) · ⬜ hard (requires manual fix / customer contact)
- **SLO / SLA burn:** Burned `[X]` minutes of monthly error budget, `[Y]` minutes of latency budget.

### 5.2 Root cause (5 Whys)

Fill each line with a short answer; don't stop at the first "because".

1. **Why did we page?** `[e.g. PgPoolSaturated fired for 1 min > 95 %]`
2. **Why was the pool saturated?** `[e.g. query X on table Y held 12 connections for 90 s]`
3. **Why was query X slow?** `[e.g. index removed in migration Z; rollback verifier missed it because …]`
4. **Why wasn't it caught in CI / pre-prod?** `[TBD]`
5. **Why did it take T minutes to contain?** `[TBD — e.g. runbook step 4 was stale, had to re-learn command]`

### 5.3 Contributing factors (environmental, process, tooling)

- `[TBD — e.g. "Runbook linked from alert was for v1 architecture; pool config had changed"]`
- `[TBD — e.g. "Correlation IDs were not propagated across job boundary, tracing was blind for 20 min"]`

### 5.4 What went well (be specific, don't skip)

- `[TBD — e.g. "Alert fired 3 min before customer reports; right runbook opened first click"]`
- `[TBD — e.g. "Rollback command worked first try; MTTR < SLO recovery time target"]`

### 5.5 Action items (export these to tickets; OWNER + DUE DATE required)

| # | Action | Owner | Due | Status |
| :-- | :--- | :--- | :--- | :--- |
| P1 | `[TBD — e.g. "Re-add index on Y(col), deploy in next hotfix window"]` | `@` | `YYYY-MM-DD` | 🔴 open |
| P1 | `[TBD — e.g. "Fix runbook capacity-alerts.md step 4 to use new pgpool env var names"]` | `@` | `YYYY-MM-DD` | 🔴 open |
| P2 | `[TBD — e.g. "Add Prometheus test for PgPoolSaturated → runbook URL annotation (tests.yaml)"]` | `@` | `YYYY-MM-DD` | 🟡 open |
| P3 | `[TBD — e.g. "Add e2e load test that exercises query X against representative dataset size"]` | `@` | `YYYY-MM-DD` | 🟡 open |

### 5.6 Blameless note

> This post-mortem is a document of **our systems and processes**, not of
> the people on-call.  An operator following the runbook and still losing
> 45 minutes is a runbook problem, not an operator problem.  No names
> will appear in the 5-Why chain except as owners of forward action
> items.
