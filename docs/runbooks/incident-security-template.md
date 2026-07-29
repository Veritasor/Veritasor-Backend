# Incident Template — Security Incident

> **When to use.** Suspected credential leak, auth bypass, audit-log
> anomalies, webhook-replay attack, mTLS / SPIFFE trust boundary concern,
> signup abuse, or any suspected compromise of the security envelope.
>
> Do NOT investigate alone.  Per company security policy, any suspected
> security event MUST page the security on-call within 15 minutes of
> detection even if you are "not sure yet".  Err on the side of paging.

Companion threat models & security docs:
- [Signup abuse threat model](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/THREAT_MODEL_SIGNUP_ABUSE.md)
- [Attestation submit threat model](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/threat-model-attestation-submit.md)
- [Idempotency / replay threat model](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/threat-model-idempotency.md)
- [Optional auth threat model](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/threat-model-optional-auth.md)
- [Revenue report schema threat model](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/threat-model-revenue-report-schema.md)
- [Security provenance / audit logs](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/security-provenance.md)
- [SLSA provenance](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/slsa-provenance.md)
- [SPIFFE / SVID docs](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/spiffe-svid.md)
- [mTLS OCSP / revocation](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/mtls-ocsp.md)
- [Key rotation / secret scram](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/runbooks/key-rotation-secret-scram.md)
- [Business authorization boundary checks](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/business-authorization-boundary-checks.md)

---

## 1. Header (fill in first — do not wait)

| Field | Value |
| :--- | :--- |
| SEV (initial guess; security over-ranks functional) | ⬜ SEV-1 (confirmed compromise) · ⬜ SEV-2 (strong suspicion / data exposed) · ⬜ SEV-3 (weak signal / no data exposed yet) |
| Incident commander | `@[TBD]` |
| Security lead on-call (paged within 15 min?) | ⬜ yes · ⬜ NO → **PAGE NOW** (see §3 Escalation) |
| Legal / privacy on-call notified (if PII involved) | ⬜ yes · ⬜ no · ⬜ N/A |
| Reported by (internal alert / user / third party) | |
| Detection timestamp (UTC) | `[ ]` |
| Sensitive data suspected exposed (tick all) | ⬜ auth tokens · ⬜ PII · ⬜ financial data · ⬜ signing keys · ⬜ webhook secrets · ⬜ env vars / DB creds · ⬜ other: |
| Evidence frozen yet? | ⬜ YES · ⬜ NO → **do not delete logs / rotate pods until §2 Evidence** |
| Status page / customer comms needed? | ⬜ SEV-1 required within 24 h · ⬜ TBD · ⬜ No |

## 1.1 Dashboards + panels

| Tool / panel | Link |
| :--- | :--- |
| Security audit dashboard (auth, admin, key events) | `https://grafana/d/security-audit?from=now-24h&to=now` |
| Audit log API (admin) | `GET /api/admin/audit-logs?from=[start]&event_in=SECURITY_*` · [docs](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/security-provenance.md) |
| Auth / signup abuse dashboard | `https://grafana/d/signup-abuse?from=now-24h&to=now` · [threat model](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/THREAT_MODEL_SIGNUP_ABUSE.md) |
| Idempotency replay attempts | `https://grafana/d/veritasor-backend?viewPanel=60&from=now-24h&to=now` · [threat model](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/threat-model-idempotency.md) |
| SPIFFE / SVID TTL + OCSP | `https://grafana/d/spiffe-mtls?from=now-24h&to=now` · [SPIFFE](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/spiffe-svid.md) · [OCSP](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/mtls-ocsp.md) |
| Webhook signature mismatches | `https://grafana/d/webhook-decay?viewPanel=15` · [negotiation](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/webhook-signature-negotiation.md) |
| Business authorization boundary crosses | `https://grafana/d/veritasor-backend?viewPanel=70` · [docs](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/business-authorization-boundary-checks.md) |
| Secret / config change audit log | `https://grafana/d/security-audit?viewPanel=20` |

---

## 2. Evidence (first 30 min — preserve before changing anything)

> ⚠️ **Preservation over remediation first.** Rotating a secret or killing
> a pod *before* you snapshot evidence destroys forensic material.
> Unless data is actively being exfiltrated (§2.4), snapshot first.

### 2.1 Log snapshots (export to incident ticket — do NOT paste raw PII)

- [ ] App logs: last 24 h, `| json | event=~".*"` in Loki. Save as JSONL with label `INC-[id] evidence`
  - [ ] auth events
  - [ ] admin events
  - [ ] idempotency events (replay hit / miss)
  - [ ] integration OAuth token refresh events
- [ ] Audit log entries for suspicious `actor_id` + IP:
  ```bash
  curl -H "Authorization: Bearer $SEC_ADMIN_TOKEN" \
    "https://api.prod/admin/audit-logs?from=[T-24h]&actor_id=[suspect]&format=jsonl" \
    > INC-ID-audit-actor-$(date +%s).jsonl
  ```
- [ ] Webhook quarantine rows (if webhook-replay suspected):
  ```sql
  SELECT id, event_id, provider, created_at, updated_at, failure_fingerprint,
         payload_hash, error_code
  FROM webhook_quarantine WHERE created_at > NOW() - INTERVAL '7 days'
  ORDER BY created_at DESC LIMIT 200;
  ```
- [ ] mTLS / SVID cert serial + OCSP responses seen (if boundary crossing):
  SPIFFE SVID docs to investigate.

### 2.2 DB forensic queries (append-only, no writes except audit log entries)

- [ ] Auth: anomalous login / token-issue rates:
  ```sql
  SELECT date_trunc('minute', created_at) AS m,
         actor_id, COUNT(*),
         array_agg(DISTINCT event_name) AS evs
  FROM audit_logs
  WHERE created_at > NOW() - INTERVAL '24 hours'
        AND event_name IN ('AUTH_ISSUE_TOKEN','AUTH_REFRESH','AUTH_PASSWORD_RESET')
  GROUP BY 1,2 HAVING COUNT(*) > 10
  ORDER BY m DESC;
  ```
- [ ] Signup abuse (per IP / device fingerprint):
  [THREAT_MODEL_SIGNUP_ABUSE.md queries](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/THREAT_MODEL_SIGNUP_ABUSE.md)
- [ ] Cross-business-tenant access attempts:
  [business-authorization-boundary-checks.md](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/business-authorization-boundary-checks.md)
- [ ] Idempotency replay patterns:
  ```sql
  SELECT idempotency_key, COUNT(*) AS attempts, MIN(created_at), MAX(created_at)
  FROM audit_logs
  WHERE event_name = 'IDEMPOTENCY_HIT' OR event_name = 'IDEMPOTENCY_REPLAY_ATTEMPT'
  GROUP BY 1 HAVING COUNT(*) > 3
  ORDER BY attempts DESC LIMIT 50;
  ```

### 2.3 Credential / secret exposure check

- [ ] Env dump against running pod (**copy to evidence only — scrub before sharing ticket**):
  ```
  kubectl exec -ti [pod] -- env | grep -E 'KEY|SECRET|PASS|TOKEN|SALT|AUTH' | awk -F= '{print $1"="$2}'
  ```
  ⚠️ Never paste real secrets into tickets; mask them as `REDACTED_sha256(prefix8)`.
- [ ] Any values appearing in GitHub / logs / dashboards? ⬜ yes → **key-rotation runbook NOW**:
  → [key-rotation-secret-scram.md](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/runbooks/key-rotation-secret-scram.md)

### 2.4 If active exfiltration suspected — STOP BLEED (before evidence capture)

- [ ] ⬜ Revoke affected JWT signing key (publish new `kid`, rotate KMS).
- [ ] ⬜ Revoke integration OAuth tokens for impacted tenants.
- [ ] ⬜ WAF rule or IP-ban the suspicious source IPs (only if pattern is clear).
- [ ] ⬜ Rotate the database master credentials.  **Only do this after
      confirming incident scope.**

---

## 3. Escalation matrix — SECURITY ESCALATES FASTER THAN ANY OTHER INCIDENT

| If | Within | Page | Via |
| :--- | :--- | :--- | :--- |
| **Any** suspected security incident | 15 min from detection | Security on-call + IC + your skip-level | PagerDuty HIGH (even at 2 AM) |
| Data exfiltration confirmed or highly likely | 5 min | Security lead + Legal + VP Eng + CISO | Bridge + PagerDuty SEV-PAGE |
| PII / financial data suspected exposed | 15 min | Security on-call + Privacy/Legal rep | PagerDuty HIGH |
| Credentials leaked (secrets in logs/GitHub) | 5 min | Security on-call — trigger secret scram runbook immediately | PagerDuty HIGH |

---

## 4. Containment → Remediation → Verification (standard SEV playbook)

Follow the [generic SEV template](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/runbooks/incident-sev-template.md) §3 checklist, but:

- **Audit everything you do.** Every remediation action gets an audit-log
  entry (event names: `SEC_REMEDIATION_*`).
- **Never share a raw secret or PII in the incident ticket.** Mask or
  hash, keep the actual values in a secured escrow folder per policy.

---

## 5. Post-mortem — security format (extra fields)

| Field | Fill in |
| :--- | :--- |
| Confirmed impact — worst-case data exposed | |
| Affected tenant / user count | |
| Regulatory reporting required (GDPR/HIPAA/etc.) | ⬜ yes · ⬜ no · ⬜ assess within 72 h |
| Customer notification required | ⬜ yes (deadline: `[date]`) · ⬜ no |
| Root cause category | ⬜ misconfiguration · ⬜ authz boundary gap · ⬜ weak/leaked credential · ⬜ design flaw · ⬜ supply chain · ⬜ other |
| 5 Whys | 1. 2. 3. 4. 5. |
| Action items (P1/P2/P3 + owner + due) | [as per SEV template §5.5] |
| Security quarterly audit: gap closed in? | ⬜ next audit · ⬜ sooner (date: `[ ]`) |
