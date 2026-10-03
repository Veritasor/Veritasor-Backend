# Incident Template — Deployment / Release Incident

> **When to use.** Bad deploy, stuck rollout, flaky health checks, readiness
> probe failures correlating with a release tag.  Any incident where the
> fastest containment is `rollback`.

Related:
- [Deployment runbook](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/runbooks/deployment-rollout-rollback.md)
- [Migration rollback verifier (CI)](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/migration-rollback-verification.md)
- [Migration timeouts (statement_timeout caps)](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/migration-timeouts.md)

---

## 1. Header

| Field | Value |
| :--- | :--- |
| SEV | |
| Release / version tag | `vX.Y.Z` · commit SHA `[ ]` |
| Deployed environment | ⬜ prod · ⬜ staging · ⬜ canary shard: `[ ]` |
| Started (UTC) | `[ ]` (when deploy began) |
| Detecting alert | `[alert name + link]` |
| Time from deploy → page | `[ ]` min |
| Rollback candidate SHA (previous good) | `[sha of prior release]` |

## 1.1 Dashboards — OPEN THESE NOW

| Panel | Grafana deep link |
| :--- | :--- |
| Deploy + SLO burn correlation (annotations overlay) | `https://grafana/d/veritasor-backend?from=now-6h&to=now&annotations=deploy` |
| Pod ready / restart count per deployment | `https://grafana/d/k8s-workload?from=now-1h&to=now` |
| Liveness / readiness probe failure rate | `https://grafana/d/k8s-workload?viewPanel=11` |
| Error rate per pod (isolate new vs old replicaset) | `https://grafana/d/veritasor-backend?viewPanel=9&var-pod=~new-rs-*` |
| CI deploy workflow logs | `https://github.com/veritasor/backend/actions/runs/[ID]` |

---

## 2. Timeline

| UTC | Who | Action | Result

---

## 3. Rollback decision tree — answer in 5 minutes

> ⚠️ Rule: **When in doubt, roll back.** You can always re-deploy the same
> SHA again after diagnosis.  Do not spend 20 minutes debugging in prod
> while user-visible errors accumulate.

Ask these questions *quickly*; if **any** answer is YES → ROLLBACK NOW:

| Question | Y/N | Evidence |
| :--- | :---: | :--- |
| User-visible errors up compared to 15 min pre-deploy? | | ⬜ error % X→Y  ·  ⬜ specific endpoint `[PATH]` 5xx |
| p95 / p99 latency crossed SLO? | | ⬜ latency graph shows sustained rise after deploy |
| Liveness / readiness probes restarting pods? | | ⬜ restart count > 0 on new replicaset · crash loop? |
| Migration failed / stuck > SLOW_QUERY_MS? | | ⬜ `pg_stat_activity` shows query from migration `[name]` |
| DLQ depth / Soroban lag / any critical alert firing? | | ⬜ alert name(s): `[ ]` |

**Decision: ⬜ ROLLBACK IMMEDIATELY · ⬜ HOLD (investigate 10 min window)**

---

## 4. If ROLLBACK (do this, in order)

### 4.1 Initiate rollback

- [ ] Execute rollback command (paste exact):
  ```
  [paste kubectl rollout undo / argo rollback / CI "rollback release" action URL]
  ```
- [ ] Rollback started at `[UTC]` · expected duration `[2–8 min]`
- [ ] **Status page update** (if SEV-2+): posted `[URL]`

### 4.2 While rollback is rolling

- [ ] Watch pod count: old replicaset = `[N]` pods → `[N]` · new = `[N]` → 0.
- [ ] Watch error rate curve — should inflect down within 1 min of old pods becoming Ready.
- [ ] If a migration *already ran successfully forwards* AND the old code
      is incompatible with the new schema → **migration DOWN rollback required**.
  - Run rollback verifier against scratch first:
    ```bash
    MIGRATION_VERIFY_FORCE=true DATABASE_URL=[scratch] pnpm migrate:verify-rollback --only=[version]
    ```
  - Then run down migration (carefully, statement_timeout set):
    ```bash
    pnpm migrate down -- --version [version]
    ```

### 4.3 Post-rollback verification checklist

- [ ] `kubectl rollout status` reports SUCCESS (or equivalent).
- [ ] Error rate back to ≤ pre-deploy baseline +- 10 % for 10 min.
- [ ] p95 / p99 latency back to baseline.
- [ ] All critical alerts resolved.
- [ ] **If migration was rolled back:** check `schema_migrations` table —
      version removed.  ⬜ yes
- [ ] Status page: marked resolved / monitoring.

---

## 5. If HOLD (10-minute investigation window)

> Only pick this path if NO customer-visible symptoms AND the suspected
> cause is noise (thrashing probes, single bad pod, single tenant).  Keep
> a tab open on the rollback button; if symptoms appear at any point,
> flip immediately to §4.

- [ ] Capture 2–3 crash / restart pod logs:
  ```
  kubectl logs --previous deploy/[name] -c app | tail -n 200
  ```
  Paste tail:
  ```
  ```
- [ ] Readiness probe: `GET /health/ready` against 1 new pod:
  ```
  kubectl exec -ti [pod] -- curl -sS http://127.0.0.1:PORT/health/ready
  ```
  Response:
  ```
  ```
- [ ] Startup dependency readiness checks — which component failing?
  Docs: [app-startup-dependency-readiness-checks.md spec](file:///C:/Users/Admin/Documents/Drips/Veritasor-Backend/docs/specs/app-startup-dependency-readiness-checks.md)
- [ ] Suspected root cause 1-liner: `[TBD]`
- [ ] Fix patch PR: `[#TBD]` · SHA `[ ]` · re-deployed at `[UTC]`

---

## 6. Post-mortem

- MTTR (deploy → rollback complete) = `[min]`.  Target: ≤ 15 min for SEV-1.
- Could rollback have happened earlier (what delayed it)? `[TBD]`
- 5 Whys:
  1. Page fired because: `[ ]`
  2. Deploy went to prod because: `[ ]`
  3. CI / canary didn't catch because: `[ ]`
  4. Rollback took X min because: `[ ]`
  5. Because: `[ ]`
- Action items:
  - P1: `[TBD]` → `@owner` · due `YYYY-MM-DD`
  - P1: `[TBD]` → `@owner` · due `YYYY-MM-DD`
  - P2: `[TBD]` → `@owner` · due `YYYY-MM-DD`
