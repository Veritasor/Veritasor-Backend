# Chaos Mesh: network partition tests

Runbook for exercising Kubernetes network partitions between the backend and
its Postgres/Redis dependencies, so recovery behavior is verified rather than
assumed.

## Prerequisites

- [Chaos Mesh](https://chaos-mesh.org/) installed in the cluster (operator +
  CRDs + dashboard optional). See the [official install guide](https://chaos-mesh.org/docs/production-installation-using-helm/).
- A `veritasor-nonprod` namespace containing the backend, Postgres, and Redis
  workloads, each carrying the label `chaos-mesh.org/environment: nonprod` in
  addition to their usual `app.kubernetes.io/name` label. **This opt-in label
  is required** — the manifests in this directory will not match any pod
  without it, even inside `veritasor-nonprod`. This is deliberate
  defense-in-depth: a manifest applied to the wrong cluster/namespace by
  mistake matches zero pods instead of silently partitioning production.
- `kubectl` context pointed at the non-prod cluster.

## Manifests

| File | Effect |
|---|---|
| `network-partition-postgres.yaml` | Full (bidirectional) partition between the backend and Postgres |
| `network-partition-redis.yaml` | Full (bidirectional) partition between the backend and Redis |
| `network-partition-postgres-partial.yaml` | One-directional partition (backend → Postgres only) — the "partial partition" edge case |

All three self-heal after their `duration` (60s) elapses even if you skip the
manual cleanup step below — this bounds the blast radius if a step is missed.

## Running an experiment

1. Confirm you're pointed at the non-prod cluster:
   ```bash
   kubectl config current-context
   ```
2. Apply the experiment:
   ```bash
   kubectl apply -f ops/chaos-mesh/network-partition-postgres.yaml
   ```
3. Watch the backend's health degrade:
   ```bash
   watch -n2 'curl -fsS "http://<backend-host>/api/health?mode=deep"'
   ```
   Expect `db: "down"` (or `redis: "down"`) and overall `status` to drop to
   `degraded` or `unhealthy` while the partition is active.
4. Let the experiment run its full `duration`, or remove it early:
   ```bash
   kubectl delete -f ops/chaos-mesh/network-partition-postgres.yaml
   ```
5. **Assert recovery timing** with the verification script:
   ```bash
   HEALTH_URL=http://<backend-host>/api/health \
   RECOVERY_TIMEOUT_SECONDS=30 \
     ./ops/chaos-mesh/verify-recovery.sh
   ```
   This polls `/api/health?mode=deep` every 2s and fails (non-zero exit) if
   `status` doesn't return to `ok` within the timeout — turning "did it
   recover?" into a pass/fail check instead of an eyeballed dashboard.

Repeat for `network-partition-redis.yaml` and the `-partial.yaml` variant.

## Recovery-time expectations

- Postgres uses `pg` pool reconnection with the pool's own timeout
  (`PG_CONN_TIMEOUT_MS`, default 2s) — expect recovery within a few seconds
  of the partition healing.
- Redis connections use `ioredis`'s built-in reconnect-with-backoff — expect
  recovery within its configured retry window.
- If `verify-recovery.sh` reports a timeout, that is itself a signal worth
  investigating (e.g. a connection pool not retrying, or a cached "down"
  state not being re-checked) — it is not expected to fail under normal
  operation.

## Cleanup

`kubectl get networkchaos -n veritasor-nonprod` should show nothing once an
experiment's `duration` has elapsed and it has healed. If an experiment is
still listed as active longer than its `duration` plus a few seconds, delete
it manually and investigate — that is not expected behavior.
