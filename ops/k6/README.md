# k6 peak attestation scenarios

This directory codifies the nightly peak-load suite for `POST` and `GET` traffic against `/api/v1/attestations`.

## What is covered

- `steady_state`: constant arrival rate to validate baseline latency and error budget.
- `spike`: short burst ramp to catch queueing and cold-path regressions.
- `soak`: long-running constant load to surface leaks and latency creep.
- `breakpoint`: rising arrival rate that makes the saturation point visible in the k6 summary and Grafana dashboard.

All scenarios export the same SLO thresholds:

- `p95 < 300ms`
- `error rate < 0.1%`

## Local run

Use a dedicated perf tenant. The default write ratio is `1`, so the script creates attestation rows with synthetic periods unless you override it.

```bash
K6_BASE_URL=http://127.0.0.1:3000 \
K6_AUTH_TOKEN=your-bearer-token \
K6_ATT_RUN_ID=local-dev \
K6_ATT_WRITE_RATIO=1 \
k6 run ops/k6/peak-attestation.js
```

The script keeps `submit=false` by default so the load stays on the API and database instead of sending on-chain Soroban transactions.

## Useful overrides

- `K6_ATT_WRITE_RATIO=0` makes the suite read-only.
- `K6_ATT_WRITE_RATIO=0.5` runs a mixed list/submit workload.
- `K6_ATT_SUBMIT_ON_CHAIN=true` enables live Soroban submissions.
- `K6_ATT_SCENARIO_GAP_SEC=5` shortens gaps for faster local iteration.
- `K6_ATT_SOAK_DURATION_SEC=300` reduces soak time for ad hoc checks.

## Grafana

Import [`ops/k6/grafana/peak-attestation-dashboard.json`](./grafana/peak-attestation-dashboard.json) into Grafana.

The dashboard expects k6 metrics written through Prometheus remote write with:

```bash
K6_PROMETHEUS_RW_TREND_STATS=p(95),p(99),avg,max
```

That emits the `k6_http_req_duration_p95` metric used by the latency panels.

## Nightly workflow

`.github/workflows/nightly-k6-attestations.yml` runs the suite nightly and on manual dispatch. Configure these repository secrets before enabling the job:

- `K6_BASE_URL`
- `K6_AUTH_TOKEN`
- `K6_PROMETHEUS_RW_SERVER_URL` if you want Grafana-backed time series
- `K6_PROMETHEUS_RW_USERNAME` and `K6_PROMETHEUS_RW_PASSWORD` when the remote-write endpoint uses basic auth
- `K6_PROMETHEUS_RW_BEARER_TOKEN` when the remote-write endpoint uses bearer auth
