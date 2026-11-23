# ops/soak – 24-hour memory-leak soak test

This directory contains the infrastructure for the nightly 24-hour soak test that
detects long-lived memory leaks in the Node.js backend.

## Overview

Long-running memory leaks only surface after hours. The soak suite:

1. Drives sustained HTTP traffic against `/api/v1/health` and
   `/api/v1/attestations` using k6 (`ops/k6/soak-memory.js`).
2. Captures V8 heap snapshots every hour via `heap-sampler.ts`, which runs as a
   sidecar process alongside the target server.
3. After the run, diffs retained-size between the first post-warm-up snapshot
   and the final snapshot. Growth above **50 MB** (configurable) is flagged as a
   leak and fails the CI step.

## Files

| File | Purpose |
|------|---------|
| `ops/soak/heap-sampler.ts` | Node.js sidecar – captures heap snapshots and analyses growth |
| `ops/k6/soak-memory.js` | k6 test script – drives the HTTP load |
| `.github/workflows/nightly-soak.yml` | Scheduled GHA workflow |
| `tests/unit/ops/heap-sampler.test.ts` | Unit tests for the sampler logic |

## How the leak detector works

```
Time ────────────────────────────────────────────────────────────────────────►
  │   t=0         t=1h         t=2h   …   t=23h        t=24h
  │   snapshot-0  snapshot-1  snapshot-2     snapshot-N  snapshot-final
  │   (baseline)  (warm-up)   (post-WU)                 (final)
  │
  │   Growth = retained(final) − retained(snapshot-2)
  │
  │   If Growth > LEAK_THRESHOLD_MB → CI step fails with exit 1
```

**False-positive guard:** The first two snapshots are skipped when computing
growth. This prevents one-time lazy-initialisation spikes (module caches,
compiled regex, etc.) from triggering false alarms.

## Local run

### Prerequisites

- Node.js 22+ with `--expose-gc` support
- k6 v0.50+
- The application running locally (or pointing at a staging environment)

### Start the heap sampler

```bash
# From the repo root
node --expose-gc \
  ./node_modules/.bin/tsx ops/soak/heap-sampler.ts \
  --interval 60 \
  --output   ops/k6/results \
  --threshold 50
```

### Run a short soak (10 minutes for local verification)

```bash
K6_BASE_URL=http://127.0.0.1:3000 \
K6_AUTH_TOKEN=your-bearer-token \
SOAK_DURATION_H=0.17 \
SOAK_VUS=2 \
k6 run ops/k6/soak-memory.js
```

### Read the report

```bash
cat ops/k6/results/soak-heap-report.json
```

## CI workflow

`.github/workflows/nightly-soak.yml` runs at **02:00 UTC** every night and can be
triggered manually via `workflow_dispatch`.

### Required secrets

| Secret | Description |
|--------|-------------|
| `K6_BASE_URL` | Base URL of the target environment |
| `K6_AUTH_TOKEN` | Bearer token for authenticated endpoints |

### Optional inputs (workflow_dispatch)

| Input | Default | Description |
|-------|---------|-------------|
| `duration_h` | `24` | Soak duration in hours |
| `vus` | `10` | Number of k6 virtual users |
| `heap_interval_s` | `3600` | Seconds between heap snapshots |
| `leak_threshold_mb` | `50` | Retained-heap growth threshold in MB |

### Artefacts

Uploaded to `soak-results-<run_id>` (retained 14 days):

- `soak-summary.json` – k6 summary with all custom metrics
- `soak-heap-report.json` – heap-diff analysis report
- `*.heapsnapshot` – raw V8 heap snapshots for further analysis with Chrome DevTools

## Interpreting results

### soak-heap-report.json

```json
{
  "generatedAt": "2026-07-29T02:30:00.000Z",
  "intervalSeconds": 3600,
  "thresholdMB": 50,
  "snapshots": [
    { "seq": 0, "file": "heap-...-0.heapsnapshot", "takenAt": "...", "retainedMB": "250.00" },
    { "seq": 1, "file": "heap-...-1.heapsnapshot", "takenAt": "...", "retainedMB": "260.00" },
    ...
  ],
  "deltaBytes": 8388608,
  "deltaMB": 8.0,
  "leakDetected": false,
  "snapCount": 26,
  "message": "No significant leak detected (growth 8.0 MB, threshold 50 MB)."
}
```

### k6 custom metrics

| Metric | Description |
|--------|-------------|
| `soak_iteration_duration` | End-to-end duration of one health + attestation-list pair |
| `soak_error_rate` | Fraction of iterations that returned a non-2xx response |
| `soak_iterations_total` | Total iterations completed during the run |

### Thresholds

| Threshold | Value |
|-----------|-------|
| `soak_error_rate` | < 1 % |
| `soak_iteration_duration p(99)` | < 2 s |
| `http_req_duration p(95)` | < 1.5 s |
| `http_req_failed` | < 1 % |

## Deep-dive with Chrome DevTools

1. Download a `.heapsnapshot` file from the workflow artefacts.
2. Open Chrome DevTools → Memory tab → Load snapshot.
3. Compare `heap-*-2.heapsnapshot` (baseline) with `heap-*-final.heapsnapshot`
   using the **Comparison** view to identify retained object types.
