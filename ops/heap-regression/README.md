# Heap regression soak

Short memory-pressure soak that snapshots heap usage and diffs against a stored baseline to catch memory regressions early.

## How it works

1. Force GC and record baseline memory.
2. Allocate `ALLOCATION_STEPS` batches of `ALLOCATION_SIZE_MB` each.
3. Track peak heap used during pressure.
4. Release all references, force GC, measure post-release heap.
5. **Check mode:** Compare post-release heap against stored baseline. Fail if delta exceeds `REGRESSION_THRESHOLD_MB`.
6. **Update mode:** Write the new measurements as baseline for future runs.

## Local run

```bash
# Check against existing baseline (fails if threshold exceeded)
node --expose-gc --import tsx ops/heap-regression/soak.ts

# Bootstrap or update baseline
HEAP_REGRESSION_UPDATE_BASELINE=true node --expose-gc --import tsx ops/heap-regression/soak.ts

# Tune allocation
ALLOCATION_SIZE_MB=20 ALLOCATION_STEPS=3 node --expose-gc --import tsx ops/heap-regression/soak.ts
```

## CI

The `heap-regression-check.yml` workflow runs on every push/PR to `main`. On failure it writes a `*.heapsnapshot` artifact for debugging.

## Updating the baseline

Baseline is a committed JSON file at `ops/heap-regression/baseline.json`. Update it by:

1. Running with `HEAP_REGRESSION_UPDATE_BASELINE=true` on a known-good commit.
2. Committing the updated `baseline.json`.

## Env vars

| Variable | Default | Description |
|---|---|---|
| `ALLOCATION_SIZE_MB` | 50 | MB to allocate per step |
| `ALLOCATION_STEPS` | 5 | Number of allocation steps |
| `GC_BETWEEN_STEPS` | true | Run GC between allocation steps |
| `REGRESSION_THRESHOLD_MB` | 10 | Max allowed delta from baseline |
| `HEAP_REGRESSION_UPDATE_BASELINE` | false | Write new baseline instead of checking |
