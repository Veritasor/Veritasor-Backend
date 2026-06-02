# Anomaly Threshold Regression Fixtures

## Overview
Labeled synthetic revenue batch fixtures for regression testing anomaly detection thresholds in `src/services/revenue/anomalyDetection.ts`. Ensures tuning changes do not silently change recall.

## Threshold Configuration Snapshot
```
DROP_THRESHOLD = 0.4   (40% fractional drop → unusual_drop)
SPIKE_THRESHOLD = 3.0  (300% fractional rise → unusual_spike)
MIN_DATA_POINTS = 2    (minimum series length)
DEFAULT_SIGMA_MULTIPLIER = 2
DEFAULT_ROLLING_WINDOW = 3
```

## Primary Fixtures

### 1. Clean Baseline — MUST NOT FLAG
**File:** `tests/fixtures/revenue/anomalyBatches.ts`
**Description:** Stable revenue over 12 months.
**Series:** 12 entries of $10,000 each.
**Expected:** `flag: "ok"`, `score: 0`

### 2. Refund Spike — MUST FLAG
**Description:** Sharp revenue drop due to large negative (refund).
**Series:** 9 stable months, then -$45,000.
**Expected:** `flag: "unusual_drop"`, `score > 0.4`

### 3. Currency Swap — MUST NOT FLAG
**Description:** Stable amounts across periods (currency changes don't affect detection).
**Expected:** `flag: "ok"`

### 4. Gradual Drift — MUST NOT FLAG
**Description:** Slow 5% decline each month (below 40% threshold).
**Expected:** `flag: "ok"`

## Edge Case Fixtures

### 5. Refund Spike Just Under Threshold — MUST NOT FLAG
**Series:** $10,000 → $6,100 (39% drop)
**Expected:** `flag: "ok"`, `score: 0`

### 6. Baseline With Sparse Data — MUST RETURN insufficient_data
**Series:** Single entry: $10,000
**Expected:** `flag: "insufficient_data"`, `score: 0`

### 7. All-Zero Batch — MUST NOT FLAG
**Series:** $0 for 5 months
**Expected:** `flag: "ok"` — no valid baseline for comparison

### 8. Sharp Spike (Boundary) — MUST FLAG
**Series:** $10,000 → $40,000 (+300% = threshold boundary)
**Expected:** `flag: "unusual_spike"`

### 9. Spike Under Threshold — MUST NOT FLAG
**Series:** $10,000 → $39,000 (+290% = just under)
**Expected:** `flag: "ok"`

### 10. Sustained Drop — MUST FLAG
**Series:** 3 stable months, then $4,000 (60% drop)
**Expected:** `flag: "unusual_drop"`

## Files Created
- `tests/fixtures/anomalyThresholds.md` — This documentation
- `tests/fixtures/revenue/anomalyBatches.ts` — Labeled synthetic batches
- `tests/unit/services/revenue/anomalyThresholds.test.ts` — Regression assertions

## Test Output
```
✓ 185 tests passed (all revenue tests including 19 new anomaly threshold tests)
```

Run:
```bash
npm test -- tests/unit/services/revenue/anomalyThresholds.test.ts
```