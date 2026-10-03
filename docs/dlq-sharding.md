# Per-Integration DLQ Sharding & Noisy-Neighbor Isolation

## Overview
A shared Dead-Letter Queue (DLQ) stream risks noisy-neighbor issues where a single high-volume integration (e.g., a failing webhook integration) overwhelms the DLQ store and delays replay operations for other integrations.

Per-integration DLQ sharding partitions dead-letter entries and quarantined items by an `integration` shard key. Replay workers can then be scaled, rate-limited, or isolated independently per integration.

## Key Architecture & Features

### 1. Integration Sharding & Fallback
Every dead-letter entry stored in `webhook_dead_letters` and `webhook_quarantine` is tagged with an `integration` shard column.

```ts
shard = resolveIntegrationShard(provider, integration)
```
- If an explicit `integration` is supplied, it is normalized (trimmed & lowercased) and used as the shard key.
- If omitted, `provider` is used as the fallback integration shard key.
- If both `provider` and `integration` are missing or empty, the entry is assigned to the fallback shard: `'unknown'` (`UNKNOWN_INTEGRATION_SHARD`).

### 2. Independent Replay Worker per Shard
`DLQShardWorker` encapsulates a dedicated worker for a specific integration shard:

```ts
const worker = createDLQShardWorker('razorpay', async (entry) => {
  // Replay handler logic for razorpay integration
  return await processReplay(entry)
})

const result = await worker.processBatch(50)
// Returns: { processed, succeeded, failed, errors }
```

Worker benefits:
- Workers fetch and process entries isolated by `integration`.
- High-volume failures in one integration shard do not block replay workers operating on other integration shards.

### 3. Database Schema Migration
Migration `20260728_001_add_dlq_integration_shard.sql` adds:
- `integration` column to `webhook_dead_letters` and `webhook_quarantine`.
- Backfills existing rows using `provider` (or `'unknown'`).
- Creates performance indexes on `integration` columns: `idx_webhook_dead_letters_integration` and `idx_webhook_quarantine_integration`.

### 4. Admin API Endpoints
- **List Shards & Entry Counts**: `GET /api/v1/admin/webhooks/shards`
- **List Quarantined Items by Integration**: `GET /api/v1/admin/webhooks/quarantine?integration=razorpay`
