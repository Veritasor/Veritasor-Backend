# Dead-Letter Queue (DLQ) Poison-Pill Classifier & Quarantine Store

## Overview
Malformed webhook payloads can bounce indefinitely through the dead-letter queue (DLQ), wasting system resources and causing repeated failures during replay operations. The Poison-Pill Classifier detects repeat offenders by tracking failure fingerprints and automatically moves malformed entries into a **quarantine store**.

Quarantined entries are blocked from standard replay execution until explicitly reviewed and released by an administrator.

## Key Features

### 1. Failure Fingerprinting
When a webhook failure occurs, a deterministic failure fingerprint is generated based on the provider, payload hash, and error code:
```ts
fingerprint = sha256(provider + ":" + payloadHash + ":" + errorCode)
```

### 2. Fingerprint Collision Guard
To prevent distinct payloads or error types from colliding on the same hash fingerprint:
- The classifier verifies that the stored `payload_hash` matches the incoming payload hash.
- If a collision occurs between different payloads generating the same fingerprint hash, a salted collision-safe fingerprint is generated (`sha256(fingerprint + ":" + currentPayloadHash)`).

### 3. Quarantine Threshold Classifier
- Default threshold: `3` (configurable).
- When consecutive failures for a fingerprint/event reach or exceed the threshold, the entry is automatically transferred from `webhook_dead_letters` to `webhook_quarantine`.
- Once quarantined, any attempt to replay the event via `POST /api/v1/admin/webhooks/replay` will be rejected with HTTP status 400.

### 4. Admin Management & Release
Quarantined entries require explicit admin action:
- **List Quarantined Entries**: `GET /api/v1/admin/webhooks/quarantine` (supports `?provider=...` filter).
- **Release Quarantined Entry**: `POST /api/v1/admin/webhooks/quarantine/release`
  - Removes entry from quarantine store and resets its failure fingerprint count.
  - Generates an audit log record (`RELEASE_QUARANTINED_WEBHOOK`).
- **Purge Quarantined Entry**: `DELETE /api/v1/admin/webhooks/quarantine`
  - Permanently purges the entry from the quarantine store.

## Database Tables
- `webhook_dead_letters`: Stores active failed webhooks pending retry.
- `webhook_quarantine`: Stores quarantined poison-pill webhooks.
- `webhook_failure_fingerprints`: Tracks failure fingerprint counts and timestamps.
