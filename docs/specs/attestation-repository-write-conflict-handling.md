# Attestation Repository Write Conflict Handling - Specification

## Overview

This document describes the write conflict handling mechanism implemented in the AttestationRepository to ensure reliable and secure data operations when handling concurrent writes to attestation records.

## Background

The attestation system allows businesses to create blockchain attestations for specific time periods. Without proper conflict handling, the following issues could occur:

1. **Duplicate Records**: Multiple simultaneous requests could create duplicate attestations for the same business + period combination
2. **Lost Updates**: Concurrent updates to the same record could overwrite each other without detection
3. **Data Corruption**: Race conditions during updates could lead to inconsistent state

## Implementation Details

### 1. Conflict Detection Types

The implementation defines three main conflict types via `ConflictErrorType`:

| Type | Code | Description | HTTP Status |
|------|------|-------------|-------------|
| `CONFLICT_TYPE_DUPLICATE` | DUPLICATE | BusinessId + period already exists | 409 |
| `CONFLICT_TYPE_VERSION` | VERSION_MISMATCH | Record was modified by another process | 409 |
| `CONFLICT_TYPE_FOREIGN_KEY` | FOREIGN_KEY_VIOLATION | Referenced business doesn't exist | 404 |

### 2. Database Schema Changes

A `version` column has been added to the attestations table for optimistic locking:

```sql
version INTEGER NOT NULL DEFAULT 1
```

Each update increments this version, allowing detection of concurrent modifications.

### 3. New Functions

#### `create(client, data)`
- Creates a new attestation
- Throws `ConflictError` with `CONFLICT_TYPE_DUPLICATE` on unique constraint violation
- Throws `ConflictError` with `CONFLICT_TYPE_FOREIGN_KEY` on FK violation
- Sets initial version to 1

#### `updateStatus(client, id, status, expectedVersion?)`
- Updates attestation status with optional optimistic locking
- If `expectedVersion` provided, throws `ConflictError` with `CONFLICT_TYPE_VERSION` on version mismatch
- Increments version on each update

#### `update(client, id, updates, expectedVersion?)`
- Updates attestation fields with optional optimistic locking
- Supports updating: `status`, `merkleRoot`, `txHash`
- Throws `ConflictError` with `CONFLICT_TYPE_VERSION` on version mismatch

#### `getByBusinessAndPeriod(client, businessId, period)`
- Retrieves attestation by business + period combination
- Useful for pre-check before creating new records

#### `createWithConflictCheck(client, data, options)`
- Advanced create with conflict resolution options:
  - `returnExistingOnConflict`: Return existing record instead of throwing
  - `retryOnConflict`: Retry creation on transient conflicts
  - `maxRetries`: Maximum retry attempts

#### `remove(client, id)`
- Deletes an attestation record
- Returns boolean indicating success/failure

## Security Assumptions

1. **Version Field Integrity**: The version field is managed exclusively by the database via triggers or application logic - clients cannot modify it directly
2. **Unique Constraint**: The unique constraint on `(business_id, period)` is enforced at the database level, providing a secondary line of defense
3. **Optimistic Locking**: Version-based optimistic locking assumes conflicts are rare; for high-contention scenarios, pessimistic locking (SELECT FOR UPDATE) may be more appropriate
4. **Idempotency**: The system assumes idempotent operations are safe to retry

## Behavior Under Write Conflicts

### Scenario 1: Concurrent Creates (Same Business + Period)

```
Request A: CREATE (business-1, 2025-01)
Request B: CREATE (business-1, 2025-01)

Result:
- First request succeeds (ID: att-1, version: 1)
- Second request fails with ConflictError(CONFLICT_TYPE_DUPLICATE)
```

### Scenario 2: Concurrent Updates (Version Mismatch)

```
Request A: UPDATE status='confirmed', version=1
Request B: UPDATE status='failed', version=1

Assume current version is 1:
- Request A succeeds (new version: 2)
- Request B fails with ConflictError(CONFLICT_TYPE_VERSION)
  - Details: { expectedVersion: 1, currentVersion: 2 }
```

### Scenario 3: Read-Modify-Write with Conflict Detection

```typescript
// Get current state
const attestation = await getById(client, id);

// Check version before update
const updated = await updateStatus(client, attestation.id, 'confirmed', attestation.version);

if (updated === null) {
  // Version conflict - another process modified the record
  throw new ConflictError(...);
}
```

## Testing Coverage

The test suite covers:

1. **Normal Operations**:
   - Create attestation
   - Retrieve by ID and by business+period
   - Update status and fields
   - Delete attestation
   - List attestations with filters

2. **Failure Scenarios**:
   - Duplicate businessId + period (unique constraint)
   - Invalid businessId (foreign key constraint)
   - Version mismatch (optimistic locking)
   - Invalid status values
   - Non-existent records

3. **Edge Cases**:
   - Simultaneous create attempts
   - Multiple updates incrementing version
   - Concurrent modification detection
   - Retry logic with conflict resolution

## API Usage Examples

### Basic Create with Conflict Detection

```typescript
try {
  const attestation = await create(client, {
    businessId: 'business-123',
    period: '2025-01',
    merkleRoot: '0xabc...',
    txHash: '0xdef...',
    status: 'pending'
  });
} catch (error) {
  if (error instanceof ConflictError) {
    switch (error.type) {
      case ConflictErrorType.CONFLICT_TYPE_DUPLICATE:
        // Handle duplicate
        break;
      case ConflictErrorType.CONFLICT_TYPE_FOREIGN_KEY:
        // Handle invalid business
        break;
    }
  }
}
```

### Optimistic Locking Update

```typescript
const current = await getById(client, attestationId);
const updated = await updateStatus(client, attestationId, 'confirmed', current.version);

if (!updated) {
  // Handle conflict - fetch latest and retry
  const latest = await getById(client, attestationId);
  // ... retry logic
}
```

### Create with Auto-Conflict Resolution

```typescript
const attestation = await createWithConflictCheck(client, {
  businessId: 'business-123',
  period: '2025-01',
  merkleRoot: '0xabc...',
  txHash: '0xdef...',
  status: 'pending'
}, {
  returnExistingOnConflict: true,  // Return existing instead of throwing
  retryOnConflict: true,             // Retry on transient conflicts
  maxRetries: 3
});
```

## Future Considerations

1. **Pessimistic Locking**: For high-contention scenarios, implement SELECT FOR UPDATE
2. **Retry Backoff**: Add exponential backoff for retry logic
3. **Metrics**: Add conflict detection metrics for monitoring
4. **Distributed Locks**: For multi-instance deployments, consider distributed locking

## Related Files

- `src/repositories/attestationRepository.ts` - Repository implementation
- `src/types/attestation.ts` - Type definitions and ConflictError
- `src/db/migrations/20260225_001_create_attestations_table.sql` - Schema changes
- `tests/unit/repositories/attestationRepository.test.ts` - Unit tests