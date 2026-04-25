# Design Document: Integration Repository

## Overview

The Integration Repository provides a data access layer for managing third-party service integration records. It abstracts database operations for storing and retrieving connections to external providers such as payment processors (Stripe, Razorpay) and e-commerce platforms (Shopify).

The repository follows the standard repository pattern, providing a clean interface between the application's business logic and the database layer. It handles CRUD operations for integration records, which contain provider credentials, authentication tokens, and provider-specific metadata required for API communication.

Key design principles:
- **Separation of Concerns**: Database operations are isolated from business logic
- **Type Safety**: Strong TypeScript types for all data structures and function signatures
- **Opaque Storage**: Provider-specific data (tokens, metadata) is stored without validation, allowing flexibility for different provider requirements
- **Consistent Interface**: All operations follow predictable patterns for error handling and return values

## Architecture

### Component Structure

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                         │
│              (Services, Route Handlers)                      │
└────────────────────┬─────────────────────────────────────────┘
                     │
                     │ Function Calls
                     │
┌────────────────────▼─────────────────────────────────────────┐
│              Integration Repository                          │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  Public Interface:                                    │  │
│  │  - listByUserId(userId): Promise<Integration[]>      │  │
│  │  - create(data): Promise<Integration>                │  │
│  │  - update(userId, id, data): Promise<Integration | null> │  │
│  │  - deleteById(userId, id): Promise<boolean>          │  │
│  └───────────────────────────────────────────────────────┘  │
│                           │                                  │
│                           │ SQL Queries                      │
│                           │                                  │
│  ┌───────────────────────▼───────────────────────────────┐  │
│  │  Database Client Abstraction                         │  │
│  │  - query(sql, params)                                │  │
│  │  - Handles connection pooling                        │  │
│  │  - Manages transactions                              │  │
│  └───────────────────────────────────────────────────────┘  │
└────────────────────┬─────────────────────────────────────────┘
                     │
                     │ Database Protocol
                     │
┌────────────────────▼─────────────────────────────────────────┐
│                    Database                                  │
│              integrations table                              │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  id (uuid, primary key)                              │  │
│  │  user_id (uuid, foreign key)                         │  │
│  │  provider (varchar)                                  │  │
│  │  external_id (varchar)                               │  │
│  │  token (jsonb)                                       │  │
│  │  metadata (jsonb)                                    │  │
│  │  created_at (timestamp)                              │  │
│  │  updated_at (timestamp)                              │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Design Decisions

1. **In-Memory Implementation for Current Phase**: Following the existing codebase pattern (as seen in `userRepository.ts` and `integrations.ts`), the initial implementation will use in-memory storage with a Map-based structure. This allows the repository interface to be defined and tested without requiring database infrastructure setup. The interface is designed to be database-agnostic, enabling future migration to a real database client without changing the public API.

2. **Async Interface**: All repository methods return Promises, even though the current in-memory implementation is synchronous. This ensures the interface is compatible with future database implementations that require async operations.

3. **Opaque Token and Metadata Storage**: The repository stores `token` and `metadata` fields as opaque objects (`Record<string, any>`) without validation. This design allows different providers to store different credential structures without requiring repository changes. Validation of provider-specific data is the responsibility of the service layer.

4. **Null vs Exception for Not Found**: The `update` method returns `null` when the integration ID doesn't exist or is outside the caller's tenant scope, following the pattern established in `integrations.ts`. The `deleteById` method returns a boolean indicating success within the same caller scope. This provides callers with clear, type-safe indicators of operation outcomes without requiring try-catch blocks for expected scenarios.

5. **Tenant-Scoped Mutations**: Write operations require the owning `userId` in addition to the integration ID. This prevents cross-tenant updates or deletes when an integration ID is disclosed or guessed and keeps authorization checks enforceable at the repository boundary.

6. **No Soft Deletes**: The repository performs hard deletes, permanently removing integration records. If soft delete functionality is needed in the future, it can be added by introducing a `deleted_at` timestamp field and modifying the query logic.

## Components and Interfaces

### Integration Type

```typescript
export interface Integration {
  id: string
  userId: string
  provider: string
  externalId: string
  token: Record<string, any>
  metadata: Record<string, any>
  createdAt: string
  updatedAt: string
}
```

**Field Descriptions:**
- `id`: Unique identifier for the integration record (UUID format)
- `userId`: Reference to the user who owns this integration
- `provider`: Provider name (e.g., "stripe", "razorpay", "shopify")
- `externalId`: The unique identifier assigned by the external provider
- `token`: Authentication credentials (API keys, OAuth tokens, etc.) stored as JSON
- `metadata`: Additional provider-specific configuration data stored as JSON
- `createdAt`: ISO 8601 timestamp of record creation
- `updatedAt`: ISO 8601 timestamp of last modification

### Repository Interface

```typescript
export interface IntegrationRepository {
  listByUserId(userId: string): Promise<Integration[]>
  create(data: CreateIntegrationData): Promise<Integration>
  update(userId: string, id: string, data: UpdateIntegrationData): Promise<Integration | null>
  deleteById(userId: string, id: string): Promise<boolean>
}
```

### Input Types

```typescript
export interface CreateIntegrationData {
  userId: string
  provider: string
  externalId: string
  token: Record<string, any>
  metadata: Record<string, any>
}

export interface UpdateIntegrationData {
  token?: Record<string, any>
  metadata?: Record<string, any>
}
```

**Design Note**: The `UpdateIntegrationData` type only includes fields that can be modified after creation. The `userId`, `provider`, and `externalId` fields are immutable once set.

### Function Signatures

#### listByUserId

```typescript
async function listByUserId(userId: string): Promise<Integration[]>
```

**Purpose**: Retrieve all integration records for a specific user.

**Parameters:**
- `userId`: The unique identifier of the user

**Returns**: Array of Integration objects (empty array if no integrations exist)

**Behavior:**
- Queries the database for all records where `user_id` matches the parameter
- Returns results ordered by `created_at` descending (newest first)
- Never throws for non-existent users (returns empty array)

#### create

```typescript
async function create(data: CreateIntegrationData): Promise<Integration>
```

**Purpose**: Create a new integration record.

**Parameters:**
- `data`: Object containing all required fields for a new integration

**Returns**: The created Integration object with generated `id`, `createdAt`, and `updatedAt` fields

**Behavior:**
- Generates a new UUID for the `id` field
- Sets `createdAt` and `updatedAt` to the current timestamp
- Inserts the record into the database
- Returns the complete integration object

**Error Conditions:**
- May throw if database constraints are violated (e.g., duplicate external_id for same user/provider)

#### update

```typescript
async function update(
  userId: string,
  id: string,
  data: UpdateIntegrationData
): Promise<Integration | null>
```

**Purpose**: Update token and/or metadata for an existing integration.

**Parameters:**
- `userId`: The unique identifier of the owning user/tenant
- `id`: The unique identifier of the integration to update
- `data`: Object containing fields to update (token and/or metadata)

**Returns**: 
- The updated Integration object if the record exists inside the provided tenant scope
- `null` if no record with the given ID exists or the record belongs to a different tenant

**Behavior:**
- Updates only the fields provided in `data`
- Sets `updatedAt` to the current timestamp
- Returns the complete updated record

**Error Conditions:**
- Returns `null` for non-existent IDs (not an error condition)
- May throw if database constraints are violated

#### deleteById

```typescript
async function deleteById(userId: string, id: string): Promise<boolean>
```

**Purpose**: Permanently remove an integration record.

**Parameters:**
- `userId`: The unique identifier of the owning user/tenant
- `id`: The unique identifier of the integration to delete

**Returns**: 
- `true` if a record was deleted inside the provided tenant scope
- `false` if no record with the given ID exists or the record belongs to a different tenant

**Behavior:**
- Removes the record from the database only when the tenant scope matches
- Returns success indicator

**Error Conditions:**
- Returns `false` for non-existent IDs (not an error condition)
- May throw if database constraints prevent deletion

## Data Models

### Database Schema

The repository assumes the following table structure exists:

```sql
CREATE TABLE integrations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider VARCHAR(255) NOT NULL,
  external_id VARCHAR(255) NOT NULL,
  token JSONB NOT NULL,
  metadata JSONB NOT NULL DEFAULT '{}',
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
  UNIQUE(user_id, provider, external_id)
);

CREATE INDEX idx_integrations_user_id ON integrations(user_id);
```

**Schema Design Notes:**
- `JSONB` type for `token` and `metadata` allows flexible storage of provider-specific data
- `UNIQUE` constraint prevents duplicate connections to the same provider account
- `CASCADE` delete ensures integrations are removed when users are deleted
- Index on `user_id` optimizes the `listByUserId` query

### Column to Field Mapping

| Database Column | TypeScript Field | Type | Notes |
|----------------|------------------|------|-------|
| id | id | string | UUID format |
| user_id | userId | string | UUID format |
| provider | provider | string | Lowercase provider name |
| external_id | externalId | string | Provider-assigned ID |
| token | token | Record<string, any> | Parsed from JSONB |
| metadata | metadata | Record<string, any> | Parsed from JSONB |
| created_at | createdAt | string | ISO 8601 format |
| updated_at | updatedAt | string | ISO 8601 format |

**Naming Convention**: Database columns use snake_case, TypeScript fields use camelCase. The repository handles conversion between these conventions.

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system—essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: List Returns All and Only Matching Records

*For any* user ID and any set of integration records in the database, calling `listByUserId` with that user ID SHALL return all integration records where `userId` matches the parameter and no records where `userId` does not match.

**Validates: Requirements 1.2**

### Property 2: Create-Retrieve Round Trip Preserves Data

*For any* valid integration data (userId, provider, externalId, token, metadata), creating an integration and then retrieving it by user ID SHALL return a record where all input fields match exactly, and the record includes a generated ID and timestamps.

**Validates: Requirements 2.2, 2.4, 5.3, 5.4, 6.3**

### Property 3: Update Modifies Only Specified Fields

*For any* existing integration record and any update data (token and/or metadata), calling `update` SHALL return a record where the specified fields match the update data, unspecified updatable fields remain unchanged, and immutable fields (userId, provider, externalId, createdAt) remain unchanged.

**Validates: Requirements 3.2, 3.3, 3.4**

### Property 4: Delete Removes Record and Returns Success

*For any* existing integration ID, calling `deleteById` SHALL return `true` and subsequent calls to `listByUserId` for that integration's user SHALL not include the deleted record.

**Validates: Requirements 4.2, 4.3**

### Property 5: Operations on Non-Existent IDs Are Idempotent

*For any* non-existent integration ID, calling `update` SHALL return `null` and calling `deleteById` SHALL return `false`, and both operations SHALL not modify any existing records.

**Validates: Requirements 3.5, 4.4**

## Error Handling

### Error Categories

1. **Not Found Scenarios**
   - `listByUserId` with non-existent user: Returns empty array
   - `update` with non-existent ID: Returns `null`
   - `deleteById` with non-existent ID: Returns `false`
   - **Rationale**: These are expected scenarios, not errors. Type-safe return values allow callers to handle them without try-catch blocks.

2. **Constraint Violations**
   - Duplicate integration (same user, provider, external_id): Throws error
   - Foreign key violation (non-existent user_id): Throws error
   - **Rationale**: These indicate programming errors or race conditions that should be handled by the caller.

3. **Invalid Input**
   - Empty or invalid UUIDs: Throws error
   - Missing required fields: TypeScript prevents at compile time
   - **Rationale**: Input validation is enforced by TypeScript types and runtime checks.

4. **Database Errors**
   - Connection failures: Throws error
   - Query timeouts: Throws error
   - Transaction conflicts: Throws error
   - **Rationale**: Infrastructure errors should propagate to allow proper error handling at the service layer.

### Error Handling Strategy

```typescript
// Example error handling in repository methods

async function create(data: CreateIntegrationData): Promise<Integration> {
  try {
    // Validate input
    if (!data.userId || !data.provider || !data.externalId) {
      throw new Error('Missing required fields')
    }
    
    // Perform database operation
    const result = await db.query(/* ... */)
    
    return mapToIntegration(result.rows[0])
  } catch (error) {
    // Check for specific database errors
    if (error.code === '23505') { // Unique constraint violation
      throw new Error(`Integration already exists for user ${data.userId} and provider ${data.provider}`)
    }
    
    if (error.code === '23503') { // Foreign key violation
      throw new Error(`User ${data.userId} does not exist`)
    }
    
    // Re-throw other errors
    throw error
  }
}

async function update(
  id: string,
  data: UpdateIntegrationData
): Promise<Integration | null> {
  // Validate that at least one field is being updated
  if (!data.token && !data.metadata) {
    throw new Error('No fields to update')
  }
  
  const result = await db.query(/* ... */)
  
  // Return null if no rows were affected (ID doesn't exist)
  if (result.rowCount === 0) {
    return null
  }
  
  return mapToIntegration(result.rows[0])
}
```

### Error Response Examples

**Successful Operations:**
```typescript
// List (no integrations)
await listByUserId('user-123') // Returns: []

// Update (non-existent)
await update('non-existent-id', { token: {...} }) // Returns: null

// Delete (non-existent)
await deleteById('non-existent-id') // Returns: false
```

**Error Conditions:**
```typescript
// Duplicate integration
await create({
  userId: 'user-123',
  provider: 'stripe',
  externalId: 'acct_123',
  token: {...},
  metadata: {}
})
// Throws: Error('Integration already exists for user user-123 and provider stripe')

// Invalid user
await create({
  userId: 'non-existent-user',
  provider: 'stripe',
  externalId: 'acct_456',
  token: {...},
  metadata: {}
})
// Throws: Error('User non-existent-user does not exist')
```

## Testing Strategy

### Dual Testing Approach

The repository will be validated using both unit tests and property-based tests to ensure comprehensive coverage:

- **Unit tests**: Verify specific examples, edge cases, and error conditions
- **Property tests**: Verify universal properties across all inputs

Together, these approaches provide comprehensive coverage where unit tests catch concrete bugs and property tests verify general correctness.

### Property-Based Testing

We will use **fast-check** (a property-based testing library for TypeScript/JavaScript) to implement the correctness properties defined above. Each property test will:

- Run a minimum of 100 iterations with randomly generated inputs
- Reference the corresponding design document property in a comment tag
- Use the format: `// Feature: integration-repository, Property {number}: {property_text}`

**Property Test Configuration:**

```typescript
import fc from 'fast-check'
import { describe, it, expect } from 'vitest'

// Generators for property-based testing
const integrationDataArb = fc.record({
  userId: fc.uuid(),
  provider: fc.constantFrom('stripe', 'razorpay', 'shopify'),
  externalId: fc.string({ minLength: 1, maxLength: 100 }),
  token: fc.dictionary(fc.string(), fc.anything()),
  metadata: fc.dictionary(fc.string(), fc.anything())
})

const updateDataArb = fc.record({
  token: fc.option(fc.dictionary(fc.string(), fc.anything())),
  metadata: fc.option(fc.dictionary(fc.string(), fc.anything()))
}, { requiredKeys: [] })

describe('Integration Repository Property Tests', () => {
  it('Property 1: List Returns All and Only Matching Records', () => {
    // Feature: integration-repository, Property 1: List returns all and only matching records
    fc.assert(
      fc.property(
        fc.array(integrationDataArb),
        fc.uuid(),
        async (integrations, targetUserId) => {
          // Setup: Create all integrations
          // Test: Call listByUserId(targetUserId)
          // Assert: All returned records have userId === targetUserId
          // Assert: Count matches expected count
        }
      ),
      { numRuns: 100 }
    )
  })
  
  it('Property 2: Create-Retrieve Round Trip Preserves Data', () => {
    // Feature: integration-repository, Property 2: Create-retrieve round trip preserves data
    fc.assert(
      fc.property(
        integrationDataArb,
        async (data) => {
          // Test: Create integration, then retrieve by userId
          // Assert: Retrieved record contains all input fields unchanged
          // Assert: Record has generated id and timestamps
        }
      ),
      { numRuns: 100 }
    )
  })
  
  // Additional property tests for Properties 3, 4, 5...
})
```

### Unit Testing

Unit tests will focus on:

1. **Specific Examples**
   - Create integration with Stripe provider
   - Create integration with Razorpay provider
   - Create integration with Shopify provider
   - List integrations for user with multiple providers
   - Update only token field
   - Update only metadata field
   - Update both token and metadata

2. **Edge Cases**
   - List integrations for user with no integrations (empty array)
   - Update non-existent integration (returns null)
   - Delete non-existent integration (returns false)
   - Create integration with empty metadata object
   - Create integration with complex nested token structure
   - Provider names with different casing

3. **Error Conditions**
   - Create duplicate integration (same user, provider, external_id)
   - Create integration with non-existent user ID
   - Update with no fields specified
   - Create with missing required fields

4. **Data Integrity**
   - Verify timestamps are set correctly on create
   - Verify updatedAt changes on update
   - Verify createdAt doesn't change on update
   - Verify immutable fields don't change on update
   - Verify JSONB fields are properly serialized/deserialized

### Test File Organization

```
tests/
├── unit/
│   └── repositories/
│       └── integration.test.ts              # Unit tests
└── property/
    └── repositories/
        └── integration.property.test.ts     # Property-based tests
```

### Coverage Goals

- 100% line coverage for all repository functions
- All 5 correctness properties implemented as property tests
- Minimum 15 unit tests covering examples, edge cases, and errors
- All error paths explicitly tested
- Integration tests with mock database client to verify SQL queries

### Mock Database Client

For testing, we'll create a mock database client that simulates the database interface:

```typescript
interface MockDBClient {
  query(sql: string, params: any[]): Promise<{ rows: any[], rowCount: number }>
}

// Mock implementation for testing
class InMemoryDBClient implements MockDBClient {
  private store: Map<string, any> = new Map()
  
  async query(sql: string, params: any[]) {
    // Parse SQL and simulate database operations
    // Return results in the format expected by the repository
  }
}
```

This allows testing the repository logic without requiring a real database connection.
