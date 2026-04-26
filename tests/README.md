# Integration Tests

This directory contains integration tests for the Veritasor Backend API.

## Running Tests

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Run tests with coverage
npm run test:coverage
```

## Test Structure

- `integration/` - Integration tests that test complete API flows
  - `auth.test.ts` - Authentication API tests (signup, login, refresh, password reset)
  - `integrations.test.ts` - Integrations API tests (list, connect, disconnect, OAuth flow)
- `unit/services/` - Unit tests for service-layer modules
  - `merkle.test.ts` - Merkle tree construction, proof generation/verification, and performance guardrail tests

## Test Setup

Tests use:
- **Jest** - Test framework (integration tests)
- **Vitest** - Unit test framework (`unit/`)
- **Supertest** - HTTP assertion library for testing Express apps
- **ts-jest** - TypeScript support for Jest

## Auth Tests

The auth integration tests cover:

1. **User Signup** - Creating new user accounts
2. **User Login** - Authentication with credentials
3. **Token Refresh** - Refreshing access tokens
4. **Get Current User** - Fetching authenticated user info
5. **Forgot Password** - Initiating password reset flow
6. **Reset Password** - Completing password reset with token

## Integrations Tests

The integrations integration tests cover:

1. **List Available Integrations** - Get all available integrations (public endpoint)
2. **List Connected Integrations** - Get connected integrations for authenticated business
3. **Stripe OAuth Connect** - Initiate and complete OAuth flow
4. **Disconnect Integration** - Remove integration connection
5. **Authentication** - Protected routes return 401 when unauthenticated
6. **Security** - Sensitive tokens not exposed in responses

### Mock Implementation

Currently, the tests include a mock auth router since the actual auth routes are not yet implemented. The mock:
- Uses in-memory stores for users, tokens, and reset tokens
- Simulates password hashing (prefixes with "hashed_")
- Implements proper token validation
- Follows security best practices (e.g., no email enumeration)

The integrations tests include a mock integrations router. The mock:
- Uses in-memory stores for connections and OAuth state
- Simulates OAuth flow with state generation and validation
- Implements proper authentication checks
- Follows security best practices (no token exposure, state validation)

### When Auth Routes Are Implemented

Replace the mock router in `auth.test.ts` with the actual auth router:

```typescript
// Remove createMockAuthRouter() function
// Import actual auth router
import { authRouter } from '../../src/routes/auth.js'

// In beforeAll:
app.use('/api/auth', authRouter)
```

### When Integrations Routes Are Implemented

Replace the mock router in `integrations.test.ts` with the actual integrations router:

```typescript
// Remove createMockIntegrationsRouter() function
// Import actual integrations router
import { integrationsRouter } from '../../src/routes/integrations.js'

// In beforeAll:
app.use('/api/integrations', integrationsRouter)
```

## Merkle Service Tests (`unit/services/merkle.test.ts`)

### Overview

Unit tests covering the Merkle tree service split across three suites:

| Suite | Focus |
|---|---|
| `MerkleTree` | Legacy Buffer-based class — construction, proof, verification |
| `MerkleProofGuards` | Modular API input validation and tamper resistance |
| `buildTree guardrails` | Size caps, structured warning logs, determinism |
| `Benchmarks — complexity probes` | Logarithmic depth checks, large-tree smoke tests |

### Performance Guardrails

The Merkle service enforces size guardrails to prevent memory spikes and request timeouts on large attestation datasets.

#### `MERKLE_MAX_LEAVES` (hard cap)

| Property | Value |
|---|---|
| Default | `1 048 576` (2²⁰) |
| Override | `MERKLE_MAX_LEAVES` env var |
| Max override | `16 777 216` (2²⁴) |
| Error type | `RangeError` |

Calls to `buildTree()` or `new MerkleTree()` with more leaves than this cap throw immediately — no partial work is done.

```bash
# Example: raise the cap for a bulk attestation job
MERKLE_MAX_LEAVES=4194304 npm run start
```

#### `MERKLE_WARN_LEAVES` (soft threshold)

When leaf count reaches 10 % of `MERKLE_MAX_LEAVES`, the service emits a structured `console.warn` entry:

```json
{
  "level": "warn",
  "service": "merkle",
  "event": "large_tree",
  "leafCount": 104857,
  "warnThreshold": 104857,
  "maxAllowed": 1048576,
  "message": "Building Merkle tree with 104857 leaves — approaching size guardrail"
}
```

Pipe this to your log aggregator (Datadog, CloudWatch, etc.) and alert on `event: large_tree`.

#### `MERKLE_PROOF_MAX_STEPS` (verification guard)

`verifyProof()` rejects proof arrays longer than `256` steps. A valid proof for a 2²⁰-leaf tree is only 20 steps; a 256-step proof is either malformed or adversarial. The guard bounds worst-case CPU in the verification loop.

### Complexity Notes

Proof depth and hashing work scale as follows (empirical, Node 20, Apple M2):

| Leaves | Proof depth | Approx build time |
|---|---|---|
| 1 024 | 10 steps | < 1 ms |
| 65 536 | 16 steps | ~90 ms |
| 1 048 576 | 20 steps | ~950 ms |

Rule of thumb: `depth = ⌈log₂(n)⌉`, hashing work = `O(n)`.

The 100 000-leaf smoke test in the benchmark suite runs on every `npm test` pass to catch regressions.

### Threat Model Notes

| Vector | Mitigation |
|---|---|
| **Oversized request body** driving OOM | `MERKLE_MAX_LEAVES` hard cap throws before any heap allocation on the tree |
| **Slow hash DoS** via crafted long proof | `MERKLE_PROOF_MAX_STEPS = 256` bounds loop iterations in `verifyProof` |
| **Tampered proof siblings** | Normalised hex validation in `normalizeHashHex` rejects malformed values; final root comparison catches modified hashes |
| **Invalid proof position field** | `isProofStep` type guard rejects anything other than `'left'` or `'right'` |
| **0x-prefixed inputs** from on-chain callers | `stripHexPrefix` normalises before validation — no silent mismatch |
| **Non-integer leaf index** | `generateProof` throws on fractional indices to surface off-by-one bugs early |

### Running Only Merkle Tests

```bash
npx vitest run tests/unit/services/merkle.test.ts
```

With coverage:

```bash
npx vitest run --coverage tests/unit/services/merkle.test.ts
```

## Database Strategy

For integration tests with a real database:

1. **Test Database** - Use a separate test database
2. **Migrations** - Run migrations before tests
3. **Cleanup** - Clear data between tests
4. **Transactions** - Wrap tests in transactions and rollback

Example setup:

```typescript
beforeAll(async () => {
  await db.migrate.latest()
})

beforeEach(async () => {
  await db.raw('BEGIN')
})

afterEach(async () => {
  await db.raw('ROLLBACK')
})

afterAll(async () => {
  await db.destroy()
})
```

## Best Practices

- Test complete user flows, not just individual endpoints
- Use descriptive test names that explain the scenario
- Clean up test data between tests
- Don't expose sensitive information in error messages
- Test both success and failure cases
- Verify security requirements (401, 403, etc.)
- Test OAuth state validation and expiration
- Ensure tokens and credentials are not leaked in responses

## End-to-End (E2E) Testing Plan

The E2E tests verify the complete system flow, including the API, backend services, database, and Soroban contract interactions.

### Testing Philosophy
E2E tests should focus on the "Happy Path" user journeys and critical failure points that integration tests might miss due to mocks.

### E2E Scenarios

#### 1. Complete Attestation Lifecycle
- **Goal**: Verify a merchant can fetch revenue and submit a verified attestation on-chain.
- **Steps**:
    1. Merchant logs into the dashboard.
    2. Merchant initiates a sync for a specific period (e.g., "2025-Q1").
    3. Backend fetches data from connected integrations (Shopify/Razorpay).
    4. Backend generates a Merkle root.
    5. Backend submits the root to the Soroban contract.
    6. Verify the transaction hash is recorded and the root is queryable on the Stellar network.

#### 2. Multi-Source Integration Sync
- **Goal**: Ensure revenue data from multiple sources is correctly aggregated.
- **Steps**:
    1. User connects both Stripe and Shopify.
    2. Initiate a consolidated sync.
    3. Verify that the Merkle tree leaves contain data from both sources accurately.

### Security & Resilience Testing
- **Rate Limiting**: Verify that excessive requests from a single IP/User are throttled.
- **Idempotency**: Ensure that re-submitting an attestation with the same `Idempotency-Key` does not create duplicate on-chain transactions.
- **Auth Resilience**: Test deep-link authentication and token rotation flows.

### Performance & Scaling
- **Load Testing**: Simulate 100+ concurrent attestation submissions to ensure the Soroban RPC and DB pool can handle the load.
- **Large Dataset Aggregation**: Test sync operations with 10,000+ line items.

## Security Assumptions & Validations

The following security assumptions are baked into the system and must be validated by the E2E suite:

1. **Isolation of Business Data**:
    - *Assumption*: A user cannot sync or view revenue for a business they do not own.
    - *Validation*: E2E tests must attempt unauthorized sync requests and verify `403 Forbidden` responses.

2. **Tamper-Proof Merkle Proofs**:
    - *Assumption*: The Merkle root submitted on-chain accurately represents the source data.
    - *Validation*: Verify that changing a single revenue entry locally results in a Merkle proof mismatch against the on-chain root.

3. **Key Management**:
    - *Assumption*: Private keys are never exposed in logs or API responses.
    - *Validation*: Audit log assertions in E2E tests must scan for sensitive strings (G... or S... keys).

4. **Idempotency Integrity**:
    - *Assumption*: Multiple identical requests do not result in multiple on-chain transactions (saving gas/fees).
    - *Validation*: Check local database for single record entry after multiple POST bursts.