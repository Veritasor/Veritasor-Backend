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

## Test Setup

Tests use:
- **Jest** - Test framework
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

## Property-Based Tests

Property-based tests use [fast-check](https://github.com/dubzzz/fast-check) to verify invariants across arbitrary inputs rather than fixed examples. They live alongside unit tests under `tests/unit/`.

### Stripe Store — ID Mapping (`store.property.test.ts`)

File: `tests/unit/services/integrations/stripe/store.property.test.ts`

Covers two groups of properties:

**OAuth state store** (`setOAuthState` / `consumeOAuthState`):
| # | Property |
|---|---|
| 1 | Arbitrary valid state strings round-trip correctly |
| 2 | Tokens stored with a future expiry are consumable |
| 3 | Boundary expiry values (1 ms, 24 h, past) behave correctly |
| 4 | Tokens are one-time use — second consume returns `false` |
| 5 | Re-storing the same token overwrites with the new expiry |
| 6 | Consuming one token does not affect other tokens |

**Integration ID mapping** (`upsertStripeIntegration` / `getStripeIntegration`):
| # | Property |
|---|---|
| 7 | Round-trip identity — `stripeUserId`, `accessToken`, `businessId` are returned unchanged |
| 8 | `createdAt` and `updatedAt` are set to the current time on first insert and are equal |
| 9 | Re-upserting preserves `createdAt`; `updatedAt` is ≥ the original value |
| 10 | Distinct `stripeUserId` keys are stored and retrieved independently |
| 11 | An unknown `stripeUserId` returns `undefined` |
| 12 | Large/boundary field values (long tokens, long business IDs) are not truncated |

**Arbitraries used:**
- `stripeUserIdArb` — `acct_` + 16 alphanumeric chars (mirrors Stripe's OAuth `stripe_user_id`)
- `accessTokenArb` — `sk_test_` or `sk_live_` prefix + random hex suffix
- `businessIdArb` — `biz_` + random hex suffix

**Edge cases exercised:** missing optional fields, type mismatches via `fc.pre` guards, large metadata blobs (Properties 11–12).

## Threat Model

### Authentication

| Threat | Mitigation |
|---|---|
| JWT forgery | Tokens are signed with `HS256`; `verifyToken` rejects any token with an invalid signature or missing `sub`/`iat` claims |
| Token replay after logout | Refresh tokens are single-use; the store deletes them on consumption |
| Brute-force login | Per-IP rate limiting with progressive backoff (`signupRateLimiter`, shared `rateLimiter`) |
| Expired access token reuse | `verifyToken` checks `exp`; middleware returns `401 INVALID_TOKEN` on expiry |
| Password enumeration | `forgotPassword` returns the same response regardless of whether the email exists |

### Webhooks

| Threat | Mitigation |
|---|---|
| Forged Razorpay webhook | `verifyRazorpaySignature` computes `HMAC-SHA256(body, RAZORPAY_WEBHOOK_SECRET)` and compares with `X-Razorpay-Signature` using a timing-safe comparison |
| Replay attack | Razorpay includes an `event.id`; handlers should deduplicate on this ID before processing (not yet enforced — track as open item) |
| Oversized payload | Express `json()` middleware limits body size; webhook routes should apply a stricter limit (e.g. `express.json({ limit: '64kb' })`) |

### Integrations (Stripe / Shopify / Razorpay)

| Threat | Mitigation |
|---|---|
| OAuth CSRF | A 64-char hex `state` token is generated, stored with a TTL, and validated on callback via `consumeOAuthState` (one-time use) |
| State token enumeration | `isValidStripeOAuthState` rejects any token that is not exactly 64 lowercase hex chars before touching the store |
| Leaked access tokens in logs | `store.ts` never logs token values; structured logger omits fields matching sensitive key patterns |
| Stale OAuth state reuse | State tokens expire (configurable TTL); `consumeOAuthState` deletes the token before checking expiry, preventing TOCTOU |
| Cross-user token access | Integration records are keyed by `stripeUserId` and scoped to `userId` in the repository layer; the callback handler verifies ownership before upsert |
| Empty / malformed IDs stored | `upsertStripeIntegration` and `setOAuthState` throw `StripeStoreValidationError` on empty or non-string inputs — no silent failures |

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
