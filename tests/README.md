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
  - `business.test.ts` - Business CRUD tests + **analytics route auth enforcement**
  - `integrations.test.ts` - Integrations API tests (list, connect, disconnect, OAuth flow)

## Test Setup

Tests use:
- **Jest** - Test framework
- **Supertest** - HTTP assertion library for testing Express apps
- **ts-jest** - TypeScript support for Jest

## Analytics Tests

The analytics integration tests (in `business.test.ts`) cover:

### Routes

| Method | Path                        | Auth Required | Rate Limit        |
|--------|-----------------------------|---------------|-------------------|
| GET    | `/api/analytics/periods`    | Business Auth | 30 req / 15 min   |
| GET    | `/api/analytics/revenue`    | Business Auth | 30 req / 15 min   |

### Auth error shapes (stable contract)

| Status | `code`                | Trigger                                      |
|--------|-----------------------|----------------------------------------------|
| 401    | `MISSING_AUTH`        | Missing or malformed `Authorization` header  |
| 401    | `INVALID_TOKEN`       | Expired, invalid, or revoked JWT             |
| 400    | `MISSING_BUSINESS_ID` | No `x-business-id` header or body field      |
| 403    | `BUSINESS_NOT_FOUND`  | Business not found or not owned by the user  |

### Test scenarios

1. **401 MISSING_AUTH** – request with no `Authorization` header
2. **401 INVALID_TOKEN** – request with an expired/invalid token
3. **403 BUSINESS_NOT_FOUND** – valid token but wrong business (role mismatch)
4. **400 bad params** – missing `period`/`from`/`to`, invalid YYYY-MM format, only `from` without `to`
5. **404 no data** – authenticated but no attestations for the requested window
6. **200 success** – valid auth + valid params returns revenue report
7. **Rate-limit headers** – `X-RateLimit-Bucket: analytics`, `X-RateLimit-Limit: 30`

### Mock strategy

`requireBusinessAuth` is mocked with `vi.mock` so tests run without a real database.
The mock simulates the exact response shapes the real middleware produces:

```typescript
// Successful auth – sets req.business so setBusinessLocals can copy to res.locals
mockRequireBusinessAuth.mockImplementation((req, res, next) => {
  req.business = { id: 'biz-1', userId: 'user-1', ... }
  next()
})

// Auth failure – returns stable 401/403 shape
mockRequireBusinessAuth.mockImplementation((_req, res) => {
  res.status(401).json({ error: '...', message: '...', code: 'MISSING_AUTH' })
})
```

Analytics services (`listAttestedPeriodsForBusiness`, `getRevenueReport`) are also mocked
so tests are deterministic and do not require a running database.

### Threat model notes

- **Token expiry mid-request**: `requireBusinessAuth` re-validates the token on every request
  (no session cache). An expired token returns `INVALID_TOKEN` regardless of prior success.
- **Role mismatch**: The middleware checks `business.userId === req.user.id` after fetching
  the business from the DB. A valid token for user A cannot access user B's business.
- **Cached sessions**: There is no server-side session cache; each request is independently
  authenticated. Revoked tokens are rejected as soon as the DB user-existence check fails.
- **Webhooks / integrations**: Webhook endpoints use separate HMAC signature verification
  and do not share the analytics rate-limit bucket.

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
