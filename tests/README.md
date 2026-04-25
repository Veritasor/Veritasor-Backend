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
- `unit/` - Unit tests for individual modules and services
  - `services/revenue/` - Revenue service tests
    - `normalize.test.ts` - Revenue data normalization tests
    - `revenueReportSchema.test.ts` - Revenue report schema validation and security tests

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

## Soroban RPC Client Configuration

The Soroban RPC client includes comprehensive timeout, retry, and resilience configuration for production deployments.

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SOROBAN_RPC_URL` | `https://soroban-testnet.stellar.org` | Soroban RPC endpoint URL |
| `SOROBAN_CONTRACT_ID` | Required | Deployed attestation contract address (C...) |
| `SOROBAN_NETWORK_PASSPHRASE` | `Test SDF Network ; September 2015` | Stellar network passphrase |
| `SOROBAN_RPC_TIMEOUT_MS` | `5000` | Timeout for individual RPC requests (100-60000ms) |
| `SOROBAN_RPC_MAX_RETRIES` | `2` | Maximum retry attempts after initial failure (0-5) |
| `SOROBAN_RPC_RETRY_BASE_DELAY_MS` | `200` | Base delay for exponential backoff (1-30000ms) |
| `SOROBAN_RPC_RETRY_MAX_DELAY_MS` | `1500` | Maximum delay for exponential backoff (1-30000ms) |
| `SOROBAN_RPC_RETRY_JITTER_RATIO` | `0.2` | Jitter ratio to reduce synchronized retries (0-1) |
| `SOROBAN_RPC_CIRCUIT_BREAKER_THRESHOLD` | `5` | Consecutive failures before opening circuit breaker (1-20) |
| `SOROBAN_RPC_CIRCUIT_BREAKER_RESET_MS` | `30000` | Time before attempting to close circuit breaker (1000-300000ms) |

### Resilience Features

- **Timeout Protection**: Individual requests timeout to prevent hanging
- **Exponential Backoff**: Delays increase exponentially with jitter to reduce thundering herd
- **Circuit Breaker**: Prevents cascading failures by temporarily rejecting requests when service is unhealthy
- **Enhanced Error Classification**: Retries DNS failures, stale connections, and rate limits
- **Observability Hooks**: Structured logging and metrics collection for monitoring

### Security Considerations

- No sensitive data (keys, tokens) is logged
- Circuit breaker prevents resource exhaustion attacks
- Rate limit awareness prevents 429 response cascades
- Request IDs enable distributed tracing

### Monitoring

The client emits structured logs for:
- Request start/completion with timing
- Retry attempts with delay information
- Circuit breaker state changes
- Transport failures with error classification

Use observability hooks for custom metrics collection:

```typescript
const hooks: SorobanObservabilityHooks = {
  onRequestSuccess: (op, attempt, duration) => {
    metrics.record(`soroban.${op}.success`, duration)
  },
  onRequestFailure: (op, attempt, duration, error) => {
    metrics.record(`soroban.${op}.failure`, { duration, error: error.message })
  },
  onCircuitBreakerStateChange: (oldState, newState) => {
    logger.info('Circuit breaker state changed', { oldState, newState })
  }
}
```

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

## Revenue Report Schema Tests

The revenue report schema tests (`revenueReportSchema.test.ts`) cover comprehensive validation and security hardening for the `/api/analytics/revenue` endpoint query parameters.

### Security Validation Coverage

1. **Input Format Validation**
   - Strict YYYY-MM format enforcement
   - Year boundary validation (2020-2105)
   - Month range validation (01-12)
   - Length limits to prevent DoS attacks

2. **Injection Prevention**
   - HTML/Script injection attempts
   - SQL injection patterns
   - Command injection attempts
   - Path traversal attacks
   - XSS attempts with various encodings

3. **Parameter Combination Validation**
   - Period vs range parameter conflicts
   - Required parameter combinations
   - Mutual exclusivity enforcement

4. **Edge Case Testing**
   - Boundary conditions (min/max years)
   - Malformed date strings
   - Unicode and null byte attacks
   - Extremely long strings

### Test Categories

- **Valid Inputs**: Ensure legitimate requests pass validation
- **Invalid Format**: Reject malformed date strings
- **Year Boundaries**: Enforce reasonable year limits
- **Month Validation**: Proper month format and range
- **Injection Prevention**: Block various attack vectors
- **Parameter Combinations**: Validate parameter relationships
- **DoS Prevention**: Prevent resource exhaustion attacks
- **Error Types**: Verify structured error constants

## Best Practices

- Test complete user flows, not just individual endpoints
- Use descriptive test names that explain the scenario
- Clean up test data between tests
- Don't expose sensitive information in error messages
- Test both success and failure cases
- Verify security requirements (401, 403, etc.)
- Test OAuth state validation and expiration
- Ensure tokens and credentials are not leaked in responses
- Include comprehensive negative testing for security-critical endpoints
- Test boundary conditions and edge cases thoroughly
- Validate input sanitization and injection prevention

## Error Envelope Snapshot Coverage

`integration/auth.test.ts` includes snapshot tests for the global error handler
client shape. These tests pin the stable envelope fields:

- `status: "error"`
- `code` from `src/types/errors.ts`
- client-safe `message`
- optional `details` for validation failures, plus legacy `errors` alias for
  existing validation clients
- `timestamp` and `requestId`

The snapshots cover direct Zod errors, PostgreSQL constraint and operational
errors, and non-`Error` throwables. Timestamps and request IDs are normalized in
the snapshot helper so the tests assert contract shape rather than runtime
entropy.

## Threat Model Notes

- **Auth**: login, refresh, password reset, and current-user failures must keep
  credential, token, and user-enumeration details out of responses. Server-side
  logs should include request method, path, request ID, status code, and typed
  error metadata for triage without recording request bodies or secrets.
- **Webhooks**: malformed payloads, signature failures, replay attempts, and
  provider downtime should return typed, generic envelopes. Logs may include
  provider name, request ID, and verification outcome, but never webhook secrets,
  raw signatures, payment tokens, or full provider payloads.
- **Integrations**: OAuth state mismatches, token exchange failures, and provider
  API errors should preserve stable client codes while redacting access tokens,
  refresh tokens, API keys, merchant credentials, and database connection
  details from both API responses and routine structured logs.

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
    
## Read Consistency & Security

Veritasor implements a multi-tier consistency model for reading attestations to balance performance and security.

### Consistency Levels

1.  **LOCAL (Default)**:
    -   Reads directly from the PostgreSQL database.
    -   Lowest latency, suitable for most dashboard views.
    -   Subject to indexing lag (DB might be a few blocks behind the chain).

2.  **STRONG**:
    -   Reads from the DB and then verifies the record against the Soroban blockchain state.
    -   Higher latency (requires RPC calls).
    -   Guarantees the data matches the "Truth on Chain".
    -   Used for critical audits and legal proof generation.

### Threat Model & Resilience Notes

| Threat | Strategy | Mechanism |
| :--- | :--- | :--- |
| **Indexing Lag** | Detection & Auto-Correction | If a STRONG read finds a record on-chain that is still marked as `pending` in the DB, the system auto-updates the DB to `confirmed`. |
| **Data Tampering** | Integrity Verification | If a STRONG read detects a Merkle root mismatch between the DB and the Chain, it logs a CRITICAL CONSISTENCY ERROR for immediate operator review. |
| **Revocation Propagation** | Immediate Verification | STRONG reads ensure that if an attestation is revoked on-chain, it is treated as revoked by the system regardless of DB state. |
| **Network Outage** | Graceful Degradation | If the Soroban RPC is unavailable during a STRONG read, the system falls back to LOCAL data and logs a warning. |

### Operator Runbook: Discrepancies

If a `CRITICAL CONSISTENCY ERROR` is observed in logs:
1.  Verify the on-chain data using a block explorer or `stellar-cli`.
2.  Check the database for unauthorized modifications.
3.  Initiate a manual re-sync if the DB record is corrupted.

## Email Security & Template Hardening

The email service implements strict validation and sanitization to prevent injection attacks.

### Injection Prevention

1.  **Input Validation (Zod)**:
    -   All emails are validated against the `z.string().email()` schema.
    -   Reset links are validated to ensure they use safe protocols (`https:` or `http:` in dev). Unsafe protocols like `javascript:` or `data:` are rejected.

2.  **HTML Escaping**:
    -   All dynamic values interpolated into HTML templates are escaped using a dedicated `escapeHtml` utility.
    -   This prevents attackers from injecting malicious HTML tags (e.g., `<script>`, `<iframe>`, `<img>`) even if they manage to partially control the link or other parameters.

### Threat Model: Email Risks

| Threat | Strategy | Mechanism |
| :--- | :--- | :--- |
| **HTML Injection** | Sanitization | `escapeHtml` converts `<`, `>`, `&`, `"`, and `'` into entities. |
| **Link Wrapping/Phishing** | Protocol Gating | Only allowed protocols are permitted; others trigger a validation error. |
| **Header Injection** | SMTP Library Safety | Use of `nodemailer` which handles header sanitization internally, combined with Zod validation of the `to` field. |
| **Information Leakage** | Dev Stubs | In development mode, reset links are logged to the console instead of sent, and the `to` address is never leaked in unauthorized contexts. |
