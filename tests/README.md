# Tests — Veritasor Backend

This directory contains unit and integration tests for the Veritasor Backend API.

---

## Enhanced Optional Auth Middleware Tests

**Location**: `tests/unit/middleware/optionalAuth.test.ts`

### Overview

The enhanced `optionalAuth` middleware provides clear distinction between absent vs malformed tokens, comprehensive error classification, and structured logging for observability. The test suite covers:

- **Token Classification**: Clear differentiation between NO_TOKEN vs MALFORMED_HEADER events
- **Error Taxonomy**: 10 specific auth event types with proper classification
- **Structured Logging**: JSON-formatted logs with correlation fields
- **Edge Cases**: Expired tokens, wrong issuer, wrong audience, database errors

### Auth Event Taxonomy

The service defines 10 specific auth event types categorized as:

| Event Type | Description | Log Level |
|------------|-------------|-----------|
| NO_TOKEN | No Authorization header present | warn |
| MALFORMED_HEADER | Header present but malformed | warn |
| INVALID_TOKEN | Token cryptographically invalid | warn |
| EXPIRED_TOKEN | Token expired | warn |
| WRONG_ISSUER | Token from wrong issuer | warn |
| WRONG_AUDIENCE | Token for wrong audience | warn |
| USER_NOT_FOUND | Token valid but user not found | warn |
| AUTH_SUCCESS | Token valid and user found | info |
| DATABASE_ERROR | Database lookup failed | warn |
| UNEXPECTED_ERROR | Unexpected system error | warn |

### Structured Logging

All auth events include these fields for observability:
```json
{
  "timestamp": "2024-03-15T12:00:00.000Z",
  "level": "info|warn",
  "service": "optional-auth",
  "event": "AUTH_EVENT_TYPE",
  "userId": "user_123",
  "userAgent": "Mozilla/5.0...",
  "ip": "192.168.1.100",
  "requestId": "req_1234567890_abc",
  "error": "Error message (if applicable)",
  "tokenLength": 256,
  "hasBearerPrefix": true,
  "headerPresent": true,
  "duration": 15
}
```

### Test Coverage

| Test Type | Coverage | Focus Areas |
|-----------|----------|------------|
| Unit Tests | 95%+ | Token classification, error mapping, log structure |
| Edge Cases | All events | Each auth event type tested with appropriate response |
| Performance | Timing | Auth processing duration tracking |
| Security | Input validation | Malformed headers, injection attempts |

### Running Optional Auth Tests

```bash
# Run only optional auth tests
npx vitest run tests/unit/middleware/optionalAuth.test.ts

# Run with coverage
npx vitest run --coverage tests/unit/middleware/optionalAuth.test.ts

# Run all middleware tests
npx vitest run tests/unit/middleware/
```

### Threat Model Notes

| Vector | Mitigation |
|--------|------------|
| **Token Enumeration** | Structured logs don't expose token content |
| **Header Injection** | Malformed headers classified and logged safely |
| **Database DoS** | Database errors logged but don't block requests |
| **Timing Attacks** | Consistent processing time regardless of auth status |
| **Log Injection** | Structured JSON logging prevents injection |

### Operational Guidance

#### Monitoring
- Monitor `AUTH_SUCCESS` rate for service health
- Alert on high `MALFORMED_HEADER` rates (potential attacks)
- Track `DATABASE_ERROR` events for infrastructure issues
- Monitor `EXPIRED_TOKEN` patterns for token refresh issues

#### Log Analysis
```bash
# Find failed authentication attempts
grep '"event":"MALFORMED_HEADER"' auth.log | wc -l

# Track authentication success rate
grep '"event":"AUTH_SUCCESS"' auth.log | wc -l

# Monitor database issues
grep '"event":"DATABASE_ERROR"' auth.log

# Find expired tokens by hour
grep '"event":"EXPIRED_TOKEN"' auth.log | cut -d',' -f1 | sort | uniq -c
```

---

## Enhanced Attestation Submit Service Tests

**Location**: `tests/unit/attestation-submit.test.ts` and `tests/integration/attestations.test.ts`

### Overview

The enhanced `submitAttestation` service includes hardened retry logic, comprehensive error taxonomy, and structured logging for Soroban blockchain submissions. The test suite covers:

- **Retry Logic**: Exponential backoff with jitter for transient failures
- **Error Taxonomy**: Clear categorization of retryable vs non-retryable errors
- **Structured Logging**: JSON-formatted logs with correlation fields
- **Edge Cases**: Network timeouts, nonce conflicts, insufficient balance, etc.

### Error Taxonomy

The service defines 13 specific Soroban error codes categorized as:

| Retryable (9) | Non-Retryable (4) |
|---------------|------------------|
| NETWORK_TIMEOUT | INVALID_SIGNATURE |
| NETWORK_ERROR | INVALID_ACCOUNT |
| RPC_UNAVAILABLE | INSUFFICIENT_BALANCE |
| NONCE_CONFLICT | CONTRACT_ERROR |
| FEE_BUMP_REQUIRED | |
| TRANSACTION_PENDING | |
| RATE_LIMITED | |
| SERVICE_UNAVAILABLE | |
| INTERNAL_ERROR | |

### Retry Configuration

Default retry behavior (configurable via environment):
- **Max Attempts**: 3
- **Base Delay**: 1000ms
- **Max Delay**: 30000ms
- **Backoff Multiplier**: 2
- **Jitter**: ±25% randomization

### Structured Logging

All logs include these fields for observability:
```json
{
  "timestamp": "2024-03-15T12:00:00.000Z",
  "level": "info|warn|error",
  "service": "attestation-submit",
  "message": "Human-readable description",
  "userId": "user_123",
  "businessId": "biz_456",
  "period": "2024-03",
  "attempt": 1,
  "maxAttempts": 3,
  "error": "Error message (if applicable)",
  "errorCode": "ERROR_CODE (if applicable)",
  "duration": 1500
}
```

### Test Coverage

| Test Type | Coverage | Focus Areas |
|-----------|----------|------------|
| Unit Tests | 95%+ | Retry logic, error mapping, log structure |
| Integration Tests | End-to-end | Service behavior with mocked dependencies |
| Error Scenarios | All codes | Each error code tested with appropriate response |
| Performance | Timing | Exponential backoff verification |

### Running Attestation Tests

```bash
# Run only attestation submit tests
npx vitest run tests/unit/attestation-submit.test.ts

# Run with coverage
npx vitest run --coverage tests/unit/attestation-submit.test.ts

# Run integration tests
npx vitest run tests/integration/attestations.test.ts
```

### Threat Model Notes

| Vector | Mitigation |
|--------|------------|
| **Timeout Loops** | Max retry attempts (3) prevent infinite loops |
| **Nonce Conflicts** | Retryable with exponential backoff |
| **Fee Bumps** | Automatic retry for fee-related failures |
| **Insufficient Balance** | Immediate failure (400) - no retries |
| **Network DoS** | Jitter prevents thundering herd attacks |
| **Log Injection** | Structured JSON logging prevents injection |
| **Error Leakage** | Client-safe messages, internal details logged only |

---

## Validate Middleware Tests

Unit tests in `tests/unit/middleware/validate.test.ts` cover `validateBody` and `validateQuery`.

**Error mapping:** `ZodError.issues` are mapped to `{ path: (string|number)[], message: string }` before being stored in `ValidationError.details`. The error envelope exposes both `details` and `errors` (same array) so existing callers using `details` are unaffected.

**Edge cases covered:**

| Case | Description |
|------|-------------|
| Extra keys (default) | Stripped silently — Zod strips unknown keys by default |
| Extra keys (strict) | Rejected with `VALIDATION_ERROR` when schema uses `.strict()` |
| Coercion | `z.coerce.number()` converts query string `"42"` → `42` |
| Coercion failure | Non-numeric string produces a `count` path error |
| Union types | First matching branch accepted; no error |
| Nested path shape | Each error has `path: string[]` and `message: string` |

**Threat model notes:**
- Validation errors never expose internal schema structure beyond field paths and human-readable messages.
- Extra keys are stripped before the request body reaches route handlers, preventing prototype pollution via unexpected fields.
- Coercion is explicit (`z.coerce.*`) — implicit coercion is not used, avoiding silent type confusion.

## Redaction Policy

`requestLogger` never writes sensitive values to logs. The policy is enforced via two exported sets in `src/middleware/requestLogger.ts`:

| Set | Members |
|-----|---------|
| `REDACTED_HEADERS` | `authorization`, `cookie`, `set-cookie`, `x-api-key`, `x-auth-token` |
| `REDACTED_QUERY_PARAMS` | `token`, `access_token`, `refresh_token`, `api_key`, `apikey`, `secret`, `password`, `reset_token`, `code` |

Matched values are replaced with the literal string `[REDACTED]` before the log entry is written. Non-sensitive fields pass through unchanged.

**Threat model notes:**
- Bearer tokens in `Authorization` headers are excluded from logs entirely (headers are not logged).
- Cookies and `Set-Cookie` are in `REDACTED_HEADERS` for future-proofing if header logging is added.
- OAuth `code` and `state` query params are redacted to prevent authorization-code interception via log aggregators.
- Webhook payloads and request bodies are never logged (existing policy).

To extend the policy, add entries to `REDACTED_HEADERS` or `REDACTED_QUERY_PARAMS` in `src/middleware/requestLogger.ts`. Tests in `tests/integration/auth.test.ts` under `"requestLogger redaction policy"` verify coverage.

## Running Tests

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Run tests with coverage
npm run test:coverage
```

---

## Test Structure

- `integration/` - Integration tests that test complete API flows
  - `auth.test.ts` - Authentication API tests (signup, login, refresh, password reset)
  - `integrations.test.ts` - Integrations API tests (list, connect, disconnect, OAuth flow)
- `unit/services/` - Unit tests for service-layer modules
  - `merkle.test.ts` - Merkle tree construction, proof generation/verification, and performance guardrail tests

---

Tests use:
- **Jest** - Test framework (integration tests)
- **Vitest** - Unit test framework (`unit/`)
- **Supertest** - HTTP assertion library for testing Express apps
- **ts-jest** - TypeScript support for Jest

### `normalize.test.ts`

Covers two source files:

| Module | Function | Description |
|--------|----------|-------------|
| `normalize.ts` | `normalizeRevenueEntry` | Canonical shape, currency/date/amount edge cases |
| `normalize.ts` | `detectNormalizationDrift` | Batch drift detection against a statistical baseline |
| `anomalyDetection.ts` | `detectRevenueAnomaly` | MoM anomaly scoring with configurable thresholds |
| `anomalyDetection.ts` | `calibrateFromSeries` | Derive thresholds from historical training data |

#### Coverage target

≥ 95% line and branch coverage on all touched modules where practical.
Run `npm run test:coverage` to verify; the coverage report is emitted to `coverage/`.

---

## Anomaly Detection — Operator Tuning

### Environment Variables

All threshold defaults for `detectRevenueAnomaly` and `calibrateFromSeries` can be
overridden at process start via environment variables. Set them in `.env` (copy from
`.env.example`) before the service boots; changes take effect on the next restart.

| Variable | Type | Default | Description |
|---|---|---|---|
| `ANOMALY_DROP_THRESHOLD` | float | `0.4` | MoM fractional drop that triggers `unusual_drop`. E.g. `0.3` = flag when revenue falls ≥ 30%. Must be in `(0, 1]`. |
| `ANOMALY_SPIKE_THRESHOLD` | float | `3.0` | MoM fractional rise that triggers `unusual_spike`. E.g. `2.0` = flag when revenue rises ≥ 200%. Must be `> 0`. |
| `ANOMALY_MIN_DATA_POINTS` | int | `2` | Minimum series length required for detection. Must be an integer `≥ 2`. |
| `ANOMALY_CALIBRATION_SIGMA` | float | `2.0` | Std-dev multiplier used by `calibrateFromSeries`. Must be `> 0`. |

**Validation behaviour** — if an env-var value fails validation (wrong type, out of
range, empty string), the module falls back silently to the hard-coded default and
emits a warning to `stderr`. No exception is thrown.

Example `.env` entries:

```dotenv
ANOMALY_DROP_THRESHOLD=0.30
ANOMALY_SPIKE_THRESHOLD=2.00
ANOMALY_MIN_DATA_POINTS=3
ANOMALY_CALIBRATION_SIGMA=2.5
```

---

### Calibration API

Use `calibrateFromSeries` to derive statistically-grounded thresholds from at least
12 months of historical revenue data and then pass the result into
`detectRevenueAnomaly`:

```ts
import { calibrateFromSeries, detectRevenueAnomaly } from './src/services/revenue/anomalyDetection.js';

const cal = calibrateFromSeries(historicalSeries, { sigmaMultiplier: 2 });
const result = detectRevenueAnomaly(currentSeries, cal);
```

The returned `CalibrationResult` can be persisted (e.g. in Redis or Postgres) and
reloaded on service start to avoid recomputing thresholds on every request.

**Missing baseline fallback** — if the training series has fewer than 2 points, or if
all prior-period amounts are zero, `calibrateFromSeries` returns the module defaults
(`dropThreshold: 0.4`, `spikeThreshold: 3.0`) so the pipeline never hard-fails.

---

### Structured Logging

Pass a logger callback to `detectRevenueAnomaly` to receive a typed `AnomalyLogRecord`
on every invocation. Wire it to your application logger (e.g. `pino`, `winston`) for
queryable, alertable anomaly events in your log aggregator (Datadog, Loki, etc.):

```ts
import pino from 'pino';
const log = pino();

const result = detectRevenueAnomaly(series, cal, (record) => {
  log.info(record, 'revenue_anomaly');
});
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

```typescript
beforeAll(async () => {
  await db.migrate.latest();
});

beforeEach(async () => {
  await db.raw('BEGIN');
});

afterEach(async () => {
  await db.raw('ROLLBACK');
});

afterAll(async () => {
  await db.destroy();
});
```

**`ForgotPasswordAuditRecord` events:**

| Event | When emitted |
|---|---|
| `forgot_password_requested` | Every call, before any DB lookup |
| `forgot_password_user_not_found` | Email not in the database |
| `forgot_password_token_issued` | Token written to DB successfully |
| `forgot_password_email_sent` | Email delivery succeeded |
| `forgot_password_email_retryable_failure` | Email provider returned a retryable error |
| `forgot_password_email_permanent_failure` | Email provider returned a non-retryable error |

**`ResetPasswordAuditRecord` events:**

| Event | When emitted |
|---|---|
| `reset_password_attempted` | Every call, before token lookup |
| `reset_password_invalid_token` | Token not found or expired |
| `reset_password_success` | Password updated and token consumed |

### Error Codes

| Code | HTTP | Meaning |
|---|---|---|
| `VALIDATION_ERROR` | 400 | Missing or invalid input fields |
| `INVALID_RESET_TOKEN` | 400 | Token not found, expired, or already consumed |
| `RESET_EMAIL_RETRYABLE_FAILURE` | 503 | Email delivery failed transiently; client should retry |
| `RESET_EMAIL_UNAVAILABLE` | 500 | Email delivery failed permanently |

### Failure Modes

| Condition | Behaviour |
|---|---|
| Email not in DB | Generic 200 response; no token stored; no email sent |
| Email delivery — retryable | Token cleared from DB; throws `503 RESET_EMAIL_RETRYABLE_FAILURE` |
| Email delivery — permanent | Token cleared from DB; throws `500 RESET_EMAIL_UNAVAILABLE` |
| Invalid / expired token at reset | Throws `400 INVALID_RESET_TOKEN`; no DB write |
| Password too short | Throws `400 VALIDATION_ERROR` before token lookup |
| Invalid `RESET_TOKEN_TTL_MINUTES` | Falls back to `15`; warning to `stderr` |
| Invalid `RESET_MIN_PASSWORD_LENGTH` | Falls back to `8`; warning to `stderr` |

### Idempotency

`forgotPassword` is **not** idempotent by design — each call that finds a valid user
generates and stores a new token, invalidating the previous one (because
`setResetToken` overwrites the stored token). Operators should rely on rate limiting
to prevent excessive token churn.

`resetPassword` is idempotent in its rejection behaviour — calling it twice with the
same token will return `INVALID_RESET_TOKEN` on the second call because the token is
consumed on first use.

- Test complete user flows, not just individual endpoints.
- Use descriptive test names that document the expected scenario.
- Clean up test data between tests; never rely on test ordering.
- Do not expose sensitive information (tokens, keys, passwords) in error messages
  or test assertions.
- Test both success and failure cases, including boundary conditions.
- Verify security requirements (401, 403, rate-limit headers, etc.).
- Test OAuth state validation and expiration.
- Ensure tokens and credentials are not leaked in responses.

---

## JWT Rotation Notes

- Refresh tokens are treated as single-use in rotation flows.
- Reuse of a consumed refresh token must be handled as a theft signal and rejected.
- Clock skew is tolerated by verifier configuration; tests should use expirations beyond skew tolerance.

Environment variables used by JWT tests and auth flows:
- `JWT_SECRET` (access token secret)
- `JWT_REFRESH_SECRET` (refresh token secret)
- `JWT_CLOCK_SKEW_SECONDS` (default `10`)
- `JWT_ACCESS_TOKEN_TTL` (default `3600`)
- `JWT_REFRESH_TOKEN_TTL` (default `604800`)

## Threat Model Notes

- Auth: stale or replayed refresh tokens are denied; rotation requires explicit reuse handling and logging.
- Webhooks: verify provider signatures and reject replays using idempotency keys or event IDs.
- Integrations: protect OAuth state, never log raw provider tokens, and enforce least-privilege scopes.
## End-to-End (E2E) Testing Plan

### Scenarios

#### 1. Complete Attestation Lifecycle
1. Merchant logs in and initiates a sync for a specific period.
2. Backend fetches data from connected integrations (Shopify / Razorpay).
3. Backend generates a Merkle root.
4. Backend submits the root to the Soroban contract.
5. Verify the transaction hash is recorded and the root is queryable on Stellar.

#### 2. Multi-Source Integration Sync
1. User connects both Stripe and Shopify.
2. Initiate a consolidated sync.
3. Verify Merkle tree leaves contain data from both sources accurately.

### Security & Resilience

- **Rate Limiting** — verify excessive requests from a single IP/user are throttled.
- **Idempotency** — re-submitting an attestation with the same `Idempotency-Key`
  must not create duplicate on-chain transactions.
- **Auth Resilience** — test deep-link auth and token rotation flows.

### Performance & Scaling

- **Load Testing** — 100+ concurrent attestation submissions.
- **Large Dataset Aggregation** — sync with 10 000+ line items.

### Security Assumptions

Rejection reasons returned by `validateRazorpayState`:

| Condition | Reason string |
|---|---|
| Not a string / empty | `Missing state parameter` |
| Exceeds 512 chars | `Invalid or expired state` |
| Contains control chars / null bytes | `Invalid or expired state` |
| Not in store (forged / already consumed) | `Invalid or expired state` |
| Expired (past TTL) | `Invalid or expired state` |

---

## Security — Threat Model Notes

### Auth Routes — Password Reset

#### User Enumeration
`forgotPassword` returns the identical response message and waits a constant ~200 ms
regardless of whether the supplied email exists. An observer who times the HTTP
response cannot distinguish "user found" from "user not found" beyond normal network
jitter.

#### Token Forgery
Reset tokens are 32 random bytes (256-bit entropy) from `crypto.randomBytes`. The
probability of guessing a valid token is negligible. Tokens are stored server-side and
compared at the repository layer (timing-safe comparison recommended).

#### Token Replay
`updateUserPassword` atomically clears `resetToken` and `resetTokenExpiry` in the
same DB transaction as the password update. A second call with the same token returns
`INVALID_RESET_TOKEN` because the repository lookup finds nothing.

#### Brute Force / Rate Limiting
Both routes must be protected by the named-bucket rate limiter (see Rate Limiting
above). Without rate limiting, an attacker could brute-force the 64-hex token space —
though 256-bit entropy makes this computationally infeasible, rate limiting provides
defence in depth and prevents denial-of-service via token generation storms.

#### Email Interception
Reset links are transmitted over email, which may be less secure than HTTPS. Operators
should:
1. Use short TTLs (`RESET_TOKEN_TTL_MINUTES ≤ 15`).
2. Ensure the frontend resets URL accepts tokens only over HTTPS.
3. Rotate email provider credentials if a breach is suspected.

#### Token Leakage via Logs
Structured log records include only the first 8 hex chars of the token
(`tokenPrefix`). The full 64-char token is never written to any log record. Do not
log the raw request body on forgot/reset routes.

#### dangling Tokens on Email Failure
If email delivery fails (retryable or permanent), the token is cleared from the DB
before the error is propagated. The user is never left with a stored, unsendable token
that could be leaked via a subsequent DB exposure.

### Razorpay OAuth Initiation

#### Open-Redirect Prevention
The `redirectUrl` origin is validated against an explicit server-side allowlist
(`RAZORPAY_ALLOWED_REDIRECT_ORIGINS`) before any state is generated. No
client-supplied URL can bypass this check: even if an attacker crafts a
`redirectUrl` that looks legitimate, the WHATWG URL parser normalises and compares
only the origin, closing protocol-relative and scheme-confusion vectors.

#### CSRF / State Forgery
State tokens are 32 random bytes (256-bit entropy) generated by Node's
`crypto.randomBytes`. They are stored server-side with a 10-minute TTL and
deleted on first use. An attacker who cannot read the token from the server
cannot forge or predict a valid state. Cross-user theft is mitigated because
`validateRazorpayState` returns the `userId` bound to the token — the callback
handler must verify this matches the authenticated session.

#### Replay Attacks
Tokens are deleted from the store on the first validation call, regardless of
outcome (success, expiry, or store-miss). This makes it impossible to reuse a
token even if intercepted after the legitimate callback completes.

#### Mixed-Environment Leakage
Each deployment must set `RAZORPAY_ALLOWED_REDIRECT_ORIGINS` to origins specific
to that environment. A production token cannot be redirected to a staging origin
unless the staging origin is explicitly allow-listed in production — an intentional
deployment decision, not a default.

#### State Enumeration
Response bodies never reflect the stored state back to the caller beyond the
token itself. Structured logs record only the first 8 hex characters of the token
(sufficient for correlation, insufficient for forgery).

### Anomaly Detection

#### Spike Attacks
An adversary submitting artificially inflated revenue figures (to obscure a real
drop later) will surface as `unusual_spike` first. Pair anomaly detection with
source-level webhook signature verification so that only authenticated payloads
reach `detectRevenueAnomaly`.

#### Replay Attacks on Baselines
`calibrateFromSeries` is a pure function — it does not persist state. Callers are
responsible for persisting and versioning `CalibrationResult` objects. An attacker
who can force a recalibration using manipulated historical data could widen
thresholds and suppress future anomaly flags. Store calibration results under
authenticated access control and avoid accepting untrusted series as training data.

#### Env-Var Injection
Threshold env vars are read once at module load and validated strictly. An attacker
who can modify process environment variables before boot could widen thresholds.
Treat your deployment secrets and runtime environment accordingly.

#### Log Injection
The `detail` string in `AnomalyResult` and the `AnomalyLogRecord` payload embed
`period` and `amount` values from the caller-supplied input series. Ensure your log
aggregator escapes or sanitises these fields before rendering them in dashboards
or alert messages.

### Webhooks & Integrations

- OAuth state parameters must be validated and be single-use to prevent CSRF.
- Integration tokens and credentials must never appear in API responses or logs;
  the E2E suite includes sensitive-string assertions to enforce this.
- Idempotency keys on attestation submissions prevent duplicate on-chain
  transactions under burst conditions.

---

## Integration Tests

### Auth Tests (`integration/auth.test.ts`)

| Scenario | Description |
|---|---|
| User Signup | Creating new user accounts |
| User Login | Authentication with credentials |
| Token Refresh | Refreshing access tokens |
| Get Current User | Fetching authenticated user info |
| Forgot Password | Initiating password reset flow |
| Reset Password | Completing password reset with token |

### Integrations Tests (`integration/integrations.test.ts`)

| Scenario | Description |
|---|---|
| List Available Integrations | Get all available integrations (public endpoint) |
| List Connected Integrations | Get connected integrations for authenticated business |
| Stripe OAuth Connect | Initiate and complete OAuth flow |
| Disconnect Integration | Remove integration connection |
| Authentication | Protected routes return 401 when unauthenticated |
| Security | Sensitive tokens not exposed in responses |

### Razorpay Connect State Tests (`integration/razorpay-connect-state.test.ts`)

| Suite | Scenarios |
|---|---|
| Authentication guard | 401 when unauthenticated |
| Redirect URL validation | Allowlisted origin accepted; non-allowlisted, javascript:, data:, protocol-relative, missing field all rejected (400) |
| State token generation | 64-hex format; uniqueness across calls and users; embedded in authUrl; correct TTL; 503 when client ID absent |
| Structural rejection | undefined, null, empty string, number, oversized, null byte, control char, SQL injection, XSS |
| Store-level checks | Valid token accepted; forged token rejected; expired token rejected and deleted; single-use (replay rejected); cross-user isolation |
| End-to-end round-trip | Token from initiation accepted by validate; consumed after first use |

### Mock Implementation

Auth and integrations tests use in-memory mock routers until the real routes are
implemented. To switch to real routes, see the comments at the top of each test file.

---

## Database Strategy

For integration tests with a real database:

```typescript
beforeAll(async () => {
  await db.migrate.latest();
});

beforeEach(async () => {
  await db.raw('BEGIN');
});

afterEach(async () => {
  await db.raw('ROLLBACK');
});

afterAll(async () => {
  await db.destroy();
});
```

---

## Best Practices

- Test complete user flows, not just individual endpoints.
- Use descriptive test names that document the expected scenario.
- Clean up test data between tests; never rely on test ordering.
- Do not expose sensitive information (tokens, keys, passwords) in error messages
  or test assertions.
- Test both success and failure cases, including boundary conditions.
- Verify security requirements (401, 403, rate-limit headers, etc.).
- Test OAuth state validation and expiration.
- Ensure tokens and credentials are not leaked in responses.

---

## End-to-End (E2E) Testing Plan

### Scenarios

#### 1. Complete Attestation Lifecycle
1. Merchant logs in and initiates a sync for a specific period.
2. Backend fetches data from connected integrations (Shopify / Razorpay).
3. Backend generates a Merkle root.
4. Backend submits the root to the Soroban contract.
5. Verify the transaction hash is recorded and the root is queryable on Stellar.

#### 2. Multi-Source Integration Sync
1. User connects both Stripe and Shopify.
2. Initiate a consolidated sync.
3. Verify Merkle tree leaves contain data from both sources accurately.

### Security & Resilience

- **Rate Limiting** — verify excessive requests from a single IP/user are throttled.
- **Idempotency** — re-submitting an attestation with the same `Idempotency-Key`
  must not create duplicate on-chain transactions.
- **Auth Resilience** — test deep-link auth and token rotation flows.

### Performance & Scaling

- **Load Testing** — 100+ concurrent attestation submissions.
- **Large Dataset Aggregation** — sync with 10 000+ line items.

### Security Assumptions

4. **Idempotency Integrity**:
    - *Assumption*: Multiple identical requests do not result in multiple on-chain transactions (saving gas/fees).
    - *Validation*: Check local database for single record entry after multiple POST bursts.
