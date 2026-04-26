# Tests — Veritasor Backend

This directory contains unit and integration tests for the Veritasor Backend API.

---

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

```
tests/
├── unit/
│   └── services/
│       ├── integration/
│       │   └── auth.test.ts            # Config validation + password reset flow
│       └── revenue/
│           └── normalize.test.ts       # normalizeRevenueEntry, detectNormalizationDrift,
│                                       # detectRevenueAnomaly, calibrateFromSeries
└── integration/
    ├── auth.test.ts                    # Auth API flows (signup, login, refresh, reset)
    ├── integrations.test.ts            # Integrations API flows (list, connect, OAuth)
    └── razorpay-connect-state.test.ts  # Razorpay connect initiation: state & redirect URL safety
```

---

## Unit Tests — Revenue Services

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

**`AnomalyLogRecord` shape:**

```ts
{
  event:      'anomaly_detected' | 'anomaly_check_ok' | 'anomaly_insufficient_data';
  flag:       AnomalyFlag;
  score:      number;          // 0–1
  detail:     string;
  thresholds: { drop: number; spike: number; minDataPoints: number };
  detectedAt: string;          // ISO 8601 UTC
}
```

---

### Seasonality & False-Positive Guidance

Month-over-month thresholds can fire spuriously for businesses with strong seasonal
patterns (e.g. e-commerce Q4 spikes, SaaS annual renewals).

**Mitigation strategies:**

1. **Use `calibrateFromSeries`** on ≥ 12 months of history so thresholds are derived
   from your actual distribution (mean ± N·σ) rather than a generic constant.

2. **Raise `ANOMALY_CALIBRATION_SIGMA`** to widen the acceptable band.
   `2` is conservative; `3` reduces false positives at the cost of missing
   smaller anomalies.

3. **Inject a `scoreHook`** to encode business rules — for example, suppress the
   spike flag during a known promotional window:

   ```ts
   const hook = (_prev, curr, _change) => {
     if (curr.period === '2025-11') return { score: 0, flag: 'ok' };
     return null; // fall back to built-in logic
   };
   const result = detectRevenueAnomaly(series, { scoreHook: hook });
   ```

4. **Raise `ANOMALY_SPIKE_THRESHOLD`** for specific business verticals that
   routinely see multi-hundred-percent promotional surges.

---

### Failure Modes

| Condition | Behaviour |
|---|---|
| Series length < `minDataPoints` | Returns `{ flag: "insufficient_data", score: 0 }`. Never throws. |
| All previous-period amounts are 0 | Pairs with `prev.amount === 0` are skipped silently; result is `ok`. |
| `scoreHook` throws | Exception propagates to the caller — wrap externally if needed. |
| Invalid env-var value | Hard-coded default is used; warning written to `stderr`. |
| Training series too short for calibration | `calibrateFromSeries` returns module defaults without throwing. |

---

### Idempotency

Both `detectRevenueAnomaly` and `calibrateFromSeries` are **pure functions**: same
inputs always produce the same outputs with no side effects or I/O. Safe to call
multiple times with the same series. Neither function mutates its input array.

---

## Password Reset Flow — Operator Guide

### Overview

The password reset flow spans two services:

| Service | File | Responsibility |
|---|---|---|
| `forgotPassword` | `src/services/auth/forgotPassword.ts` | Generates token, sends email |
| `resetPassword` | `src/services/auth/resetPassword.ts` | Validates token, updates password |

Both services accept an optional structured-log callback (same pattern as anomaly
detection) and surface all failures as typed `AppError` instances — no silent
failures.

### Environment Variables

| Variable | Type | Default | Description |
|---|---|---|---|
| `RESET_PASSWORD_URL` | string | `http://localhost:3000/reset-password` | Base URL prepended to the reset token. Must be set to the frontend URL in production. |
| `RESET_TOKEN_TTL_MINUTES` | int | `15` | Token lifetime in minutes. Must be in `(0, 60]`. Values outside this range fall back to `15` with a `stderr` warning. |
| `RESET_MIN_PASSWORD_LENGTH` | int | `8` | Minimum length enforced on the new password. Must be `≥ 8`. Values below `8` fall back to `8` with a `stderr` warning. |

**Production checklist:**
- Set `RESET_PASSWORD_URL` to your actual frontend origin (`https://app.veritasor.com/reset-password`).
- Keep `RESET_TOKEN_TTL_MINUTES` at `15` or lower. The threat model requires tokens to be short-lived.
- `NODE_ENV=production` suppresses the `resetLink` field from API responses (it is present in `development` / `test` for local debugging only).

### Rate Limiting

Forgot-password and reset-password routes use the shared `rateLimiter` middleware
with explicit named buckets:

| Route | Bucket name | Recommended limits |
|---|---|---|
| `POST /api/v1/auth/forgot-password` | `auth:forgot-password` | 5 req / 15 min per IP |
| `POST /api/v1/auth/reset-password` | `auth:reset-password` | 10 req / 15 min per IP |

Named buckets ensure that abuse against the forgot-password endpoint cannot exhaust
the rate-limit budget for login or token refresh routes. Configure window and max via
`RATE_LIMIT_WINDOW_MS` and `RATE_LIMIT_MAX`, or pass per-route options directly to
`rateLimiter({ bucket: 'auth:forgot-password', windowMs: 15 * 60 * 1000, max: 5 })`.

### Security Properties

| Property | Implementation |
|---|---|
| **User enumeration resistance** | The same response message and a 200 ms constant-time delay are returned whether or not the email exists. |
| **Token entropy** | 32 random bytes (`crypto.randomBytes`) → 64 lowercase hex chars (256-bit). Not guessable. |
| **Token single-use** | `updateUserPassword` atomically clears `resetToken` + `resetTokenExpiry` alongside the password update. Replayed tokens return `INVALID_RESET_TOKEN`. |
| **Token TTL** | Configurable, default 15 min. Expired tokens are rejected at the repository layer. |
| **Timing attack mitigation** | `findUserByEmail` and the 200 ms delay run in parallel via `Promise.all`, equalising response time for found vs. not-found branches. |
| **Email delivery cleanup** | On any delivery failure (retryable or permanent) the token is cleared from the DB before the error is thrown, preventing dangling unusable tokens. |
| **Audit log — token prefix only** | Log records include only the first 8 hex chars of the token (sufficient for incident correlation, insufficient for forgery). The full token never appears in logs. |
| **No production reset link** | `resetLink` is omitted from the response when `NODE_ENV=production`. |

### Structured Audit Log

---

## Razorpay Connect Initiation — State Validation & Redirect URL Safety

### Overview

`POST /api/integrations/razorpay/initiate` begins a Razorpay OAuth connect flow.
It returns a short-lived, single-use CSRF state token and a pre-built authorization
URL that the client should redirect the merchant's browser to.

The callback handler **must** call `validateRazorpayState(state)` before exchanging
the authorization code for an access token.

### Environment Variables

| Variable | Required | Example | Description |
|---|---|---|---|
| `RAZORPAY_CLIENT_ID` | Yes | `rzp_live_abcdef` | Razorpay OAuth application client ID. |
| `RAZORPAY_ALLOWED_REDIRECT_ORIGINS` | Yes | `https://app.veritasor.com,https://staging.veritasor.com` | Comma-separated list of origins that are permitted as OAuth redirect targets. Any origin not in this list is rejected (fail-closed). |

**Fail-closed behaviour** — if `RAZORPAY_ALLOWED_REDIRECT_ORIGINS` is empty or
unset, **all** redirect URLs are rejected. If `RAZORPAY_CLIENT_ID` is unset, the
endpoint returns `503 Service Unavailable` and cleans up any partially stored state.

### Request

```http
POST /api/integrations/razorpay/initiate
Authorization: Bearer <jwt>
Content-Type: application/json

{
  "redirectUrl": "https://app.veritasor.com/oauth/razorpay/callback"
}
```

### Response (200 OK)

```json
{
  "authUrl": "https://auth.razorpay.com/authorize?response_type=code&client_id=…&redirect_uri=…&state=<token>&scope=read_write",
  "state": "<64-hex-char token>",
  "expiresAt": "2026-04-24T11:00:00.000Z"
}
```

Redirect the merchant's browser to `authUrl`. Razorpay will redirect back to
`redirectUrl?code=<code>&state=<token>` after the merchant authorizes.

### State Token Properties

- **Entropy**: 32 random bytes (256-bit) — not guessable.
- **Format**: 64 lowercase hex characters.
- **TTL**: 10 minutes from issuance.
- **Single-use**: consumed and deleted on the first `validateRazorpayState` call,
  regardless of whether that call succeeds or fails.

### Redirect URL Validation

The supplied `redirectUrl` is validated against `RAZORPAY_ALLOWED_REDIRECT_ORIGINS`
before any state token is generated or stored.

| Blocked vector | How it is rejected |
|---|---|
| Arbitrary external URL (`https://evil.com`) | Origin not in allowlist → `400` |
| Protocol-relative URL (`//evil.com`) | URL parser rejects → `400` |
| `javascript:` / `data:` scheme | Non-http(s) scheme → `400` |
| Malformed string | URL constructor throws → `400` |
| Missing field | Zod schema validation → `400` |

### Failure Modes

| Condition | HTTP Status | Error |
|---|---|---|
| Unauthenticated | 401 | `Unauthorized` |
| Missing / invalid `redirectUrl` | 400 | Zod validation details |
| Origin not in allowlist | 400 | `redirectUrl origin "…" is not in the allowed list` |
| `RAZORPAY_CLIENT_ID` not set | 503 | `Razorpay OAuth is not configured` |

### `validateRazorpayState` — Callback Handler Usage

```ts
import { validateRazorpayState } from '../services/integrations/razorpay/connect.js'

// In your OAuth callback route:
const result = validateRazorpayState(req.query.state)
if (!result.valid) {
  return res.status(400).json({ error: result.reason })
}

const { userId, redirectUrl } = result.entry
// … exchange authorization code …
```

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

### Auth Routes

- JWT tokens must be validated on every request; user existence is re-verified
  against the database to detect revoked accounts.
- Rate limiting is applied per route bucket (see `src/middleware/rateLimiter.ts`);
  auth endpoints (login, refresh, forgot-password, reset-password) use named buckets
  so bursts against one endpoint cannot exhaust the shared budget for another.
- Password reset tokens must be single-use and short-lived (< 15 minutes).
- Signup uses a dedicated abuse-prevention limiter stricter than the shared bucket.

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

## Health Endpoint Tests

The health endpoint tests in `auth.test.ts` validate the stable JSON schema for load balancer probes.

### Endpoint

| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| GET | `/api/health` | Basic health check | No |
| HEAD | `/api/health` | HEAD request support | No |

### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `mode` | `shallow` \| `deep` | `shallow` | Health check mode |

### Response Schema

The health endpoint returns a JSON object conforming to `HealthResponseSchema`:

```typescript
{
  status: "ok" | "degraded" | "unhealthy",
  service: "veritasor-backend",
  timestamp: string,  // ISO 8601 datetime
  mode: "shallow" | "deep",
  db?: "ok" | "down",        // Only if DATABASE_URL is set
  redis?: "ok" | "down",     // Only if REDIS_URL is set
  soroban?: "ok" | "down",   // Only in deep mode if SOROBAN_RPC_URL is set
  email?: "ok" | "down"      // Only in deep mode if SMTP_HOST is set
}
```

### Status Codes

| Code | Condition |
|------|----------|
| `200` | Service is operational (ok, degraded) |
| `503` | Service is unhealthy (critical dependency down in deep mode) |

### Status Values

| Status | Meaning |
|--------|---------|
| `ok` | All configured dependencies are healthy |
| `degraded` | Some dependencies are down but service is operational |
| `unhealthy` | Critical dependency is down (deep mode only, returns 503) |

### Environment Variables

The health endpoint checks connectivity based on these environment variables:

| Variable | Check Performed | Critical |
|----------|-----------------|----------|
| `DATABASE_URL` | PostgreSQL `SELECT 1` query | Yes (deep mode) |
| `REDIS_URL` | Redis `PING` command | No |
| `SOROBAN_RPC_URL` | Stellar Soroban RPC health check | Yes (deep mode) |
| `SMTP_HOST` | SMTP port connectivity check | Yes (deep mode) |

### Health Modes

**Shallow Mode (default)**:
- Checks `DATABASE_URL` (if set) and `REDIS_URL` (if set)
- Returns `degraded` if database is down
- Redis being down does not affect status

**Deep Mode (`?mode=deep`)**:
- Also checks `SOROBAN_RPC_URL` and `SMTP_HOST`
- Returns `unhealthy` with 503 if any critical dependency (db, soroban, email) is down
- Returns `degraded` if only non-critical dependencies (redis) are down

### Security Notes

- No authentication required (designed for load balancers)
- No sensitive data exposed in response
- Uses read-only operations for all checks
- Not subject to rate limiting
- Uses 2-second timeouts to keep response time low

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

| Assumption | Validation |
|---|---|
| A user cannot access a business they do not own | E2E tests attempt unauthorized sync; verify `403 Forbidden` |
| Merkle root accurately represents source data | Mutate one entry locally; verify Merkle proof mismatch vs on-chain root |
| Private keys never appear in logs or API responses | Audit log assertions scan for `G...` and `S...` key patterns |
| Identical requests don't result in multiple on-chain transactions | Check DB for a single record after multiple POST bursts |
| Razorpay OAuth state cannot be forged, replayed, or stolen cross-user | State tests in `razorpay-connect-state.test.ts` assert each property |
| Password reset tokens cannot be replayed | `resetPassword` called twice with same token returns `INVALID_RESET_TOKEN` on second call |
| Password reset does not leak user existence | `forgotPassword` response is identical for found and not-found emails |
