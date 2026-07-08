# Veritasor Backend

API gateway and attestation service for Veritasor. Handles revenue data normalization, Merkle proof generation, and on-chain submission to Soroban contracts (integration points are stubbed for the initial version).

## Tech Stack

- **Node.js** + **TypeScript**
- **Express** for HTTP API
- Planned: PostgreSQL, Redis, gRPC internal services

## Prerequisites

- Node.js 18+
- npm or yarn

## Setup

```bash
# Install dependencies
npm install

# Run in development (watch mode)
npm run dev
```

API runs at `http://localhost:3000`. Use `PORT` env var to override.

## Rate Limiting

The shared rate limiter in [src/middleware/rateLimiter.ts](src/middleware/rateLimiter.ts) supports explicit route-level buckets. Apply a stable bucket name per sensitive route so bursts against one endpoint do not consume the budget for another endpoint. Auth routes use this for login, refresh, forgot-password, reset-password, and `me`, while signup keeps its dedicated abuse-prevention limiter.

## Observability

Prometheus metrics are available at `/metrics` when `METRICS_ENABLED=true`.

### Idempotency TTL semantics

Idempotency keys are cached so duplicate requests within a TTL window return the original response. Default TTL is 24 hours (`getDefaultTtl()` in [src/middleware/idempotency.ts](src/middleware/idempotency.ts)). Per-route overrides use `idempotencyMiddleware({ scope, ttlMs })`.

**Eviction** is cooperative and never blocks the request path:

- The in-memory store evicts on read (`get`) and on overflow (`set` when `MAX_MEMORY_STORE_SIZE` is reached) and additionally on a periodic sweep.
- The Redis store relies on `PEXPIRE` for self-eviction; the sweeper does not write to Redis.
- A background sweeper (`IdempotencySweeper`) runs at `IDEMPOTENCY_SWEEP_INTERVAL_MS` (default 60s, hard floor 1s) and emits the metrics below.
- The sweeper is `unref`'d: it never blocks process exit and is stopped cleanly during graceful shutdown.
- A single Redis blip does not stop the sweeper — `runOnce()` swallows store errors, increments `idempotency_sweep_runs_total{outcome="error"}`, and the next cycle resumes once ioredis reconnects.

**Metrics for storage pressure** (see [src/metrics.ts](src/metrics.ts)):

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `idempotency_keys_count` | gauge | `backend` (`memory`/`redis`) | Current number of live keys in the store. Driven from `Map.size` (memory) or a `SCAN MATCH idempotency:*` walk (redis). |
| `idempotency_evictions_total` | counter | `backend`, `reason` (`expired`/`overflow`/`manual`) | Total keys removed. `expired` = TTL sweep, `overflow` = capacity prune in `set`, `manual` = explicit `delete`. |
| `idempotency_sweep_runs_total` | counter | `backend`, `outcome` (`ok`/`error`) | Sweeper cycles executed; `outcome="error"` indicates a transient store failure. |

Tune the TTL (`ttlMs` per route) or the sweep interval (`IDEMPOTENCY_SWEEP_INTERVAL_MS`) so the gauge plateaus instead of climbing — a continuously-rising gauge signals either a leak in `set()` or a too-long TTL.

Distributed tracing is disabled by default. Set `OTEL_EXPORTER_OTLP_ENDPOINT` to an OTLP/HTTP traces endpoint, such as `http://localhost:4318/v1/traces`, to initialize the OpenTelemetry Node SDK during app startup. The request logger creates one server span per HTTP request and Soroban RPC retries create child client spans, so slow attestation requests can be correlated with individual blockchain attempts.

Trace attributes intentionally exclude request bodies, headers, and raw query strings. Correlation IDs, HTTP method, route/path, status code, user agent, and Soroban operation metadata are emitted; exception messages are redacted before being recorded on custom spans.

## Attestation Reminders

The `attestationReminderJob` (`src/jobs/attestationReminder.ts`) sends attestation reminders aligned to each business's reporting calendar rather than on a fixed interval.

**How it works:**

- Each business has a `reportingPeriod` (`weekly` | `monthly`) and a `reportingTimezone` (IANA, e.g. `America/New_York`).
- The job computes the *next period boundary* since the last send using `Intl.DateTimeFormat` for DST-safe local-date decomposition.
- A reminder fires only when `now >= nextBoundary`. After sending, `lastReminderSentAt` is persisted to prevent double-firing within the same period.
- The job accepts an injectable `now: Date` parameter for deterministic testing without `vi.useFakeTimers()`.

**DST safety:** Period boundaries are computed by reading the local calendar date via `Intl`, then constructing a UTC instant via `Date.UTC`. This avoids the spring-forward / fall-back hazards that arise from using JS local-time methods directly.

**Schema changes:** See migration `20260627_001_add_businesses_reminder_columns.sql` which adds `reporting_period`, `reporting_timezone`, and `last_reminder_sent_at` to the `businesses` table.



| Command          | Description                    |
|------------------|--------------------------------|
| `npm run dev`    | Start with tsx watch           |
| `npm run build`  | Compile TypeScript to `dist/`  |
| `npm run start`  | Run compiled `dist/index.js`   |
| `npm run lint`   | Run ESLint                     |
| `npm run migrate`| Run database migrations        |
| `npm run audit:ci` | Run dependency audit and allowlist validation |

## Security audit

This repository includes a GitHub Actions workflow at `.github/workflows/security-audit.yml` that runs:

- `pnpm audit --prod --json` to detect vulnerabilities.
- `scripts/check-audit.ts` to enforce `.audit-allowlist.json` for temporary, expiring exceptions.
- A CycloneDX SBOM generation step that uploads `sbom/cyclonedx-sbom.xml` as a workflow artifact.

## Security Tests

[![Security Tests](https://github.com/Veritasor/Veritasor-Backend/actions/workflows/security-tests.yml/badge.svg)](https://github.com/Veritasor/Veritasor-Backend/actions/workflows/security-tests.yml)

Multi-tenant authorization fuzz tests live in `tests/security/multitenant.fuzz.spec.ts`. They use [fast-check](https://github.com/dubzzz/fast-check) property-based testing to generate randomized cross-tenant scenarios and assert `requireBusinessAuth` rejects every off-tenant request, including nested resources (attestations under integrations).

Run the security tests in isolation:

```bash
npx vitest run tests/security/multitenant.fuzz.spec.ts
```

**What is fuzz-tested:**

| Scenario | Property | Expected outcome |
|---|---|---|
| Tenant A claims Tenant B's business | `requestingUser.id ≠ business.userId` | 403 `BUSINESS_NOT_FOUND` |
| Spoofed `X-Business-Id` header | Non-existent or foreign business ID | 403 `BUSINESS_NOT_FOUND` |
| Nested attestation access | Attacker requests route protected by foreign business | 403 `BUSINESS_NOT_FOUND` |
| Suspended business (own owner) | `business.suspended = true` | 403 `BUSINESS_SUSPENDED` |
| Injection characters in business ID | IDs outside `[a-zA-Z0-9\-_]{1,50}` | 400 `MISSING_BUSINESS_ID` |
| DB failure during ownership check | `getById` throws | 403 `BUSINESS_NOT_FOUND` (never 500) |
| Error response data | Any rejection path | No secrets, stack traces, or sensitive fields leaked |

fast-check's shrinking automatically narrows any failing case to the minimal counterexample.

## Security audit allowlist



- `id`: Advisory identifier
- `package`: npm package name
- `severity`: `low`, `moderate`, `high`, or `critical`
- `reason`: Why the exception is allowed
- `expires`: ISO 8601 expiration timestamp

Expired allowlist entries are rejected.

## Performance testing

Peak-load k6 scenarios for `/api/v1/attestations` live in `ops/k6/`.

- Local entrypoint: `npm run perf:k6:attestations`
- Scenario docs: `ops/k6/README.md`
- Nightly workflow: `.github/workflows/nightly-k6-attestations.yml`
- Grafana dashboard: `ops/k6/grafana/peak-attestation-dashboard.json`

## API Versioning

Routes may be mounted with an `/api/v{n}` prefix and/or legacy unversioned paths (e.g. `/api/attestations`). The server still resolves a major version for each request.

- **Negotiation:** Path segment wins when present; otherwise `X-API-Version`, `Accept-Version`, query `apiVersion` / `api_version`, then `Accept` parameters (`version=`, `api-version=`, `v=`). Default is **v1**. Unsupported majors fall back to v1 with `API-Version-Fallback: true`.
- **Response headers:** `API-Version` (always a supported label), optional `API-Version-Fallback`, and merged `Vary` for caches.
- **Spec:** [docs/specs/api-version-negotiation.md](docs/specs/api-version-negotiation.md)
- **Future extensions:** Add entries to `SUPPORTED_API_VERSIONS` and mount `/api/v2` routers when ready.

## API (current)

| Method | Path                      | Description              | Auth Required |
|--------|---------------------------|--------------------------|---------------|
| GET    | `/api/v1/health`          | Health check             | No |
| GET    | `/api/v1/attestations`    | List attestations (stub) | User Auth |
| POST   | `/api/v1/attestations`    | Submit attestation (stub)| User Auth |
| GET    | `/api/v1/businesses/me`   | Get user business        | User Auth |
| POST   | `/api/v1/businesses`      | Create business           | User Auth |
| PATCH  | `/api/v1/businesses/me`   | Update business           | User Auth |

## Authentication & Authorization

### User Authentication
The API uses JWT-based authentication. Include the token in the `Authorization` header:

```http
Authorization: Bearer <your_jwt_token>
```

### Business Authorization
For business-scoped operations, use the enhanced business authorization middleware:

```http
Authorization: Bearer <your_jwt_token>
x-business-id: <business_id>
```

**Security Features:**
- JWT token validation with user existence verification
- Business ownership enforcement (users can only access their own businesses)
- Input validation and injection prevention
- Detailed error responses with structured error codes

**Error Codes:**
- `MISSING_AUTH` (401): Missing or invalid Authorization header
- `INVALID_TOKEN` (401): Invalid, expired, or malformed JWT token
- `MISSING_BUSINESS_ID` (400): Business ID not provided or invalid format
- `BUSINESS_NOT_FOUND` (403): Business not found or access denied

For detailed documentation, see [Business Authorization Boundary Checks](docs/business-authorization-boundary-checks.md).

## Project structure

```
veritasor-backend/
├── src/
│   ├── db/
│   │   ├── migrations/   # SQL migrations (e.g. 001_create_users_table.sql)
│   │   └── migrate.ts    # Migration runner
│   ├── routes/       # health, attestations
│   └── index.ts      # Express app entry
├── package.json
└── tsconfig.json
```

## Database migrations

Migrations live in `src/db/migrations/` as numbered SQL files (e.g. `001_create_users_table.sql`). The runner applies only pending migrations and records them in `schema_migrations`, so each runs once.

**Local database setup (contributors)**  
The repo does not include database credentials. Install PostgreSQL locally, create a database (and optionally a user), then set `DATABASE_URL` in your `.env` using your own username, password, and database name. Example after installing Postgres: create a DB (e.g. `createdb veritasor` or via your GUI), then use a connection string like `postgresql://localhost:5432/veritasor` (or with a username/password if you created one).

**How to run migrations**

1. Set `DATABASE_URL` (PostgreSQL connection string), e.g. in `.env` (copy from `.env.example`).
2. Run:

```bash
npm run migrate
```

Or with the CLI directly:

```bash
DATABASE_URL=postgresql://user:pass@localhost:5432/dbname npx tsx src/db/migrate.ts
```

Requires Node 18+ and a running PostgreSQL instance.

## Environment

Optional `.env`:

```
PORT=3000
DATABASE_URL=postgresql://user:password@localhost:5432/veritasor
```

## Merging to remote

This directory is its own git repository. To push to your remote:

```bash
git remote add origin <your-backend-repo-url>
git push -u origin main
```
