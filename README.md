# Veritasor Backend

API service for **Veritasor**: businesses connect revenue sources (Stripe, Shopify, Razorpay), revenue data is normalized, and attestations (Merkle-based proofs) are recorded and submitted toward Soroban contracts on Stellar. Many Soroban integration points are stubs or are exercised against a mock RPC; this repo does not assert that any contract is deployed.

- Frontend: [Veritasor/Veritasor-Frontend](https://github.com/Veritasor/Veritasor-Frontend)
- Contracts: [Veritasor/Veritasor-Contracts](https://github.com/Veritasor/Veritasor-Contracts)

## Architecture

Node.js (ESM) + TypeScript + Express. `src/index.ts` starts the server; `src/app.ts` assembles middleware and routers.

| Area | Location |
| --- | --- |
| HTTP routers | `src/routes/` |
| Services / repositories | `src/services/`, `src/repositories/` |
| PostgreSQL + SQL migrations | `src/db/` (`migrate.ts`, `migrations/`) |
| Redis (rate limiting, idempotency, cache) with circuit breaker | `src/redis.ts`, `src/middleware/` |
| Background jobs (e.g. attestation reminders) | `src/jobs/` |
| GraphQL, WebSocket, SPIFFE/mTLS | `src/graphql/`, `src/ws/`, `src/spiffe/` |
| Startup readiness checks, graceful shutdown | `src/startup/`, `src/shutdown.ts` |
| Metrics / tracing | `src/metrics.ts`, `src/tracing/` (Prometheus at `/metrics`, OTLP optional) |
| Ops assets (dev compose, alerts, Grafana, k6, soak) | `ops/` |

Request flow: request logger and security headers, mTLS, API-version negotiation (path, `X-API-Version`, `Accept-Version`, default v1), body parsing, CORS, compression, then routers, then the error handler. The Razorpay webhook router is mounted before JSON parsing so signatures can be verified over the raw body.

## API surface

Routers are mounted in `src/app.ts`. Some are also reachable under `/api/v1/...`; negotiate via the version middleware. Auto-generated map: [docs/api-routes.md](docs/api-routes.md) (`npm run docs:routes`); OpenAPI: `docs/openapi/` (`npm run docs:openapi`).

| Mount | Endpoints (from router files) |
| --- | --- |
| `/api/health` | `GET /`, `/live`, `/ready` |
| `/api/auth` | `POST /signup`, `/login`, `/refresh`, `/forgot-password`, `/reset-password`; `GET /me`, `/signup/availability` |
| `/api/users` | `PATCH /me`; data export: `POST /me/export`, `GET /me/export/:token`, `GET /me/export/:exportId/status` |
| `/api/businesses` | `POST /`, `GET /me`, `PATCH /me`, `GET /:id` |
| `/api/attestations` | `GET /`, `POST /`, `GET /:id`, `POST` or `DELETE /:id/revoke` |
| `/api/v1/public/attestations` | public attestation lookup |
| `/api/analytics` | `GET /periods`, `GET /revenue` |
| `/api/integrations` | `GET /`, `GET /connected`, `POST /connect`, `GET`/`DELETE /:integrationId` |
| `/api/integrations/{stripe,shopify,razorpay}` | OAuth connect/callback (Stripe, Shopify), connect/disconnect (Razorpay) |
| `/api/webhooks/razorpay` | inbound Razorpay webhook |
| `/api/v1/webhook-subscriptions` | outbound webhook subscriptions; egress IP list router |
| `/api/admin`, `/api/v1/admin` | admin router incl. GraphQL; DLQ routes (`/entries`, `/stats`, archive/restore) |
| `/metrics`, `/.well-known/jwks.json` | Prometheus metrics (when enabled); JWKS |

Authentication: JWT bearer tokens; business-scoped operations also take `x-business-id`. See [docs/business-authorization-boundary-checks.md](docs/business-authorization-boundary-checks.md) and [docs/rbac-policy-engine.md](docs/rbac-policy-engine.md). Errors follow a standard envelope: [docs/errors.md](docs/errors.md).

## Configuration

Copy `.env.example` to `.env`. Variables defined there:

- Core: `PORT` (3000), `NODE_ENV`
- Security: `JWT_SECRET`, `JWT_REFRESH_SECRET` (production requires strong values, >= 32 chars), `AUDIT_CHAIN_SECRET`, `ALLOWED_ORIGINS` (required in production), `SECRET_PROVIDER` (`env`, `aws`, `vault`) plus `VAULT_*`
- Database: `DATABASE_URL` (required) or `DB_HOST/DB_PORT/DB_NAME/DB_USER/DB_PASSWORD`, `DB_MAX_CONNECTIONS`, `DB_IDLE_TIMEOUT`, `PGSSL*`, `MIGRATION_*_TIMEOUT_MS`
- Redis: `REDIS_URL`, or `REDIS_CLUSTER_NODES`, `REDIS_TLS`
- Observability: `METRICS_ENABLED`, `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_SERVICE_NAME`, PgBouncer/Pushgateway options
- Stellar/Soroban: `STELLAR_NETWORK`, `SOROBAN_RPC_URL`, `SOROBAN_NETWORK_PASSPHRASE`, optional `SOROBAN_CONTRACT_ID`, `SOROBAN_BACKUP_RPC_URL`, hedging options
- Integrations (optional): `SHOPIFY_*`, `STRIPE_*`, Razorpay settings

The file is the authoritative, commented reference.

## Running locally

Requires Node.js 22 (as in CI) and Docker for the dev stack. CI uses pnpm (`pnpm-lock.yaml`); `package-lock.json` also exists and the Dockerfile uses `npm ci`.

```bash
docker compose -f ops/dev/docker-compose.yml up -d   # Postgres, Redis, mock Soroban RPC (seeded dev data)
cp .env.example .env
pnpm install            # or: npm install
pnpm run migrate        # apply SQL migrations
pnpm run dev            # http://localhost:3000
```

Other scripts: `build`, `start`, `lint`, `migrate:rollback`, `migrate:verify-rollback`, `docs:routes`, `docs:openapi`, `sbom:generate`, `perf:k6:*`, `soak`, `pact:test`, `test:mutation`. Reset the dev stack with `docker compose -f ops/dev/docker-compose.yml down -v`.

## Testing

`pnpm test` runs Vitest (`vitest.config.ts`); `pnpm run test:coverage` adds coverage; `pnpm run pact:test` runs consumer contract tests (`tests/pact/`). Load/soak tooling lives in `ops/k6` and `scripts/soak-attestations.ts`.

## CI and deployment

`.github/workflows/ci.yml` (push/PR to `main`) installs with `pnpm install --frozen-lockfile --ignore-scripts` and runs `tsc --noCheck --noEmit`. It is a minimal build gate, not the full test suite.

The `Dockerfile` builds with `npm ci` and `npm run build`, and its `HEALTHCHECK` targets `/api/health/live`. For Kubernetes use `/api/health/live` for liveness and `/api/health/ready` for readiness. Production requires `JWT_SECRET`, `ALLOWED_ORIGINS` and `DATABASE_URL`. Operational runbooks: [docs/runbooks/](docs/runbooks/README.md).

## Documentation

See [docs/index.md](docs/index.md). Other root notes: `IMPLEMENTATION_NOTES.md`, `SHOPIFY_OAUTH_STATE_SECURITY.md`, `MERKLE_TREE_TEST_IMPLEMENTATION.md`, `TODO.md`.

Note: older README text referenced `security-audit.yml` and `slsa-provenance.yml` workflows; those files are not currently in `.github/workflows/`. The related design docs remain in `docs/` ([security-provenance.md](docs/security-provenance.md), [slsa-provenance.md](docs/slsa-provenance.md)).
