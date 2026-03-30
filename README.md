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

## Scripts

| Command          | Description                    |
|------------------|--------------------------------|
| `npm run dev`    | Start with tsx watch           |
| `npm run build`  | Compile TypeScript to `dist/`  |
| `npm run start`  | Run compiled `dist/index.js`   |
| `npm run lint`   | Run ESLint                     |
| `npm run migrate`| Run database migrations        |

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
