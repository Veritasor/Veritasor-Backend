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

All API routes are versioned and mounted under `/api/v1`. This enables future compatibility with `/api/v2`, `/api/v3`, etc.

- **Versioning approach:** Middleware-based with request-level `apiVersion` tracking
- **Response headers:** Include `API-Version` for client awareness
- **Current version:** v1
- **Future extensions:** Add routers to `/api/v2`, `/api/v3` as needed

## API (current)

| Method | Path                      | Description              |
|--------|---------------------------|--------------------------|
| GET    | `/api/v1/health`          | Health check             |
| GET    | `/api/v1/attestations`    | List attestations (stub) |
| POST   | `/api/v1/attestations`    | Submit attestation (stub)|

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
