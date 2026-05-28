/**
 * Global test setup — runs before every test file.
 *
 * Sets up environment variables required by modules that are eagerly evaluated
 * at import time (e.g. src/db/client.ts). These values are intentionally
 * pointing to a non-existent database; the application-level repositories are
 * mocked or never actually called in integration tests that use the shared
 * in-memory store, so no real connection is made.
 *
 * @module tests/setup
 */

// Provide minimal env vars so that eagerly-evaluated modules don't throw
// during import. The values below are fake — no real database is used in
// unit/integration tests (repositories are backed by in-memory stores).
process.env.DATABASE_URL =
  process.env.DATABASE_URL ?? 'postgresql://test:test@localhost:5432/veritasor_test';

process.env.JWT_SECRET =
  process.env.JWT_SECRET ?? 'supersecretjwttokenthatisfortycharacterslong!!';

process.env.NODE_ENV = process.env.NODE_ENV ?? 'test';
