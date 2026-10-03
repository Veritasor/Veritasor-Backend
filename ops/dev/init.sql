-- ============================================================================
-- Veritasor Development Seed Data
-- ============================================================================
-- Applied automatically by the postgres container on first boot.
-- Creates tables (if they don't exist) and populates baseline data.
--
-- Provides baseline data so developers can immediately exercise:
--   - Authentication (test user with known credentials)
--   - Business management (pre-seeded business)
--   - Attestation workflows (sample attestation record)
--
-- ⚠️  SECURITY: These credentials are for LOCAL DEVELOPMENT ONLY.
--     Never use in staging or production environments.
-- ============================================================================

-- ── Enable extensions ───────────────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ── Tables (self-contained — no separate migration needed for dev) ──────────

CREATE TABLE IF NOT EXISTS users (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email         TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  name          TEXT NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS businesses (
  id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id              UUID NOT NULL,
  name                 TEXT NOT NULL,
  email                TEXT NOT NULL,
  industry             TEXT,
  description          TEXT,
  website              TEXT,
  reporting_period     TEXT NOT NULL DEFAULT 'monthly',
  reporting_timezone   TEXT NOT NULL DEFAULT 'UTC',
  last_reminder_sent_at TIMESTAMPTZ,
  created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS businesses_user_id_unique_idx
  ON businesses (user_id);

CREATE TABLE IF NOT EXISTS attestations (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  business_id UUID NOT NULL,
  period      VARCHAR(32) NOT NULL,
  merkle_root TEXT NOT NULL,
  tx_hash     TEXT,
  status      VARCHAR(24) NOT NULL DEFAULT 'submitted',
  version     INTEGER NOT NULL DEFAULT 1,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT attestations_status_check
    CHECK (status IN ('pending', 'submitted', 'confirmed', 'failed', 'revoked')),
  CONSTRAINT attestations_business_period_unique
    UNIQUE (business_id, period)
);

CREATE TABLE IF NOT EXISTS schema_migrations (
  version     TEXT PRIMARY KEY,
  applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ── Test User ───────────────────────────────────────────────────────────────
-- Email: dev@veritasor.local
-- Password: devpassword123
-- The bcrypt hash below corresponds to "devpassword123" (10 rounds).

INSERT INTO users (id, email, password_hash, name, created_at, updated_at)
VALUES (
  '10000000-0000-0000-0000-000000000001',
  'dev@veritasor.local',
  '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy',
  'Dev User',
  NOW(),
  NOW()
) ON CONFLICT (id) DO NOTHING;

-- ── Test Business ───────────────────────────────────────────────────────────

INSERT INTO businesses (id, user_id, name, email, industry, website, created_at, updated_at)
VALUES (
  '20000000-0000-0000-0000-000000000001',
  '10000000-0000-0000-0000-000000000001',
  'Veritasor Demo Inc.',
  'dev@veritasor.local',
  'Technology',
  'https://demo.veritasor.local',
  NOW(),
  NOW()
) ON CONFLICT (id) DO NOTHING;

-- ── Sample Attestation ──────────────────────────────────────────────────────

INSERT INTO attestations (id, business_id, period, merkle_root, status, version, created_at)
VALUES (
  '30000000-0000-0000-0000-000000000001',
  '20000000-0000-0000-0000-000000000001',
  '2026-07',
  'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  'submitted',
  1,
  NOW()
) ON CONFLICT (id) DO NOTHING;
