-- Migration: create attestations table
-- Target: PostgreSQL

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS attestations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  business_id UUID NOT NULL,
  period VARCHAR(32) NOT NULL,
  merkle_root TEXT NOT NULL,
  tx_hash TEXT,
  status VARCHAR(24) NOT NULL DEFAULT 'submitted',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT attestations_status_check
    CHECK (status IN ('pending', 'submitted', 'confirmed', 'failed', 'revoked')),
  CONSTRAINT attestations_business_period_unique
    UNIQUE (business_id, period)
);

CREATE INDEX IF NOT EXISTS attestations_business_id_idx
  ON attestations (business_id);

CREATE INDEX IF NOT EXISTS attestations_status_idx
  ON attestations (status);

CREATE INDEX IF NOT EXISTS attestations_created_at_idx
  ON attestations (created_at DESC);

CREATE OR REPLACE FUNCTION set_attestations_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_attestations_updated_at ON attestations;
CREATE TRIGGER trg_attestations_updated_at
BEFORE UPDATE ON attestations
FOR EACH ROW
EXECUTE FUNCTION set_attestations_updated_at();

