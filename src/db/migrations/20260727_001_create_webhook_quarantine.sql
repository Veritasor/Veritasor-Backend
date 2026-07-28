-- Migration: 20260727_001_create_webhook_quarantine
-- Creates quarantine table for malformed DLQ entries (poison pills) and fingerprint tracking.

CREATE TABLE IF NOT EXISTS webhook_quarantine (
  id                SERIAL PRIMARY KEY,
  provider          TEXT NOT NULL,
  event_id          TEXT NOT NULL,
  payload_hash      TEXT NOT NULL,
  error_code        TEXT NOT NULL,
  fingerprint       TEXT NOT NULL,
  attempt_count     INTEGER NOT NULL DEFAULT 1,
  quarantine_reason TEXT NOT NULL DEFAULT 'poison_pill_threshold_exceeded',
  quarantined_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  released_at       TIMESTAMPTZ,
  released_by       TEXT,
  CONSTRAINT webhook_quarantine_provider_event_id_key UNIQUE (provider, event_id)
);

CREATE INDEX IF NOT EXISTS idx_webhook_quarantine_fingerprint ON webhook_quarantine(fingerprint);

CREATE TABLE IF NOT EXISTS webhook_failure_fingerprints (
  fingerprint       TEXT PRIMARY KEY,
  provider          TEXT NOT NULL,
  payload_hash      TEXT NOT NULL,
  error_code        TEXT NOT NULL,
  failure_count     INTEGER NOT NULL DEFAULT 1,
  first_seen_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
