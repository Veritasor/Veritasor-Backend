-- Migration: 20261124_001_create_revenue_entries
-- Store normalized Kafka revenue entries with idempotent writes. A redelivered
-- message with the same (source, entry_id) pair must never create a second row.

CREATE TABLE IF NOT EXISTS revenue_entries (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  entry_id   TEXT NOT NULL,
  source     TEXT NOT NULL,
  amount     NUMERIC(20, 4) NOT NULL,
  currency   TEXT NOT NULL,
  entry_type TEXT NOT NULL CHECK (entry_type IN ('payment', 'refund')),
  event_at   TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT revenue_entries_source_entry_id_key UNIQUE (source, entry_id)
);

CREATE INDEX IF NOT EXISTS revenue_entries_event_at_idx ON revenue_entries (event_at);
