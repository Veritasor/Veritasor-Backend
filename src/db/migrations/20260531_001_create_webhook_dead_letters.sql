-- Migration: 20260531_001_create_webhook_dead_letters
-- Creates dead-letter table webhook_dead_letters to store failed webhooks.

CREATE TABLE IF NOT EXISTS webhook_dead_letters (
  id            SERIAL PRIMARY KEY,
  provider      TEXT NOT NULL,
  event_id      TEXT NOT NULL,
  payload_hash  TEXT NOT NULL,
  error_code    TEXT NOT NULL,
  attempt_count INTEGER NOT NULL DEFAULT 1,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT webhook_dead_letters_provider_event_id_key UNIQUE (provider, event_id)
);
