-- Migration: 20260729_001_create_webhook_subscriptions_table
-- Creates webhook_subscriptions table for persistent webhook subscription management
-- with per-event filter DSL stored as JSONB.

CREATE TABLE IF NOT EXISTS webhook_subscriptions (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  business_id       TEXT NOT NULL,
  url               TEXT NOT NULL,
  secret            TEXT NOT NULL,
  event_filters     JSONB DEFAULT '{}'::jsonb,
  enabled           BOOLEAN NOT NULL DEFAULT true,
  max_payload_size  INTEGER,
  secret_version    INTEGER NOT NULL DEFAULT 1,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_webhook_subs_business_id ON webhook_subscriptions(business_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_webhook_subs_business_url ON webhook_subscriptions(business_id, url);

COMMENT ON TABLE webhook_subscriptions IS 'Persistent webhook subscriptions with per-event filter DSL';
COMMENT ON COLUMN webhook_subscriptions.event_filters IS 'JSONB map of event types to boolean or filter objects. e.g. {"attestation.created":true,"attestation.updated":{"status":"completed"}}';
COMMENT ON COLUMN webhook_subscriptions.secret_version IS 'Monotonically increasing version for HMAC secret rotation tracking';
COMMENT ON COLUMN webhook_subscriptions.max_payload_size IS 'Optional max payload size in bytes. Exceeding this causes delivery rejection.';
