-- Migration: 20261124_002_webhook_subscription_previous_secret
-- Add the previous signing secret columns used for a bounded dual-signing
-- window when a webhook subscription secret is rotated. Values are stored in
-- the same encrypted format as webhook_subscriptions.secret.

ALTER TABLE webhook_subscriptions
  ADD COLUMN IF NOT EXISTS previous_secret TEXT,
  ADD COLUMN IF NOT EXISTS previous_secret_version INTEGER,
  ADD COLUMN IF NOT EXISTS previous_secret_expires_at TIMESTAMPTZ;

COMMENT ON COLUMN webhook_subscriptions.previous_secret IS 'Encrypted previous signing secret retained during the rotation grace window';
COMMENT ON COLUMN webhook_subscriptions.previous_secret_version IS 'Version number of the previous signing secret';
COMMENT ON COLUMN webhook_subscriptions.previous_secret_expires_at IS 'Timestamp after which the previous signing secret must no longer be accepted';
