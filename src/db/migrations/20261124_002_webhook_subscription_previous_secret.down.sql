ALTER TABLE webhook_subscriptions
  DROP COLUMN IF EXISTS previous_secret_expires_at,
  DROP COLUMN IF EXISTS previous_secret_version,
  DROP COLUMN IF EXISTS previous_secret;
