-- Migration: 20261021_001_webhook_subscription_secret_encryption
-- Webhook signing secrets are encrypted at rest with the app secret loader.
--
-- Existing rows may still contain plaintext secrets from older deployments.
-- The application transparently decrypts legacy values on read and re-encrypts
-- them when a subscription is created or updated. This migration intentionally
-- does not rewrite every row in place; it is a compatibility gate for the
-- encrypted format prefix used by the repository:
--
--   enc:v1:<iv_b64>:<ciphertext_and_auth_tag_b64>
--
-- Operationally, the deployment should provision WEBHOOK_SUBSCRIPTION_ENCRYPTION_KEY
-- via secretLoader (or SECRET_LOADER-backed secret management) before rotating
-- secrets or writing new subscriptions.

ALTER TABLE webhook_subscriptions
  ALTER COLUMN secret DROP NOT NULL;
