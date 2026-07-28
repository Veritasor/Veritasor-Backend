-- Down migration: 20260728_001_add_dlq_integration_shard

DROP INDEX IF EXISTS idx_webhook_dead_letters_integration;
DROP INDEX IF EXISTS idx_webhook_quarantine_integration;

ALTER TABLE webhook_dead_letters DROP COLUMN IF EXISTS integration;
ALTER TABLE webhook_quarantine DROP COLUMN IF EXISTS integration;
