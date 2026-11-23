-- Migration: 20260728_001_add_dlq_integration_shard
-- Adds integration column and index to DLQ tables to support per-integration sharding and noisy-neighbor isolation.

ALTER TABLE webhook_dead_letters ADD COLUMN IF NOT EXISTS integration TEXT DEFAULT 'unknown';
ALTER TABLE webhook_quarantine ADD COLUMN IF NOT EXISTS integration TEXT DEFAULT 'unknown';

-- Backfill existing entries with provider name as integration, or fallback to 'unknown'
UPDATE webhook_dead_letters
SET integration = COALESCE(NULLIF(TRIM(provider), ''), 'unknown')
WHERE integration IS NULL OR integration = 'unknown' OR integration = '';

UPDATE webhook_quarantine
SET integration = COALESCE(NULLIF(TRIM(provider), ''), 'unknown')
WHERE integration IS NULL OR integration = 'unknown' OR integration = '';

-- Make integration NOT NULL after backfilling
ALTER TABLE webhook_dead_letters ALTER COLUMN integration SET NOT NULL;
ALTER TABLE webhook_quarantine ALTER COLUMN integration SET NOT NULL;

-- Create indexes for per-integration shard queries
CREATE INDEX IF NOT EXISTS idx_webhook_dead_letters_integration ON webhook_dead_letters(integration);
CREATE INDEX IF NOT EXISTS idx_webhook_quarantine_integration ON webhook_quarantine(integration);
