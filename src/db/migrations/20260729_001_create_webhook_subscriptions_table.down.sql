-- Migration: 20260729_001_create_webhook_subscriptions_table (down)
-- Drops the webhook_subscriptions table and its indexes.

DROP TABLE IF EXISTS webhook_subscriptions CASCADE;
