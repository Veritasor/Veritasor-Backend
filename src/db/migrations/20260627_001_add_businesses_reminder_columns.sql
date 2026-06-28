-- Migration: 20260627_001_add_businesses_reminder_columns
-- Add period-alignment and reminder-tracking columns to the businesses table.

ALTER TABLE businesses
  ADD COLUMN IF NOT EXISTS reporting_period   VARCHAR(16)  NOT NULL DEFAULT 'monthly',
  ADD COLUMN IF NOT EXISTS reporting_timezone TEXT         NOT NULL DEFAULT 'UTC',
  ADD COLUMN IF NOT EXISTS last_reminder_sent_at TIMESTAMPTZ;

COMMENT ON COLUMN businesses.reporting_period   IS 'Attestation reporting cadence: weekly or monthly';
COMMENT ON COLUMN businesses.reporting_timezone IS 'IANA timezone for period boundary calculations (e.g. America/New_York)';
COMMENT ON COLUMN businesses.last_reminder_sent_at IS 'UTC timestamp of the most recent reminder; NULL if never sent';

ALTER TABLE businesses
  ADD CONSTRAINT businesses_reporting_period_check
    CHECK (reporting_period IN ('weekly', 'monthly'));
