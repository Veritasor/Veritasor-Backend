-- Rollback: 20260627_001_add_businesses_reminder_columns
ALTER TABLE businesses
  DROP CONSTRAINT IF EXISTS businesses_reporting_period_check,
  DROP COLUMN IF EXISTS reporting_period,
  DROP COLUMN IF EXISTS reporting_timezone,
  DROP COLUMN IF EXISTS last_reminder_sent_at;
