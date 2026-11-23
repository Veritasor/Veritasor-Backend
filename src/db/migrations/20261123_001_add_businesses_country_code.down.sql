-- Rollback: 20261123_001_add_businesses_country_code
-- Reverse the EXPAND phase: drop the country_code column added by the
-- corresponding up migration.

ALTER TABLE businesses
  DROP COLUMN IF EXISTS country_code;
