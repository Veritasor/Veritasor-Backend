-- Migration: 20261123_001_add_businesses_country_code
-- Add the ISO 3166-1 alpha-2 country code of the business registration
-- country to the businesses table. Nullable: existing rows keep NULL.

ALTER TABLE businesses
  ADD COLUMN IF NOT EXISTS country_code CHAR(2);

COMMENT ON COLUMN businesses.country_code IS 'ISO 3166-1 alpha-2 code of the business registration country (e.g., US, GB, NG)';
