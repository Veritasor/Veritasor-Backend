-- Migration: 20261123_001_add_users_profile_column
-- Add the nullable `profile` JSONB column to the users table so the
-- PATCH /api/users/me `profile` field has a home in the database.
-- `name` already exists on the users table (001_create_users_table).

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS profile JSONB;

COMMENT ON COLUMN users.profile IS 'Free-form user profile object (e.g. display preferences); not security-sensitive.';
