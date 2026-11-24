-- Rollback for 20261123_001_add_users_profile_column

ALTER TABLE users
  DROP COLUMN IF EXISTS profile;
