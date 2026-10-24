-- Rollback for 20261019_001_add_webhook_dead_letter_archive_metadata

ALTER TABLE webhook_dead_letters
  DROP COLUMN IF EXISTS archive_encrypted,
  DROP COLUMN IF EXISTS archive_location,
  DROP COLUMN IF EXISTS archived;
