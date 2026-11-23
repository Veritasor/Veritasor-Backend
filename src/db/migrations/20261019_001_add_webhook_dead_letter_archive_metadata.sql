-- Migration: 20261019_001_add_webhook_dead_letter_archive_metadata
-- Adds archive state used by DeadLetterQueue on the existing webhook DLQ table.

ALTER TABLE webhook_dead_letters
  ADD COLUMN IF NOT EXISTS archived BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS archive_location TEXT,
  ADD COLUMN IF NOT EXISTS archive_encrypted BOOLEAN NOT NULL DEFAULT FALSE;
