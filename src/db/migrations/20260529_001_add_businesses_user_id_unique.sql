-- Migration: 20260529_001_add_businesses_user_id_unique
-- Enforce one-business-per-user at the database layer.

CREATE UNIQUE INDEX IF NOT EXISTS businesses_user_id_unique_idx
  ON businesses (user_id);
