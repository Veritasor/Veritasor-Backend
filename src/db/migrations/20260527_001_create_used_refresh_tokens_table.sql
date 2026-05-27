-- Migration: 20260527_001_create_used_refresh_tokens_table
-- Persists consumed refresh token JTIs so rotation protection survives
-- restarts and is shared across all instances.
--
-- TTL strategy: rows are inserted with an explicit expires_at derived from
-- the token's exp claim (7-day refresh lifetime). A periodic cleanup job
-- (or a pg_cron task) can DELETE WHERE expires_at < NOW() to reclaim space.
-- The unique constraint on jti is the replay-prevention guard.

CREATE TABLE IF NOT EXISTS used_refresh_tokens (
  jti        TEXT        PRIMARY KEY,
  user_id    TEXT        NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index to make TTL-based cleanup fast
CREATE INDEX IF NOT EXISTS used_refresh_tokens_expires_at_idx
  ON used_refresh_tokens (expires_at);
