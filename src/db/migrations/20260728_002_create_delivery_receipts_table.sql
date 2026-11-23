-- Migration: 20260728_002_create_delivery_receipts_table
-- Creates delivery_receipts table for per-attempt webhook delivery receipts
-- to support compliance audit trail with retry history.

CREATE TABLE IF NOT EXISTS delivery_receipts (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  delivery_id       UUID NOT NULL,
  attempt_number    INTEGER NOT NULL CHECK (attempt_number > 0),
  subscription_id   TEXT NOT NULL,
  business_id       TEXT NOT NULL,
  url               TEXT NOT NULL,
  status_code       INTEGER NOT NULL,
  latency_ms        INTEGER NOT NULL,
  signature_version INTEGER NOT NULL DEFAULT 1,
  signature         TEXT NOT NULL,
  response_body     TEXT,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_delivery_receipts_delivery_id   ON delivery_receipts(delivery_id);
CREATE INDEX IF NOT EXISTS idx_delivery_receipts_business_id   ON delivery_receipts(business_id);
CREATE INDEX IF NOT EXISTS idx_delivery_receipts_created_at    ON delivery_receipts(created_at);

COMMENT ON TABLE delivery_receipts IS 'Per-attempt webhook delivery receipts for compliance audit trail';
COMMENT ON COLUMN delivery_receipts.signature_version IS 'HMAC signature algorithm version (currently 1 = sha256)';
COMMENT ON COLUMN delivery_receipts.latency_ms IS 'Round-trip time for the delivery attempt in milliseconds';
COMMENT ON COLUMN delivery_receipts.response_body IS 'Truncated response body from the receiving endpoint for debugging';
