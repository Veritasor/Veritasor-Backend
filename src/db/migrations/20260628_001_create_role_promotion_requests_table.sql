-- Migration: create role promotion requests table
-- Target: PostgreSQL

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS role_promotion_requests (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  target_user_id UUID NOT NULL,
  requested_role VARCHAR(24) NOT NULL,
  requested_by_admin_id UUID NOT NULL,
  status VARCHAR(24) NOT NULL DEFAULT 'pending',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  approved_by_admin_id UUID,
  approved_at TIMESTAMPTZ,
  CONSTRAINT role_promotion_requests_status_check
    CHECK (status IN ('pending', 'approved', 'expired', 'rejected')),
  CONSTRAINT role_promotion_requests_role_check
    CHECK (requested_role IN ('user', 'business_admin', 'admin'))
);

CREATE INDEX IF NOT EXISTS role_promotion_requests_target_user_id_idx
  ON role_promotion_requests (target_user_id);

CREATE INDEX IF NOT EXISTS role_promotion_requests_status_idx
  ON role_promotion_requests (status);

CREATE INDEX IF NOT EXISTS role_promotion_requests_created_at_idx
  ON role_promotion_requests (created_at DESC);
