-- Rollback migration: create role promotion requests table

DROP INDEX IF EXISTS role_promotion_requests_created_at_idx;
DROP INDEX IF EXISTS role_promotion_requests_status_idx;
DROP INDEX IF EXISTS role_promotion_requests_target_user_id_idx;
DROP TABLE IF EXISTS role_promotion_requests;
