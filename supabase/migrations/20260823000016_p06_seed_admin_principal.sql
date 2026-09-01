-- Migration: 20260823000016_p06_seed_admin_principal.sql
-- Purpose: Seed authoritative admin principal account with real bcrypt hash
-- Document Reference: Architecture V2.0.1 Document 13 (Authentication & Principal Context)
--
-- CREDENTIALS DOCUMENTATION FOR INITIAL ROTATION:
-- Default Administrator Account:
--   Email: admin@caim.internal
--   Plaintext Password: Admin2026!SecureRoot#
--   Bcrypt Hash (10 rounds): $2b$10$yETjGKPiH3Nge4JRueLT.uS/0uPXYGUVmSgQZQzpjzwhB/7M/bNl6
--   Roles: {"admin", "operator", "auditor", "reviewer", "analyst", "product_user"}
--
-- Security Auditor Account:
--   Email: auditor@caim.internal
--   Plaintext Password: Admin123!Secure
--   Bcrypt Hash (10 rounds): $2b$10$FqsaxeCzDIEfRURLkub1heoy8ugi5cC3TMGMqGDDtWFbIIdOogVce
--   Roles: {"auditor", "analyst", "product_user"}

INSERT INTO security.principals (
  principal_id,
  email,
  hashed_password,
  external_identity_provider_id,
  roles,
  tenant_id,
  created_at
)
VALUES
  (
    '00000000-0000-0000-0001-000000000001',
    'admin@caim.internal',
    '$2b$10$yETjGKPiH3Nge4JRueLT.uS/0uPXYGUVmSgQZQzpjzwhB/7M/bNl6',
    NULL,
    ARRAY['admin', 'operator', 'auditor', 'reviewer', 'analyst', 'product_user']::text[],
    NULL,
    now()
  ),
  (
    '00000000-0000-0000-0001-000000000002',
    'auditor@caim.internal',
    '$2b$10$FqsaxeCzDIEfRURLkub1heoy8ugi5cC3TMGMqGDDtWFbIIdOogVce',
    NULL,
    ARRAY['auditor', 'analyst', 'product_user']::text[],
    NULL,
    now()
  )
ON CONFLICT (email) DO UPDATE SET
  hashed_password = EXCLUDED.hashed_password,
  roles = EXCLUDED.roles;
