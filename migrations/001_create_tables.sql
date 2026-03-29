
-- Migration 001: Initial Schema

-- Enable UUID generation
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ─── Users table ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
  id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username              VARCHAR(64) NOT NULL UNIQUE,

  -- Email stored encrypted (AES-256-GCM via Node crypto module)
  -- If this DB is leaked, email addresses remain ciphertext
  email_encrypted       TEXT,

  -- Argon2id hash — NEVER store plaintext or bcrypt here
  password_hash         TEXT NOT NULL,

  role                  VARCHAR(16) NOT NULL DEFAULT 'user'
                          CHECK (role IN ('user', 'admin')),

  -- Brute-force lockout tracking
  failed_login_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until          TIMESTAMPTZ,

  created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for username lookups (used on every login)
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

-- ─── Feedback table ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS feedback (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id           UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

  -- Sanitized message — express-validator strips dangerous chars upstream
  message           TEXT NOT NULL,

  -- File metadata — UUID is the actual stored filename
  -- original_filename is untrusted user input, stored for display ONLY
  -- It is NEVER used in filesystem operations
  file_uuid         UUID,
  original_filename VARCHAR(255),
  file_mime_type    VARCHAR(64),
  file_size_bytes   INTEGER,

  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_feedback_user_id ON feedback(user_id);

-- ─── Audit log table ──────────────────────────────────────────
-- Stores structured security events for monitoring and incident response.
-- This is a separate table from application logs (winston files) —
-- DB-level audit log is harder to tamper with than flat files.
CREATE TABLE IF NOT EXISTS audit_log (
  id          BIGSERIAL PRIMARY KEY,
  event       VARCHAR(64) NOT NULL,
  user_id     UUID REFERENCES users(id) ON DELETE SET NULL,
  ip_address  INET,
  details     JSONB,               -- Flexible structured metadata
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_log_event     ON audit_log(event);
CREATE INDEX IF NOT EXISTS idx_audit_log_user_id   ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at DESC);

-- ─── Restricted DB access ─────────────────────────────────────
-- Create a limited-privilege application user.
-- This user can only SELECT/INSERT/UPDATE/DELETE on application tables.
-- Even if the app is compromised, the attacker cannot DROP tables
-- or access pg_shadow (password hashes of DB users).
--
-- Run these as the postgres superuser, then connect as 'appuser' in .env:
--
-- CREATE USER appuser WITH PASSWORD 'strong_password_here';
-- GRANT CONNECT ON DATABASE secureapp TO appuser;
-- GRANT USAGE ON SCHEMA public TO appuser;
-- GRANT SELECT, INSERT, UPDATE, DELETE ON users, feedback, audit_log TO appuser;
-- GRANT USAGE, SELECT ON SEQUENCE audit_log_id_seq TO appuser;
-- REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;

-- ─── updated_at trigger ───────────────────────────────────────
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER users_updated_at
  BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER feedback_updated_at
  BEFORE UPDATE ON feedback
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();
