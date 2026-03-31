
-- Migration for the Initial Schema

-- Enable UUID generation
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

--Users table
CREATE TABLE IF NOT EXISTS users (
  id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username              VARCHAR(64) NOT NULL UNIQUE,

  -- Email stored encrypted (AES-256-GCM via Node crypto module)
  -- If this DB is leaked, email addresses remain ciphertext
  email_encrypted       TEXT,

  -- Argon2id hash
  password_hash         TEXT NOT NULL,

  role                  VARCHAR(16) NOT NULL DEFAULT 'user'
                          CHECK (role IN ('user', 'admin', 'moderator')),

  -- Brute-force lockout tracking
  failed_login_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until          TIMESTAMPTZ,

  created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for username lookups (used on every login)
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

--Feedback table
CREATE TABLE IF NOT EXISTS feedback (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id           UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

  -- Sanitized message as express-validator strips dangerous chars upstream
  message           TEXT NOT NULL,

  -- File metadata — UUID is the actual stored filename
  file_uuid         UUID,
  original_filename VARCHAR(255),
  file_mime_type    VARCHAR(64),
  file_size_bytes   INTEGER,

  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_feedback_user_id ON feedback(user_id);

--Audit log table
CREATE TABLE IF NOT EXISTS audit_log (
  id          BIGSERIAL PRIMARY KEY,
  event       VARCHAR(64) NOT NULL,
  user_id     UUID REFERENCES users(id) ON DELETE SET NULL,
  ip_address  INET,
  details     JSONB,               -- Flexible structured metadata
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_log_event      ON audit_log(event);
CREATE INDEX IF NOT EXISTS idx_audit_log_user_id    ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at DESC);


--updated_at trigger
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
