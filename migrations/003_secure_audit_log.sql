-- Migration to enforce Least Privilege and Secure Audit Logging

-- 1. Alter details to TEXT to support an encrypted AES-256 string
ALTER TABLE audit_log ALTER COLUMN details TYPE TEXT USING details::TEXT;

-- 2. Create the restricted application user
DO $$ 
BEGIN
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'app_user') THEN
    CREATE ROLE app_user WITH LOGIN PASSWORD 'securepass123!';
  END IF;
END
$$;

-- 3. Grant necessary DML privileges on the schema
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_user;

-- 4. Automatically grant privileges on tables created in the future
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_user;

-- 5. Grant sequence privileges (crucial for BIGSERIAL on audit_log.id)
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO app_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO app_user;
