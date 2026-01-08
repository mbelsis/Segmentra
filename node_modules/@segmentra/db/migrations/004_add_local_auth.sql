-- Add local password authentication support
-- Add password_hash column for local users (nullable - LDAP users won't have this)
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash text;

-- Add index for faster lookups
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

