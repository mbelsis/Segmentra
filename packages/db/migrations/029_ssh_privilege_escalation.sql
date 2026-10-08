-- Up Migration
-- Agentless privilege escalation for SSH credentials. Every statement is idempotent.
--
-- sudo_mode:
--   'NOPASSWD'       sudo without a password (sudo -n; the behaviour before this migration)
--   'LOGIN_PASSWORD' sudo with the SSH login password (auth_method = 'PASSWORD' only)
--   'SUDO_PASSWORD'  sudo with a separate password stored in sudo_password_secret_id
-- Key credentials may additionally carry a key passphrase (passphrase_secret_id, existing column).
-- secret_store.type has no CHECK constraint; sudo passwords use type 'SUDO_PASSWORD' and key
-- passphrases 'SSH_KEY_PASSPHRASE'.

ALTER TABLE ssh_credentials ADD COLUMN IF NOT EXISTS sudo_mode text NOT NULL DEFAULT 'NOPASSWD';
ALTER TABLE ssh_credentials ADD COLUMN IF NOT EXISTS sudo_password_secret_id uuid REFERENCES secret_store(id);

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ssh_credentials_sudo_mode_valid') THEN
    ALTER TABLE ssh_credentials
      ADD CONSTRAINT ssh_credentials_sudo_mode_valid
      CHECK (sudo_mode IN ('NOPASSWD', 'LOGIN_PASSWORD', 'SUDO_PASSWORD'));
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ssh_credentials_sudo_mode_payload') THEN
    ALTER TABLE ssh_credentials
      ADD CONSTRAINT ssh_credentials_sudo_mode_payload
      CHECK (
        (sudo_mode = 'NOPASSWD')
        OR (sudo_mode = 'LOGIN_PASSWORD' AND auth_method = 'PASSWORD')
        OR (sudo_mode = 'SUDO_PASSWORD' AND sudo_password_secret_id IS NOT NULL)
      );
  END IF;
END $$;

-- Down Migration
ALTER TABLE ssh_credentials DROP CONSTRAINT IF EXISTS ssh_credentials_sudo_mode_payload;
ALTER TABLE ssh_credentials DROP CONSTRAINT IF EXISTS ssh_credentials_sudo_mode_valid;
ALTER TABLE ssh_credentials DROP COLUMN IF EXISTS sudo_password_secret_id;
ALTER TABLE ssh_credentials DROP COLUMN IF EXISTS sudo_mode;
