-- Allow SSH credentials to authenticate with either a private key or a password.

ALTER TABLE ssh_credentials
  ALTER COLUMN private_key_secret_id DROP NOT NULL;

ALTER TABLE ssh_credentials
  ADD COLUMN IF NOT EXISTS password_secret_id uuid REFERENCES secret_store(id);

ALTER TABLE ssh_credentials
  ADD COLUMN IF NOT EXISTS auth_method text NOT NULL DEFAULT 'KEY';

UPDATE ssh_credentials
SET auth_method = 'KEY'
WHERE auth_method IS NULL OR auth_method = '';

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'ssh_credentials_auth_method_valid'
  ) THEN
    ALTER TABLE ssh_credentials
      ADD CONSTRAINT ssh_credentials_auth_method_valid
      CHECK (auth_method IN ('KEY', 'PASSWORD'));
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'ssh_credentials_auth_payload_present'
  ) THEN
    ALTER TABLE ssh_credentials
      ADD CONSTRAINT ssh_credentials_auth_payload_present
      CHECK (
        (auth_method = 'KEY' AND private_key_secret_id IS NOT NULL)
        OR
        (auth_method = 'PASSWORD' AND password_secret_id IS NOT NULL)
      );
  END IF;
END $$;
