-- Up Migration
-- SSH credential scoping. Every statement is idempotent.
--
-- ssh_credentials.scope_type:
--   'GLOBAL' default for every host (scope_id NULL)
--   'TAG'    hosts carrying the tag  (scope_id = tags.id)
--   'VLAN'   hosts in the VLAN       (scope_id = vlans.id)
--   'HOST'   one host                (scope_id = hosts.id)
--   'NONE'   stored only: never chosen automatically; used by discovery target sets or by an
--            explicit host assignment (hosts.ssh_credential_id) (scope_id NULL)
-- scope_id is polymorphic, so it has no FK: a credential whose tag/VLAN/host was deleted simply
-- matches nothing.
--
-- Resolution for a host (apps/api/src/services/ssh-credentials.ts):
--   hosts.ssh_credential_id (explicit assignment) -> HOST -> TAG (any of the host's tags)
--   -> VLAN (the host's VLAN) -> GLOBAL; within a level: highest priority, then newest.

ALTER TABLE ssh_credentials ADD COLUMN IF NOT EXISTS priority integer NOT NULL DEFAULT 0;

-- Discovery used to store its inline credentials as scope_type 'TAG' without a tag; they were
-- never selected automatically. They are "stored only" credentials.
UPDATE ssh_credentials SET scope_type = 'NONE'
 WHERE scope_type IN ('TAG', 'VLAN', 'HOST') AND scope_id IS NULL;
UPDATE ssh_credentials SET scope_type = 'NONE'
 WHERE scope_type NOT IN ('GLOBAL', 'TAG', 'VLAN', 'HOST', 'NONE');
UPDATE ssh_credentials SET scope_id = NULL
 WHERE scope_type IN ('GLOBAL', 'NONE') AND scope_id IS NOT NULL;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ssh_credentials_scope_type_valid') THEN
    ALTER TABLE ssh_credentials
      ADD CONSTRAINT ssh_credentials_scope_type_valid
      CHECK (scope_type IN ('GLOBAL', 'TAG', 'VLAN', 'HOST', 'NONE'));
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ssh_credentials_scope_id_matches_type') THEN
    ALTER TABLE ssh_credentials
      ADD CONSTRAINT ssh_credentials_scope_id_matches_type
      CHECK (
        (scope_type IN ('GLOBAL', 'NONE') AND scope_id IS NULL)
        OR (scope_type IN ('TAG', 'VLAN', 'HOST') AND scope_id IS NOT NULL)
      );
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_ssh_credentials_scope ON ssh_credentials(scope_type, scope_id);

-- Explicit per-host credential assignment; overrides scope resolution. Deleting the credential
-- reverts the host to automatic resolution (the API refuses such deletes with 409 first).
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS ssh_credential_id uuid REFERENCES ssh_credentials(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_hosts_ssh_credential_id ON hosts(ssh_credential_id) WHERE ssh_credential_id IS NOT NULL;

-- Down Migration
DROP INDEX IF EXISTS idx_hosts_ssh_credential_id;
ALTER TABLE hosts DROP COLUMN IF EXISTS ssh_credential_id;
DROP INDEX IF EXISTS idx_ssh_credentials_scope;
ALTER TABLE ssh_credentials DROP CONSTRAINT IF EXISTS ssh_credentials_scope_id_matches_type;
ALTER TABLE ssh_credentials DROP CONSTRAINT IF EXISTS ssh_credentials_scope_type_valid;
UPDATE ssh_credentials SET scope_type = 'TAG' WHERE scope_type = 'NONE';
ALTER TABLE ssh_credentials DROP COLUMN IF EXISTS priority;
