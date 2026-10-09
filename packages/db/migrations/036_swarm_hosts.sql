-- Up Migration
-- Docker Swarm nodes and Docker-published ports.
--   swarm_cluster: name that groups the nodes of one swarm (NULL = not a Swarm node). The other
--                  enabled hosts with the same name are the peers whose cluster ports are always allowed.
--   swarm_role:    manager | worker (managers also accept 2377/tcp from their peers).
--   swarm_addr:    address the node uses in the swarm (--advertise-addr); defaults to mgmt_ip.
--   swarm_encrypted_overlay: allow IPsec ESP between nodes (overlay networks created with --opt encrypted).
--   docker_published_ports: apply the inbound policy rules also to traffic Docker publishes with
--                  DNAT (published ports, Swarm routing mesh), which never reaches the INPUT chain.
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS swarm_cluster text;
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS swarm_role text;
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS swarm_addr text;
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS swarm_encrypted_overlay boolean NOT NULL DEFAULT false;
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS docker_published_ports boolean NOT NULL DEFAULT false;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'hosts_swarm_role_check') THEN
    ALTER TABLE hosts ADD CONSTRAINT hosts_swarm_role_check CHECK (swarm_role IS NULL OR swarm_role IN ('manager', 'worker'));
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_hosts_swarm_cluster ON hosts(swarm_cluster) WHERE swarm_cluster IS NOT NULL;

-- Down Migration
DROP INDEX IF EXISTS idx_hosts_swarm_cluster;
ALTER TABLE hosts DROP CONSTRAINT IF EXISTS hosts_swarm_role_check;
ALTER TABLE hosts DROP COLUMN IF EXISTS docker_published_ports;
ALTER TABLE hosts DROP COLUMN IF EXISTS swarm_encrypted_overlay;
ALTER TABLE hosts DROP COLUMN IF EXISTS swarm_addr;
ALTER TABLE hosts DROP COLUMN IF EXISTS swarm_role;
ALTER TABLE hosts DROP COLUMN IF EXISTS swarm_cluster;
