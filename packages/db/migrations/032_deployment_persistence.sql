-- Up Migration
-- Reboot persistence of the deployed rules with the distribution's own service
-- (nftables.service, netfilter-persistent, iptables-services), reported per host:
--   persistence_status:  persisted | not_persisted | removed | unknown (NULL = not reported,
--                        e.g. host failed before the persistence step or deployed by an older version)
--   persistence_method:  nftables.service | netfilter-persistent | iptables-services
--   persistence_message: summary + warnings (firewalld active, package missing, unsupported distro)
ALTER TABLE deployment_hosts ADD COLUMN IF NOT EXISTS persistence_status text;
ALTER TABLE deployment_hosts ADD COLUMN IF NOT EXISTS persistence_method text;
ALTER TABLE deployment_hosts ADD COLUMN IF NOT EXISTS persistence_message text;

-- Down Migration
ALTER TABLE deployment_hosts DROP COLUMN IF EXISTS persistence_message;
ALTER TABLE deployment_hosts DROP COLUMN IF EXISTS persistence_method;
ALTER TABLE deployment_hosts DROP COLUMN IF EXISTS persistence_status;
