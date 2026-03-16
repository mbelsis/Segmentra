-- Add OT/IoT asset management and flow collection

CREATE TABLE IF NOT EXISTS iot_assets (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  name text NOT NULL,
  description text,
  asset_type text NOT NULL DEFAULT 'sensor',
  vendor text,
  model text,
  firmware_version text,
  mac_address text,
  ip_address text,
  vlan_id uuid REFERENCES vlans(id) ON DELETE SET NULL,
  zone text,
  criticality text NOT NULL DEFAULT 'medium',
  fingerprint jsonb NOT NULL DEFAULT '{}',
  discovered_by text,
  enabled boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS iot_asset_tags (
  asset_id uuid NOT NULL REFERENCES iot_assets(id) ON DELETE CASCADE,
  tag_id uuid NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
  PRIMARY KEY (asset_id, tag_id)
);

CREATE TABLE IF NOT EXISTS flow_collectors (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  name text NOT NULL,
  description text,
  type text NOT NULL DEFAULT 'netflow_v5',
  listen_address text NOT NULL,
  listen_port integer NOT NULL DEFAULT 2055,
  config jsonb NOT NULL DEFAULT '{}',
  enabled boolean NOT NULL DEFAULT false,
  last_received_at timestamptz,
  created_by uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS iot_observed_flows (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  collector_id uuid REFERENCES flow_collectors(id) ON DELETE SET NULL,
  source_ip text NOT NULL,
  source_port integer,
  dest_ip text NOT NULL,
  dest_port integer,
  protocol text NOT NULL DEFAULT 'tcp',
  bytes_total bigint NOT NULL DEFAULT 0,
  packets_total bigint NOT NULL DEFAULT 0,
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  flow_count integer NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS enforcement_points (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  name text NOT NULL,
  description text,
  type text NOT NULL DEFAULT 'gateway_firewall',
  vendor text,
  model text,
  mgmt_ip text NOT NULL,
  ssh_credential_id uuid REFERENCES ssh_credentials(id) ON DELETE SET NULL,
  enabled boolean NOT NULL DEFAULT true,
  last_sync_at timestamptz,
  created_by uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS enforcement_acls (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  enforcement_point_id uuid NOT NULL REFERENCES enforcement_points(id) ON DELETE CASCADE,
  policy_version_id uuid REFERENCES policy_versions(id) ON DELETE SET NULL,
  acl_name text NOT NULL,
  acl_config text NOT NULL,
  status text NOT NULL DEFAULT 'PENDING',
  deployed_hash text,
  deployed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_iot_assets_ip ON iot_assets(ip_address);
CREATE INDEX IF NOT EXISTS idx_iot_assets_mac ON iot_assets(mac_address);
CREATE INDEX IF NOT EXISTS idx_iot_assets_type ON iot_assets(asset_type);
CREATE INDEX IF NOT EXISTS idx_iot_assets_vlan ON iot_assets(vlan_id);
CREATE INDEX IF NOT EXISTS idx_iot_observed_flows_src ON iot_observed_flows(source_ip);
CREATE INDEX IF NOT EXISTS idx_iot_observed_flows_dst ON iot_observed_flows(dest_ip);
CREATE INDEX IF NOT EXISTS idx_iot_observed_flows_collector ON iot_observed_flows(collector_id);
CREATE INDEX IF NOT EXISTS idx_enforcement_acls_point ON enforcement_acls(enforcement_point_id);
CREATE INDEX IF NOT EXISTS idx_enforcement_acls_version ON enforcement_acls(policy_version_id);
