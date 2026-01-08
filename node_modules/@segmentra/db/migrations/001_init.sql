-- Segmentra initial schema (v1)

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 9.1 Auth & RBAC
CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  username text UNIQUE NOT NULL,
  display_name text,
  email text,
  directory_subject text,
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_login_at timestamptz
);

CREATE TABLE IF NOT EXISTS roles (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  name text UNIQUE NOT NULL,
  description text
);

CREATE TABLE IF NOT EXISTS user_roles (
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_id uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  PRIMARY KEY (user_id, role_id)
);

CREATE TABLE IF NOT EXISTS secret_store (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  name text NOT NULL,
  type text NOT NULL,
  encrypted_blob bytea NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  rotated_at timestamptz,
  is_active boolean NOT NULL DEFAULT true
);

CREATE TABLE IF NOT EXISTS ldap_settings (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  enabled boolean NOT NULL DEFAULT false,
  url text,
  bind_dn text,
  bind_password_secret_id uuid REFERENCES secret_store(id),
  base_dn text,
  user_filter text,
  group_filter text,
  use_ldaps boolean NOT NULL DEFAULT true,
  tls_ca_cert_secret_id uuid REFERENCES secret_store(id),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ad_group_role_map (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  ad_group_dn text NOT NULL,
  role_id uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE
);

-- 9.2 Inventory
CREATE TABLE IF NOT EXISTS vlans (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  vlan_tag int NOT NULL,
  name text NOT NULL,
  description text
);

CREATE TABLE IF NOT EXISTS tags (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  name text UNIQUE NOT NULL,
  description text
);

CREATE TABLE IF NOT EXISTS hosts (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  hostname text UNIQUE NOT NULL,
  mgmt_ip inet,
  ssh_port int NOT NULL DEFAULT 22,
  environment text,
  os_family text,
  firewall_backend text,
  vlan_id uuid REFERENCES vlans(id),
  enabled boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS host_tags (
  host_id uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  tag_id uuid NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
  PRIMARY KEY (host_id, tag_id)
);

CREATE TABLE IF NOT EXISTS host_interfaces (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  host_id uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  name text NOT NULL,
  role text NOT NULL,
  ip_address inet,
  cidr int,
  vlan_id uuid REFERENCES vlans(id),
  is_primary boolean NOT NULL DEFAULT false,
  enabled boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- 9.3 Policies
CREATE TABLE IF NOT EXISTS policy_sets (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  name text NOT NULL,
  description text,
  scope_type text NOT NULL,
  scope_tag_id uuid REFERENCES tags(id),
  scope_vlan_id uuid REFERENCES vlans(id),
  created_by uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS policy_set_hosts (
  policy_set_id uuid NOT NULL REFERENCES policy_sets(id) ON DELETE CASCADE,
  host_id uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  PRIMARY KEY (policy_set_id, host_id)
);

CREATE TABLE IF NOT EXISTS policy_versions (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  policy_set_id uuid NOT NULL REFERENCES policy_sets(id) ON DELETE CASCADE,
  version_number int NOT NULL,
  status text NOT NULL,
  change_summary text,
  created_by uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  submitted_at timestamptz,
  approved_by uuid REFERENCES users(id),
  approved_at timestamptz,
  rejected_by uuid REFERENCES users(id),
  rejected_at timestamptz,
  rejection_reason text,
  interface_scope_type text NOT NULL,
  interface_scope_roles text[],
  interface_scope_names text[],
  is_high_risk boolean NOT NULL DEFAULT false
);

CREATE TABLE IF NOT EXISTS policy_rules (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  policy_version_id uuid NOT NULL REFERENCES policy_versions(id) ON DELETE CASCADE,
  order_index int NOT NULL,
  action text NOT NULL,
  protocol text NOT NULL,
  ports text,
  source_type text NOT NULL,
  source_value text NOT NULL,
  log_mode text NOT NULL,
  comment text,
  use_policy_interface_scope boolean NOT NULL DEFAULT true,
  interface_scope_type text,
  interface_scope_roles text[],
  interface_scope_names text[]
);

-- 9.4 Deployments & artifacts
CREATE TABLE IF NOT EXISTS deployments (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  policy_version_id uuid NOT NULL REFERENCES policy_versions(id),
  mode text NOT NULL,
  target_query jsonb NOT NULL,
  target_count int NOT NULL DEFAULT 0,
  created_by uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  started_at timestamptz,
  finished_at timestamptz,
  status text NOT NULL DEFAULT 'QUEUED',
  requires_approval boolean NOT NULL DEFAULT false,
  approved_by uuid REFERENCES users(id),
  approved_at timestamptz,
  canary_size int,
  batch_size int
);

CREATE TABLE IF NOT EXISTS deployment_hosts (
  deployment_id uuid NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
  host_id uuid NOT NULL REFERENCES hosts(id),
  status text NOT NULL DEFAULT 'PENDING',
  started_at timestamptz,
  finished_at timestamptz,
  message text,
  applied_hash text,
  rollback_performed boolean NOT NULL DEFAULT false,
  PRIMARY KEY (deployment_id, host_id)
);

CREATE TABLE IF NOT EXISTS deployment_artifacts (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  deployment_id uuid NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
  bundle_path text NOT NULL,
  bundle_hash text NOT NULL,
  manifest jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS execution_runs (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  deployment_id uuid NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
  executor_type text NOT NULL,
  command text NOT NULL,
  exit_code int,
  stdout_path text,
  stderr_path text,
  started_at timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz,
  status text NOT NULL DEFAULT 'RUNNING'
);

-- 9.5 Auditing
CREATE TABLE IF NOT EXISTS audit_events (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  actor_user_id uuid REFERENCES users(id),
  action text NOT NULL,
  entity_type text NOT NULL,
  entity_id uuid NOT NULL,
  timestamp timestamptz NOT NULL DEFAULT now(),
  ip_address inet,
  metadata jsonb
);

-- 9.6 SSH creds
CREATE TABLE IF NOT EXISTS ssh_credentials (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  name text NOT NULL,
  username text NOT NULL,
  private_key_secret_id uuid NOT NULL REFERENCES secret_store(id),
  passphrase_secret_id uuid REFERENCES secret_store(id),
  scope_type text NOT NULL,
  scope_id uuid,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- indexes
CREATE INDEX IF NOT EXISTS idx_hosts_vlan_id ON hosts(vlan_id);
CREATE INDEX IF NOT EXISTS idx_host_tags_tag_id ON host_tags(tag_id);
CREATE INDEX IF NOT EXISTS idx_policy_versions_policy_set ON policy_versions(policy_set_id);
CREATE INDEX IF NOT EXISTS idx_policy_rules_policy_version ON policy_rules(policy_version_id);
CREATE INDEX IF NOT EXISTS idx_deployments_policy_version ON deployments(policy_version_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events(timestamp);



