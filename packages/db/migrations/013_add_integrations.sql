-- Add integrations framework for SIEM, SOAR, vulnerability DB, and threat intelligence

CREATE TABLE IF NOT EXISTS integrations (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  type text NOT NULL,
  provider text NOT NULL,
  name text NOT NULL,
  description text,
  enabled boolean NOT NULL DEFAULT false,
  config jsonb NOT NULL DEFAULT '{}',
  credentials_secret_id uuid REFERENCES secret_store(id) ON DELETE SET NULL,
  last_sync_at timestamptz,
  last_sync_status text,
  created_by uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS integration_events (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  integration_id uuid NOT NULL REFERENCES integrations(id) ON DELETE CASCADE,
  direction text NOT NULL DEFAULT 'outbound',
  event_type text NOT NULL,
  payload jsonb NOT NULL DEFAULT '{}',
  status text NOT NULL DEFAULT 'PENDING',
  error_message text,
  created_at timestamptz NOT NULL DEFAULT now(),
  processed_at timestamptz
);

CREATE TABLE IF NOT EXISTS host_vulnerabilities (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  host_id uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  integration_id uuid NOT NULL REFERENCES integrations(id) ON DELETE CASCADE,
  cve_id text NOT NULL,
  severity text NOT NULL DEFAULT 'medium',
  title text,
  description text,
  status text NOT NULL DEFAULT 'open',
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  patched_at timestamptz
);

CREATE TABLE IF NOT EXISTS threat_intel_entries (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  integration_id uuid NOT NULL REFERENCES integrations(id) ON DELETE CASCADE,
  entry_type text NOT NULL,
  value text NOT NULL,
  threat_type text,
  confidence numeric(5,2) NOT NULL DEFAULT 50,
  source_name text,
  expires_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_integrations_type ON integrations(type);
CREATE INDEX IF NOT EXISTS idx_integrations_enabled ON integrations(enabled) WHERE enabled = true;
CREATE INDEX IF NOT EXISTS idx_integration_events_integration ON integration_events(integration_id);
CREATE INDEX IF NOT EXISTS idx_integration_events_status ON integration_events(status);
CREATE INDEX IF NOT EXISTS idx_host_vulnerabilities_host ON host_vulnerabilities(host_id);
CREATE INDEX IF NOT EXISTS idx_host_vulnerabilities_cve ON host_vulnerabilities(cve_id);
CREATE INDEX IF NOT EXISTS idx_host_vulnerabilities_severity ON host_vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_threat_intel_entries_type_value ON threat_intel_entries(entry_type, value);
CREATE INDEX IF NOT EXISTS idx_threat_intel_entries_expires ON threat_intel_entries(expires_at) WHERE expires_at IS NOT NULL;
