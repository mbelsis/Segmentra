-- Add firewall audit sessions table for log-only firewall auditing

CREATE TABLE IF NOT EXISTS firewall_audit_sessions (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  host_id uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  status text NOT NULL DEFAULT 'RUNNING',
  duration_minutes integer NOT NULL,
  started_at timestamptz NOT NULL DEFAULT now(),
  scheduled_restore_at timestamptz NOT NULL,
  restored_at timestamptz,
  backup_path text,
  log_file_path text,
  log_data jsonb,
  created_by uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_firewall_audit_sessions_host_id ON firewall_audit_sessions(host_id);
CREATE INDEX IF NOT EXISTS idx_firewall_audit_sessions_status ON firewall_audit_sessions(status);
CREATE INDEX IF NOT EXISTS idx_firewall_audit_sessions_scheduled_restore_at ON firewall_audit_sessions(scheduled_restore_at) WHERE status = 'RUNNING';
