-- Store security audit scan results for persistence and history

CREATE TABLE IF NOT EXISTS security_audit_results (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  findings jsonb NOT NULL DEFAULT '[]',
  summary jsonb NOT NULL DEFAULT '{}',
  triggered_by uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_security_audit_results_created ON security_audit_results(created_at);
