-- Add policy recommendations from audit session analysis

CREATE TABLE IF NOT EXISTS policy_recommendations (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  audit_session_id uuid NOT NULL REFERENCES firewall_audit_sessions(id) ON DELETE CASCADE,
  host_id uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  status text NOT NULL DEFAULT 'PENDING',
  recommended_rules jsonb NOT NULL DEFAULT '[]',
  confidence_score numeric(5,2) NOT NULL DEFAULT 0,
  reviewed_by uuid REFERENCES users(id),
  reviewed_at timestamptz,
  applied_policy_version_id uuid REFERENCES policy_versions(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_policy_recommendations_audit_session ON policy_recommendations(audit_session_id);
CREATE INDEX IF NOT EXISTS idx_policy_recommendations_host ON policy_recommendations(host_id);
CREATE INDEX IF NOT EXISTS idx_policy_recommendations_status ON policy_recommendations(status);
