-- Add policy test sessions for structured pre-enforcement testing

CREATE TABLE IF NOT EXISTS policy_test_sessions (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  policy_version_id uuid NOT NULL REFERENCES policy_versions(id) ON DELETE CASCADE,
  host_id uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  status text NOT NULL DEFAULT 'PENDING',
  duration_minutes integer NOT NULL DEFAULT 30,
  started_at timestamptz,
  scheduled_end_at timestamptz,
  completed_at timestamptz,
  backup_path text,
  log_file_path text,
  raw_log_data jsonb,
  analysis_results jsonb,
  created_by uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_policy_test_sessions_policy_version ON policy_test_sessions(policy_version_id);
CREATE INDEX IF NOT EXISTS idx_policy_test_sessions_host ON policy_test_sessions(host_id);
CREATE INDEX IF NOT EXISTS idx_policy_test_sessions_status ON policy_test_sessions(status);
CREATE INDEX IF NOT EXISTS idx_policy_test_sessions_scheduled_end ON policy_test_sessions(scheduled_end_at) WHERE status = 'RUNNING';
