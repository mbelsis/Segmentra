-- Up Migration
-- Compliance evidence reports. A report is a point-in-time snapshot (what Segmentra knew when it was generated), kept
-- as generated so it can be handed to an auditor and re-downloaded unchanged. content_sha256 is the SHA-256 of the
-- canonical JSON of `content`; the API recomputes it on every read to show whether the snapshot is intact.
CREATE TABLE IF NOT EXISTS compliance_reports (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  title text NOT NULL,
  frameworks text[] NOT NULL,
  period_from timestamptz NOT NULL,
  period_to timestamptz NOT NULL,
  parameters jsonb NOT NULL DEFAULT '{}'::jsonb,
  summary jsonb NOT NULL DEFAULT '{}'::jsonb,
  content jsonb NOT NULL,
  content_sha256 text NOT NULL,
  generated_by uuid REFERENCES users(id) ON DELETE SET NULL,
  generated_by_username text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_compliance_reports_created ON compliance_reports(created_at DESC);

-- Down Migration
DROP TABLE IF EXISTS compliance_reports;
