-- Add optional policy expiry support for time-limited deployments

ALTER TABLE policy_versions ADD COLUMN IF NOT EXISTS expires_at timestamptz;
ALTER TABLE policy_versions ADD COLUMN IF NOT EXISTS expiry_action text NOT NULL DEFAULT 'NOTIFY_ONLY';

ALTER TABLE deployments ADD COLUMN IF NOT EXISTS expires_at timestamptz;
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS expiry_action text NOT NULL DEFAULT 'NOTIFY_ONLY';
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS expired boolean NOT NULL DEFAULT false;

CREATE INDEX IF NOT EXISTS idx_deployments_expires_at ON deployments(expires_at) WHERE expires_at IS NOT NULL AND expired = false;
