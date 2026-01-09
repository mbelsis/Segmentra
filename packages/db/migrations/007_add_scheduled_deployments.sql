-- Add scheduled_at field to deployments table for deferred deployments
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS scheduled_at timestamptz;

-- Add index for efficient querying of scheduled deployments
CREATE INDEX IF NOT EXISTS idx_deployments_scheduled_at ON deployments(scheduled_at) WHERE scheduled_at IS NOT NULL;
