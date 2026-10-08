-- Up Migration
-- Automatic policy-expiry actions (REMOVE / REVERT). Every statement is idempotent.

-- Free-text note on a deployment (e.g. "Automatic revert: deployment <id> expired").
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS notes text;

-- A system-created revert deployment points at the deployment whose expiry triggered it.
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS revert_of_deployment_id uuid REFERENCES deployments(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_deployments_revert_of ON deployments(revert_of_deployment_id) WHERE revert_of_deployment_id IS NOT NULL;

-- Outcome of the automatic expiry action, e.g.
-- {"action":"REMOVE","result":"REMOVED","processedAt":"...","hostCounts":{...},"message":"..."}
-- {"action":"REVERT","result":"REVERT_STARTED","revertDeploymentId":"...","revertToVersionNumber":3}
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS expiry_outcome jsonb;

-- Per-host result of the expiry action (REMOVED / FAILED / SKIPPED / REVERT_QUEUED).
ALTER TABLE deployment_hosts ADD COLUMN IF NOT EXISTS expiry_status text;
ALTER TABLE deployment_hosts ADD COLUMN IF NOT EXISTS expiry_message text;
ALTER TABLE deployment_hosts ADD COLUMN IF NOT EXISTS expiry_processed_at timestamptz;

