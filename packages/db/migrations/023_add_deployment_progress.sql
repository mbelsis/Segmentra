-- Add progress tracking for async deployment execution

ALTER TABLE deployments ADD COLUMN IF NOT EXISTS progress jsonb;
-- progress format: { "phase": "checking"|"deploying"|"complete", "checked": 5, "totalToCheck": 20, "deployed": 3, "totalToDeploy": 18, "currentBatch": ["host1","host2"...], "warnings": [...] }
