-- Up Migration
-- Warnings produced while generating a NetworkPolicy (skipped rules, ipBlock/CNI caveats) are kept
-- with the manifest so they can be shown again when the policy is applied.
ALTER TABLE k8s_network_policies ADD COLUMN IF NOT EXISTS warnings jsonb NOT NULL DEFAULT '[]'::jsonb;

-- Down Migration
ALTER TABLE k8s_network_policies DROP COLUMN IF EXISTS warnings;
