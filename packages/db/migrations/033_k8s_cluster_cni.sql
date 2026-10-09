-- Up Migration
-- The CNI plugin enforces NetworkPolicy and treats ipBlock peers differently (Cilium does not
-- apply ipBlock to in-cluster pod traffic), so Segmentra records which one a cluster runs.
ALTER TABLE k8s_clusters ADD COLUMN IF NOT EXISTS cni text NOT NULL DEFAULT 'unknown';

-- Down Migration
ALTER TABLE k8s_clusters DROP COLUMN IF EXISTS cni;
