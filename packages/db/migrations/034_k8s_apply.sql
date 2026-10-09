-- Up Migration
-- Applying NetworkPolicies to a cluster from Segmentra. Cluster credentials (bearer token or
-- kubeconfig) and the optional CA certificate are stored encrypted in secret_store and referenced
-- by k8s_clusters.credentials_secret_id / ca_cert_secret_id (columns from migration 015).
ALTER TABLE k8s_clusters ADD COLUMN IF NOT EXISTS tls_skip_verify boolean NOT NULL DEFAULT false;

-- Apply tracking on generated manifests. status: GENERATED | APPLIED | FAILED | REMOVED | SUPERSEDED
-- (SUPERSEDED = an older row of the same cluster/namespace/name replaced by a newer applied one).
ALTER TABLE k8s_network_policies ADD COLUMN IF NOT EXISTS applied_at timestamptz;
ALTER TABLE k8s_network_policies ADD COLUMN IF NOT EXISTS applied_by uuid REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE k8s_network_policies ADD COLUMN IF NOT EXISTS last_error text;
ALTER TABLE k8s_network_policies ADD COLUMN IF NOT EXISTS live_state text;
ALTER TABLE k8s_network_policies ADD COLUMN IF NOT EXISTS live_checked_at timestamptz;

-- Down Migration
ALTER TABLE k8s_network_policies DROP COLUMN IF EXISTS live_checked_at;
ALTER TABLE k8s_network_policies DROP COLUMN IF EXISTS live_state;
ALTER TABLE k8s_network_policies DROP COLUMN IF EXISTS last_error;
ALTER TABLE k8s_network_policies DROP COLUMN IF EXISTS applied_by;
ALTER TABLE k8s_network_policies DROP COLUMN IF EXISTS applied_at;
ALTER TABLE k8s_clusters DROP COLUMN IF EXISTS tls_skip_verify;
