-- Add Kubernetes cluster management for container microsegmentation

CREATE TABLE IF NOT EXISTS k8s_clusters (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  name text NOT NULL,
  description text,
  api_server_url text NOT NULL,
  auth_type text NOT NULL DEFAULT 'kubeconfig',
  credentials_secret_id uuid REFERENCES secret_store(id) ON DELETE SET NULL,
  ca_cert_secret_id uuid REFERENCES secret_store(id) ON DELETE SET NULL,
  default_namespace text DEFAULT 'default',
  last_sync_at timestamptz,
  last_sync_status text,
  enabled boolean NOT NULL DEFAULT true,
  created_by uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS k8s_workloads (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  cluster_id uuid NOT NULL REFERENCES k8s_clusters(id) ON DELETE CASCADE,
  namespace text NOT NULL,
  kind text NOT NULL,
  name text NOT NULL,
  labels jsonb NOT NULL DEFAULT '{}',
  pod_ips text[],
  service_cluster_ip text,
  service_ports jsonb,
  status text NOT NULL DEFAULT 'active',
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS k8s_workload_tags (
  workload_id uuid NOT NULL REFERENCES k8s_workloads(id) ON DELETE CASCADE,
  tag_id uuid NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
  source text NOT NULL DEFAULT 'label_sync',
  PRIMARY KEY (workload_id, tag_id)
);

CREATE TABLE IF NOT EXISTS k8s_network_policies (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  cluster_id uuid NOT NULL REFERENCES k8s_clusters(id) ON DELETE CASCADE,
  policy_version_id uuid REFERENCES policy_versions(id) ON DELETE SET NULL,
  namespace text NOT NULL,
  policy_name text NOT NULL,
  manifest jsonb NOT NULL DEFAULT '{}',
  status text NOT NULL DEFAULT 'PENDING',
  deployed_hash text,
  deployed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE policy_sets ADD COLUMN IF NOT EXISTS scope_k8s_cluster_id uuid REFERENCES k8s_clusters(id) ON DELETE SET NULL;
ALTER TABLE policy_sets ADD COLUMN IF NOT EXISTS scope_k8s_namespace text;

CREATE INDEX IF NOT EXISTS idx_k8s_workloads_cluster ON k8s_workloads(cluster_id);
CREATE INDEX IF NOT EXISTS idx_k8s_workloads_namespace ON k8s_workloads(cluster_id, namespace);
CREATE INDEX IF NOT EXISTS idx_k8s_network_policies_cluster ON k8s_network_policies(cluster_id);
CREATE INDEX IF NOT EXISTS idx_k8s_network_policies_version ON k8s_network_policies(policy_version_id);
