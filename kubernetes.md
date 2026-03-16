# Kubernetes Microsegmentation

## Overview

Segmentra's Kubernetes module extends microsegmentation to containerized workloads by managing **Kubernetes NetworkPolicy** resources agentlessly via the K8s API. There is no sidecar, no service mesh, and no DaemonSet — Segmentra connects to the Kubernetes API server directly, discovers workloads, and applies NetworkPolicy manifests.

This allows teams to manage firewall policies for both Linux hosts (via SSH/nftables/iptables) and Kubernetes containers (via K8s API/NetworkPolicy) from a single platform, using the same tags, approval workflow, and audit trail.

---

## How It Works

### Traditional Host Deployment vs. Kubernetes Deployment

| | Linux Hosts | Kubernetes |
|---|---|---|
| **Connection** | SSH to each host | K8s API server |
| **Policy format** | nftables/iptables rules | NetworkPolicy YAML/JSON manifests |
| **Enforcement** | netfilter in the Linux kernel | CNI plugin (Calico, Cilium, Weave, etc.) |
| **Targeting** | Host IPs, tags, VLANs | Pod labels, namespace selectors |
| **Executor** | `packages/executor` (Ansible/SSH) | K8s API client (direct HTTP) |
| **Ansible playbook** | Used for deployment | **Not used** — deployment is via K8s API |

### Architecture

```
┌──────────────────────────────────────┐
│  Segmentra API                        │
│                                       │
│  1. Take approved policy version      │
│  2. Translate rules → NetworkPolicy   │
│     manifest (JSON)                   │
│  3. POST to K8s API server            │
│     /apis/networking.k8s.io/v1/       │
│       namespaces/{ns}/networkpolicies │
└──────────────┬───────────────────────┘
               │ HTTPS (K8s API)
               ▼
┌──────────────────────────────────────┐
│  Kubernetes API Server                │
│                                       │
│  Stores NetworkPolicy resource        │
└──────────────┬───────────────────────┘
               │
               ▼
┌──────────────────────────────────────┐
│  CNI Plugin (Calico/Cilium/Weave)    │
│                                       │
│  Reads NetworkPolicy resources        │
│  Enforces rules on pod traffic        │
│  (eBPF, iptables, or IPVS)           │
└──────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────┐
│  Pods                                 │
│  Traffic filtered per NetworkPolicy   │
└──────────────────────────────────────┘
```

### Key Point: CNI Plugin Required

Kubernetes NetworkPolicy resources are only enforced if the cluster's CNI plugin supports them. The default `kubenet` CNI does **not** enforce NetworkPolicy. You need one of:

- **Calico** (most common)
- **Cilium** (eBPF-based)
- **Weave Net**
- **Antrea**
- **Kube-router**

Segmentra creates the NetworkPolicy resources — the CNI plugin enforces them.

---

## Concepts

### Clusters

A cluster represents a Kubernetes cluster that Segmentra manages. Each cluster has:

- **API Server URL** — The endpoint (e.g., `https://k8s-api.example.com:6443`)
- **Authentication** — How Segmentra authenticates to the K8s API:
  - `kubeconfig` — A kubeconfig file stored as an encrypted secret
  - `service_account` — A ServiceAccount token with RBAC permissions
  - `token` — A bearer token (e.g., from `kubectl create token`)
- **CA Certificate** — Optional TLS CA cert for API server verification
- **Default Namespace** — The namespace used when none is specified

Credentials are stored in the existing `secret_store` table with AES-256-GCM encryption — the same mechanism used for SSH keys.

### Workloads

Workloads are Kubernetes resources discovered via the sync operation:

| Kind | Description |
|------|-------------|
| **Pod** | Individual running container(s) |
| **Deployment** | Manages ReplicaSets and Pods |
| **StatefulSet** | Manages stateful Pods with stable identities |
| **DaemonSet** | Runs a Pod on every node |
| **Service** | Network endpoint that routes to Pods |

For each workload, Segmentra stores:
- Namespace, kind, name
- **Labels** (JSONB) — The key data for NetworkPolicy selectors
- Pod IPs and service cluster IPs
- Service ports

### Label-to-Tag Mapping

The bridge between Kubernetes and Segmentra's policy model:

```
K8s Label:  app=nginx        ←→  Segmentra Tag: web-server
K8s Label:  tier=database     ←→  Segmentra Tag: db-server
K8s Label:  env=production    ←→  Segmentra Tag: production
```

This allows you to write a single Segmentra policy like "web-server can access db-server on TCP 5432" and have it apply to both:
- Linux hosts tagged `web-server` → deployed as nftables rules via SSH
- K8s pods labeled `app=nginx` → deployed as NetworkPolicy via K8s API

### Network Policies

Segmentra translates its policy rules into Kubernetes NetworkPolicy manifests:

**Segmentra rule:**
```
Direction: IN, Action: ALLOW, Protocol: TCP, Ports: 5432
Source Type: CIDR, Source Value: 10.0.1.0/24
```

**Generated K8s NetworkPolicy:**
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: segmentra-db-policy
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - ipBlock:
            cidr: 10.0.1.0/24
      ports:
        - port: 5432
          protocol: TCP
```

The manifest is stored as JSONB in the database along with a SHA-256 hash for drift detection.

---

## Usage Workflow

### Step 1: Add a Cluster

Go to **Kubernetes** in the sidebar and click **+ Add Cluster**:

1. **Name** — Descriptive name (e.g., "Production EKS Cluster")
2. **API Server URL** — The K8s API endpoint (e.g., `https://10.0.1.50:6443`)
3. **Auth Type** — Choose authentication method:
   - **Kubeconfig** — Upload a kubeconfig file (stored encrypted)
   - **Service Account** — Provide a ServiceAccount token
   - **Bearer Token** — Provide a static token
4. **Default Namespace** — e.g., `default` or `production`

### Step 2: Store Credentials

Before the cluster can connect, store the authentication credentials:
- Go to **Admin → SSH Credentials** (or use the API)
- Create a secret with the kubeconfig content, service account token, or bearer token
- Link the secret to the cluster configuration

### Step 3: Sync Workloads

Click **Sync** on the cluster to discover workloads:
- Segmentra queries the K8s API for namespaces, pods, deployments, statefulsets, daemonsets, and services
- Workloads are stored with their labels, IPs, and service ports
- The namespace list is populated for filtering

### Step 4: Map Labels to Tags

In the workload browser, map Kubernetes labels to Segmentra tags:
- Select a workload
- Click **Map Tag** and choose a Segmentra tag
- This creates a `k8s_workload_tags` entry linking the workload to the tag

Label-to-tag mappings can be:
- **Manual** — You explicitly map a workload to a tag
- **Label sync** — Automatic mapping based on label conventions (e.g., `app=X` → tag `X`)

### Step 5: Create and Approve a Policy

Use the normal Segmentra policy workflow:
1. Create a **Policy Set** with scope type TAG (or the new K8S scope)
2. Create a **Policy Version** with rules
3. Submit for approval → Approve

### Step 6: Deploy NetworkPolicy

In the Kubernetes page, click **Deploy Policy**:
1. Select the approved **Policy Version**
2. Choose the target **Namespace**
3. Enter a **Policy Name** (the K8s resource name)
4. Segmentra translates the rules into a NetworkPolicy manifest
5. The manifest is applied to the cluster via the K8s API

### Step 7: Monitor

View deployed NetworkPolicies in the **Network Policies** tab:
- See which policies are deployed in which namespaces
- Track deployment status and hashes
- Link back to the Segmentra policy version that generated them

---

## NetworkPolicy Translation Rules

Segmentra policy rules are translated to K8s NetworkPolicy as follows:

| Segmentra Rule | K8s NetworkPolicy |
|---------------|-------------------|
| Direction: `IN` + Action: `ALLOW` | `ingress` rule with `from` selector |
| Direction: `OUT` + Action: `ALLOW` | `egress` rule with `to` selector |
| Direction: `BOTH` + Action: `ALLOW` | Both `ingress` and `egress` rules |
| Source Type: `CIDR` | `ipBlock.cidr` selector |
| Source Type: `TAG` / `VLAN` / `HOST` | Resolved to `ipBlock.cidr: 0.0.0.0/0` (fallback) |
| Protocol: `tcp` / `udp` | `ports[].protocol: TCP / UDP` |
| Ports: `80,443` | Multiple `ports[]` entries |
| Action: `DENY` | **Not included** — K8s NetworkPolicy is allow-list only; unmatched traffic is denied by default |

### Important: K8s NetworkPolicy Is Allow-List

Kubernetes NetworkPolicy works differently from nftables/iptables:
- If **no** NetworkPolicy selects a pod → all traffic is allowed (open by default)
- If **any** NetworkPolicy selects a pod → only traffic matching a rule is allowed (default deny for that direction)
- There is **no explicit DENY** rule — you deny by omission

This means Segmentra's DENY rules are not directly translatable. Instead, the presence of a NetworkPolicy with ALLOW rules implicitly denies everything else.

---

## Permissions Required

The Kubernetes credentials used by Segmentra need these RBAC permissions:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: segmentra-manager
rules:
  # Workload discovery
  - apiGroups: [""]
    resources: ["pods", "services", "namespaces"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["apps"]
    resources: ["deployments", "statefulsets", "daemonsets"]
    verbs: ["get", "list", "watch"]
  # NetworkPolicy management
  - apiGroups: ["networking.k8s.io"]
    resources: ["networkpolicies"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
```

For namespace-scoped access, use a `Role` + `RoleBinding` instead of `ClusterRole`.

---

## Multi-Cluster Support

Segmentra supports managing multiple Kubernetes clusters from a single instance:

- Each cluster has its own API server URL and credentials
- Workloads are scoped to their cluster (`k8s_workloads.cluster_id`)
- NetworkPolicies are deployed per-cluster
- The UI shows a cluster sidebar for switching between clusters

This is useful for organizations with:
- Separate clusters per environment (dev/staging/prod)
- Multi-region clusters
- Different clusters for different teams

---

## Key Design Decisions

- **Agentless via K8s API** — No sidecar, no DaemonSet, no service mesh dependency. Segmentra only needs API server access.
- **Separate from SSH executor** — K8s deployment does not use the Ansible playbook or SSH Direct executor. It's a direct API call.
- **Label-based targeting** — K8s NetworkPolicy uses label selectors, not IP sets. This is fundamentally different from the host compiler which resolves tags to IP addresses.
- **Unified tag model** — K8s labels are mapped to the same Segmentra tags used for hosts, enabling cross-platform policy management.
- **Credentials in secret_store** — Same AES-256-GCM encrypted storage used for SSH keys.
- **Manifest storage** — The full NetworkPolicy JSON is stored in the database for audit and drift detection.

---

## Comparison with Host-Based Microsegmentation

| Feature | Linux Hosts | Kubernetes |
|---------|------------|------------|
| **Inventory** | `hosts` table | `k8s_workloads` table |
| **Grouping** | Tags, VLANs | Labels, Namespaces |
| **Policy format** | nftables/iptables text | NetworkPolicy JSON manifest |
| **Deployment** | SSH + Ansible | K8s API (HTTPS) |
| **Enforcement** | Linux kernel netfilter | CNI plugin (Calico, Cilium, etc.) |
| **Rollback** | Restore backup via SSH | Delete NetworkPolicy resource |
| **Drift detection** | Hash comparison via SSH | Hash comparison via K8s API |
| **Audit trail** | `audit_events` table | `audit_events` table (same) |
| **Approval workflow** | Same DRAFT → APPROVED → DEPLOYED | Same DRAFT → APPROVED → DEPLOYED |

---

## API Endpoints

### Clusters
- `GET /api/k8s/clusters` — List all clusters
- `GET /api/k8s/clusters/:id` — Get cluster with workload summary and namespaces
- `POST /api/k8s/clusters` — Add cluster. Body: `{ name, apiServerUrl, authType, credentialsSecretId?, caCertSecretId?, defaultNamespace?, enabled? }`
- `PUT /api/k8s/clusters/:id` — Update cluster configuration
- `DELETE /api/k8s/clusters/:id` — Remove cluster and all associated workloads/policies
- `POST /api/k8s/clusters/:id/sync` — Sync workloads from the K8s API

### Workloads
- `GET /api/k8s/clusters/:id/workloads` — List workloads (filter by `namespace`, `kind`)
- `POST /api/k8s/workloads/:workloadId/map-tag` — Map a workload to a Segmentra tag. Body: `{ tagId }`

### Network Policies
- `GET /api/k8s/clusters/:id/network-policies` — List deployed NetworkPolicies
- `POST /api/k8s/clusters/:id/deploy-policy` — Deploy a Segmentra policy as a K8s NetworkPolicy. Body: `{ policyVersionId, namespace, policyName }`

---

## Database Tables

### `k8s_clusters`
| Column | Type | Description |
|--------|------|-------------|
| `id` | uuid PK | Cluster identifier |
| `name` | text | Display name |
| `description` | text | Optional description |
| `api_server_url` | text | K8s API endpoint |
| `auth_type` | text | `kubeconfig`, `service_account`, or `token` |
| `credentials_secret_id` | uuid FK → secret_store | Encrypted credentials |
| `ca_cert_secret_id` | uuid FK → secret_store | Optional CA certificate |
| `default_namespace` | text | Default namespace |
| `last_sync_at` | timestamptz | Last workload sync time |
| `last_sync_status` | text | Last sync result |
| `enabled` | boolean | Whether cluster is active |

### `k8s_workloads`
| Column | Type | Description |
|--------|------|-------------|
| `id` | uuid PK | Workload identifier |
| `cluster_id` | uuid FK → k8s_clusters | Parent cluster |
| `namespace` | text | K8s namespace |
| `kind` | text | Pod, Deployment, StatefulSet, DaemonSet, Service |
| `name` | text | Resource name |
| `labels` | jsonb | K8s labels (key-value pairs) |
| `pod_ips` | text[] | Pod IP addresses |
| `service_cluster_ip` | text | Service ClusterIP |
| `service_ports` | jsonb | Service port definitions |

### `k8s_workload_tags`
| Column | Type | Description |
|--------|------|-------------|
| `workload_id` | uuid FK → k8s_workloads | Workload |
| `tag_id` | uuid FK → tags | Segmentra tag |
| `source` | text | `label_sync` or `manual` |

### `k8s_network_policies`
| Column | Type | Description |
|--------|------|-------------|
| `id` | uuid PK | Policy identifier |
| `cluster_id` | uuid FK → k8s_clusters | Target cluster |
| `policy_version_id` | uuid FK → policy_versions | Source Segmentra policy |
| `namespace` | text | Target namespace |
| `policy_name` | text | K8s resource name |
| `manifest` | jsonb | Full NetworkPolicy JSON |
| `status` | text | PENDING, DEPLOYED |
| `deployed_hash` | text | SHA-256 of manifest |
| `deployed_at` | timestamptz | Deployment timestamp |
