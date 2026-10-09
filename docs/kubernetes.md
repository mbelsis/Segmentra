# Kubernetes Microsegmentation

## Overview

Segmentra's Kubernetes module generates **Kubernetes NetworkPolicy** manifests from approved Segmentra policy versions. You register clusters, generate a NetworkPolicy (Ingress only) for a namespace, and apply it either from Segmentra (with stored cluster credentials) or yourself with **kubectl** or your CI/CD pipeline.

With credentials stored, Segmentra talks to the Kubernetes API to **apply** a generated NetworkPolicy, **check** it for drift and **remove** it. It does not discover workloads (they are registered by hand) and does not read anything else from the cluster.

---

## How It Works

### Linux Host Deployment vs. Kubernetes

| | Linux Hosts | Kubernetes |
|---|---|---|
| **Connection** | SSH to each host | Kubernetes API over HTTPS with stored credentials (optional: you can also apply manifests yourself) |
| **Policy format** | nftables/iptables rules or native firewalld/UFW artifacts | NetworkPolicy JSON manifest |
| **Enforcement** | netfilter in the Linux kernel | CNI plugin (Calico, Cilium, Weave, etc.) |
| **Targeting** | Host IPs, tags, VLANs | All pods in the chosen namespace (`podSelector: {}`); sources become `ipBlock` CIDRs |
| **Executor** | `packages/executor` (Ansible/SSH) | Segmentra's Kubernetes client (`apps/api/src/services/k8s-client.ts`), or kubectl/CI/CD |
| **Ansible playbook** | Used for deployment | **Not used** |

### Flow

```
┌──────────────────────────────────────┐
│  Segmentra API                        │
│                                       │
│  1. Take approved policy version      │
│  2. Translate rules → NetworkPolicy   │
│     manifest (JSON, Ingress only,     │
│     labelled managed-by=segmentra)    │
│  3. Store manifest + warnings         │
└──────┬─────────────────────┬─────────┘
       │ Apply / Check /     │ Copy / Download
       │ Remove (HTTPS, with │
       │ stored credentials) ▼
       │            ┌─────────────────────┐
       │            │ kubectl / CI/CD     │
       │            │ applies the JSON    │
       │            └──────────┬──────────┘
       ▼                       ▼
┌──────────────────────────────────────┐
│  Kubernetes API Server                │
│  → CNI Plugin enforces policies      │
└──────────────────────────────────────┘
```

### Key Point: CNI Plugin Required

Kubernetes NetworkPolicy resources are only enforced if the cluster's CNI plugin supports them. The default `kubenet` CNI does **not** enforce NetworkPolicy. You need one of:

- **Calico** (most common)
- **Cilium** (eBPF-based)
- **Weave Net**
- **Antrea**
- **Kube-router**

Segmentra generates the NetworkPolicy resources; the CNI plugin enforces them once you apply them.

---

## Concepts

### Clusters

A cluster record describes a Kubernetes cluster. Each cluster has:

- **Name** and optional **Description**
- **API Server URL**, e.g. `https://k8s-api.example.com:6443`. With a kubeconfig the URL inside the kubeconfig is used and stored here
- **Auth Type**: `kubeconfig`, `service_account` or `token`
- **CNI Plugin**: `unknown` (default), `calico`, `cilium`, `kindnet`, `antrea`, `weave`, `kube-router` or `other`. It decides which warnings Segmentra shows when generating a NetworkPolicy (see below)
- **Default Namespace**, e.g. `default`

### Cluster credentials

To apply, check and remove policies from Segmentra, store credentials on the cluster (admin; in the UI when registering the cluster, with **Add / Replace credentials** on the Kubernetes page, or in **Admin → Kubernetes Credentials**, which lists every cluster next to the SSH credentials with Add, Replace, Remove and Test):

- **Kubeconfig** (auth type `kubeconfig`): the current context is used. It must carry **inline** credentials: a `token`, or `client-certificate-data` + `client-key-data` (and normally `certificate-authority-data`). Kubeconfigs that reference files (`certificate-authority`, `client-certificate`, `client-key`, `tokenFile`), `exec` credential plugins, `auth-provider` plugins or `proxy-url` are rejected, because the API server must not read files or run programs
- **Bearer token** (auth types `service_account` and `token`): the token plus, usually, the API server **CA certificate** (PEM). Without a CA, Segmentra verifies the API server against the system trust store

Credentials and the CA are encrypted with AES-256-GCM in `secret_store` (types `K8S_CREDENTIALS` and `TLS_CA_CERT`), exactly like SSH and LDAP secrets, and use the same key (`SEGMENTRA_KEK_B64`). They are write-only: the API only reports `has_credentials` / `has_ca_cert`, and they are decrypted in memory for the duration of a call. Certificate verification can be disabled per cluster (`tlsSkipVerify`); this is insecure and should only be used for tests. API server addresses in the link-local range (including cloud metadata) are refused, unless `SEGMENTRA_ALLOW_PRIVATE_WEBHOOKS=true`. The API server must be reachable from where the Segmentra API runs (for the Docker deployment, from inside the `segmentra-app` container).

Minimal RBAC for the account (use a dedicated service account):

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: { name: segmentra-networkpolicies }
rules:
  - apiGroups: ["networking.k8s.io"]
    resources: ["networkpolicies"]
    verbs: ["get", "list", "create", "update", "patch", "delete"]
```

Bind it with a `ClusterRoleBinding` (or a `RoleBinding` per namespace to limit Segmentra to some namespaces). A read-only account (`get`, `list`) can use **Test connection** and **Check** but not **Apply** or **Remove**. Generate a token with `kubectl create token <service-account> -n <namespace> --duration=<lifetime>`; tokens expire, so replace the stored one before then.

### ipBlock and the CNI

Segmentra expresses CIDR, HOST and VLAN sources, and the IP addresses of TAG sources, as `ipBlock` peers. NetworkPolicy leaves it to the CNI whether `ipBlock` matches traffic from inside the cluster, and the CNIs differ:

| CNI | `ipBlock` for in-cluster pod traffic |
|---|---|
| Calico, kindnet | Matched (verified by `npm run test:integration:k8s`) |
| **Cilium** | **Not matched.** Pod and node traffic is identified by Cilium identities, so `ipBlock` only matches clients outside the cluster. A default-deny policy built only from `ipBlock` peers therefore blocks all in-cluster clients |

When the cluster's CNI is `cilium` (or still `unknown`), generating a NetworkPolicy adds a warning for every rule whose sources became `ipBlock` peers. Set the CNI on the cluster so the warning is accurate.

For in-cluster clients use **workload tags**: register the workload (`POST /api/k8s/clusters/:id/workloads` with its pod labels), map it to a Segmentra tag, and use that TAG as the rule source. The tag's workloads become `namespaceSelector` (by `kubernetes.io/metadata.name`) plus `podSelector` (the workload's labels) peers, which work on every CNI. A TAG can combine host IPs (`ipBlock`) and labelled workloads (selectors) in the same rule. A workload without labels is skipped with a warning, because an empty `podSelector` would match every pod in the namespace.

### Workloads

The `k8s_workloads` table can hold workloads (namespace, kind, name, labels, pod IPs, service ClusterIP and ports), and the **Workloads** tab lists them with a namespace filter. Segmentra has no workload discovery: the **sync** endpoint returns `501 not_implemented`. In the UI, **+ Add workload** on the Workloads tab registers a workload (namespace, kind, name and at least one pod label) and the **+ tag** selector maps it to a Segmentra tag. Register workloads with `POST /api/k8s/clusters/:id/workloads` (re-posting the same namespace, kind and name updates its labels), or insert them directly (for example with the demo data script, `demo-data/seed-demo-data.js`).

### Workload-to-Tag Mapping

`POST /api/k8s/workloads/:workloadId/map-tag` links a workload to a Segmentra tag (`k8s_workload_tags`, source `manual`). In the UI it is the **+ tag** selector on each workload row (the **×** on a tag chip unmaps it). When a rule uses that TAG as its source, the mapped workloads of the target cluster become selector peers in the generated NetworkPolicy (see *ipBlock and the CNI*).

### Network Policies

Segmentra translates the rules of an approved (or deployed) policy version into one NetworkPolicy manifest:

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
  ingress:
    - from:
        - ipBlock:
            cidr: 10.0.1.0/24
      ports:
        - port: 5432
          protocol: TCP
```

Only `Ingress` is listed in `policyTypes`, matching Segmentra's model (inbound default deny, outbound default allow). Listing `Egress` would make Kubernetes deny all outbound traffic that is not listed, DNS included.

The manifest is stored as JSONB in `k8s_network_policies` with status `GENERATED` and a SHA-256 hash of the manifest.

---

## Usage Workflow

### Step 1: Register a Cluster (admin)

Go to **Kubernetes** in the sidebar and click **+ Add Cluster**. Fill in **Cluster Name**, **Auth Type**, **CNI Plugin** and **Default Namespace**. To let Segmentra apply policies, also paste the **kubeconfig** (the API server URL is taken from it) or the **bearer token** with the **API server URL** and **CA certificate**, then click **Register Cluster**. Use **Test connection** on the cluster to verify the credentials and read access to NetworkPolicies. Without credentials you can still generate manifests and apply them yourself.

### Step 2: Create and Approve a Policy

Use the normal Segmentra policy workflow:
1. Create a **Policy Set** (scope TAG, VLAN or HOST_LIST; the scope does not matter for Kubernetes export)
2. Create a **Policy Version** with rules
3. Submit for approval → Approve

### Step 3: Generate the NetworkPolicy (operator or admin)

Select the cluster, open the **Network Policies** tab and click **Generate NetworkPolicy**. Choose the **Policy Version** (approved or deployed versions only), the **Namespace** and the **NetworkPolicy Name**. Rules that NetworkPolicy cannot express are skipped and listed as warnings (see the translation table below).

### Step 4: Apply the NetworkPolicy

Each generated manifest in the **Network Policies** tab shows its status (`Generated`, `Applied`, `Apply failed`, `Removed`, `Superseded`), whether it is in sync on the cluster, and these actions:

- **Apply** / **Re-apply** (operator, admin; needs stored credentials): asks for confirmation (listing the generation warnings), then creates or updates the policy with server-side apply. If a policy with the same name exists that Segmentra did not create (no `app.kubernetes.io/managed-by: segmentra` label), Apply refuses and offers an explicit overwrite
- **Dry run**: asks the API server to validate the manifest without changing anything
- **Check**: compares the live policy with Segmentra's manifest and reports `In sync`, `Drifted` (edited on the cluster; Apply again to repair) or `Not present`
- **Remove**: deletes the policy from the cluster, only if it carries the managed-by label
- **View**, **Copy kubectl**, **Download**: show the JSON, copy a ready-to-run `kubectl apply` command or download the manifest, to apply it yourself

Generating the same name again creates a newer manifest; once it is applied, older manifests of that name are marked `Superseded` and cannot be applied (that would revert the policy). A failed apply is recorded with the Kubernetes error (for example `forbidden`, or a namespace that does not exist). Every apply, check failure and removal is written to the audit log.

> **Warning:** a NetworkPolicy denies all other inbound traffic to every pod in the namespace as soon as it is applied. Review the warnings, run a **Dry run**, and on **Cilium** read *ipBlock and the CNI* above: IP-based sources do not match in-cluster pods there, so use tags mapped to labelled workloads.

Without stored credentials, apply the manifest yourself:
```bash
# Option A: Paste the copied kubectl command
cat <<'EOF' | kubectl apply -f -
{ ... manifest JSON ... }
EOF

# Option B: Apply the downloaded file
kubectl apply -f segmentra-db-policy.json
```
Policies applied outside Segmentra stay `Generated`; Segmentra only tracks what it applied itself (Check works for any manifest whose policy exists on the cluster).

---

## NetworkPolicy Translation Rules

| Segmentra Rule | K8s NetworkPolicy |
|---------------|-------------------|
| Direction `IN` or `BOTH` + Action `ALLOW` | `ingress` rule with `from` `ipBlock` peers |
| Direction `OUT` + Action `ALLOW` (and the outbound half of `BOTH`) | **Not emitted** (outbound is allowed by default; warning) |
| Direction `FORWARD` | **Skipped** (no NetworkPolicy equivalent; warning) |
| Action `DENY` | **Skipped** (NetworkPolicy is allow-only; warning) |
| Source Type `CIDR` | `ipBlock.cidr` (single IPs become `/32` or `/128`; a comma-separated list gives one peer each; `any` or `*` becomes `0.0.0.0/0` and `::/0`) |
| Source Type `HOST` | `ipBlock` for the host's management IP |
| Source Type `TAG` | `ipBlock` for the management IP of every enabled host with the tag, plus a `namespaceSelector` + `podSelector` peer for every workload of the cluster mapped to the tag |
| Source Type `VLAN` | `ipBlock` for the VLAN subnet (or member hosts' IPs if the VLAN has no subnet) |
| A source that resolves to no addresses | **Skipped** (warning), never widened to `0.0.0.0/0` |
| Protocol `tcp` / `udp` / `sctp` | `ports[].protocol: TCP / UDP / SCTP` |
| Ports `80,443` or ranges `8000-8100` | One `ports[]` entry each (ranges use `endPort`) |
| Protocol `icmp` | **Skipped** (not supported by NetworkPolicy; warning) |
| Protocol `any` without ports | No `ports` (all ports and protocols) |

The policy always selects all pods in the namespace (`podSelector: {}`).

### Important: K8s NetworkPolicy Is Allow-List

Kubernetes NetworkPolicy works differently from nftables/iptables:
- If **no** NetworkPolicy selects a pod, all traffic is allowed (open by default)
- If **any** NetworkPolicy selects a pod for a direction, only traffic matching a rule is allowed in that direction
- There is **no explicit DENY** rule; you deny by omission

Segmentra's DENY rules are therefore not translated. The presence of a NetworkPolicy with ALLOW ingress rules implicitly denies all other inbound traffic to the selected pods.

---

## Multi-Cluster

Several clusters can be registered. Workloads and generated NetworkPolicies are stored per cluster (`cluster_id`), and the UI shows a cluster list for switching between them.

---

## API Endpoints

All endpoints require authentication.

### Clusters
- `GET /api/k8s/clusters`: list clusters (all roles)
- `GET /api/k8s/clusters/:id`: cluster with workload counts per kind and namespace (all roles)
- `POST /api/k8s/clusters`: add a cluster (admin). Body: `{ name, apiServerUrl?, authType?, cni?, description?, credentials?, caCert?, tlsSkipVerify?, defaultNamespace?, enabled? }`. `credentials` (kubeconfig or token) and `caCert` (PEM) are write-only and stored encrypted; `apiServerUrl` is optional with a kubeconfig. Responses include `has_credentials` / `has_ca_cert`, never the secrets
- `PUT /api/k8s/clusters/:id`: update a cluster (admin). Omitting `credentials` / `caCert` keeps the stored ones, `null` removes them
- `POST /api/k8s/clusters/:id/test-connection`: reads the API server version and checks that NetworkPolicies can be listed; stores the result in `last_sync_status` (operator, admin)
- `DELETE /api/k8s/clusters/:id`: remove the cluster record, its workloads, generated policies and stored credentials. Policies already applied stay on the cluster (remove them first) (admin)
- `POST /api/k8s/clusters/:id/sync`: not implemented; returns `501 not_implemented` and does not contact the cluster (operator, admin)

### Workloads
- `GET /api/k8s/clusters/:id/workloads`: list workloads, filter by `namespace` and `kind` (all roles)
- `POST /api/k8s/clusters/:id/workloads`: register or update a workload. Body: `{ namespace, name, kind?, labels?, podIps? }` (operator, admin)
- `POST /api/k8s/workloads/:workloadId/map-tag`: map a workload to a Segmentra tag. Body: `{ tagId }` (operator, admin)
- `DELETE /api/k8s/workloads/:workloadId/tags/:tagId`: unmap a tag (operator, admin)
- `DELETE /api/k8s/workloads/:workloadId`: remove a workload record; the cluster is not touched (operator, admin)

### Network Policies
- `GET /api/k8s/clusters/:id/network-policies`: list generated NetworkPolicies (all roles)
- `POST /api/k8s/clusters/:id/deploy-policy`: generate and store a NetworkPolicy from an APPROVED or DEPLOYED policy version (`409 policy_version_not_approved` otherwise). Body: `{ policyVersionId, namespace, policyName }`. Returns `{ networkPolicy, warnings }`. Despite the name, this only generates and stores the manifest; use `apply` to put it on the cluster (operator, admin)
- `POST /api/k8s/clusters/:id/network-policies/:npId/apply`: create or update the policy on the cluster. Body: `{ dryRun?, overwrite? }`. `409 not_managed_by_segmentra` if a same-named policy without the managed-by label exists (unless `overwrite`), `409 superseded` for an older manifest, `409 no_credentials`, `404 namespace_not_found`, `502` for Kubernetes errors such as `forbidden` (the row becomes `FAILED` with `last_error`) (operator, admin)
- `POST /api/k8s/clusters/:id/network-policies/:npId/check`: compare with the live policy; returns `state` `IN_SYNC`, `DRIFTED` or `MISSING` (operator, admin)
- `POST /api/k8s/clusters/:id/network-policies/:npId/remove`: delete the policy from the cluster (only if managed-by Segmentra); `alreadyAbsent` when it was gone (operator, admin)

---

## Database Tables (migrations 015, 033, 034, 035)

### `k8s_clusters`
| Column | Type | Description |
|--------|------|-------------|
| `id` | uuid PK | Cluster identifier |
| `name` | text | Display name |
| `description` | text | Optional description |
| `api_server_url` | text | K8s API endpoint |
| `auth_type` | text | `kubeconfig`, `service_account` or `token` |
| `cni` | text | CNI plugin (migration 033), default `unknown`; drives the `ipBlock` warning |
| `credentials_secret_id` | uuid FK → secret_store | Encrypted kubeconfig or bearer token (`K8S_CREDENTIALS`) |
| `ca_cert_secret_id` | uuid FK → secret_store | Encrypted API server CA certificate (`TLS_CA_CERT`) |
| `tls_skip_verify` | boolean | Disable API server certificate verification (migration 034) |
| `default_namespace` | text | Default namespace |
| `last_sync_at` | timestamptz | Last connection test |
| `last_sync_status` | text | Result of the last connection test |
| `enabled` | boolean | Whether the cluster is active |
| `created_by`, `created_at`, `updated_at` | | Bookkeeping |

### `k8s_workloads`
| Column | Type | Description |
|--------|------|-------------|
| `id` | uuid PK | Workload identifier |
| `cluster_id` | uuid FK → k8s_clusters | Parent cluster |
| `namespace` | text | K8s namespace |
| `kind` | text | e.g. Pod, Deployment, StatefulSet, DaemonSet, Service |
| `name` | text | Resource name |
| `labels` | jsonb | K8s labels (key-value pairs) |
| `pod_ips` | text[] | Pod IP addresses |
| `service_cluster_ip` | text | Service ClusterIP |
| `service_ports` | jsonb | Service port definitions |
| `status`, `last_seen_at`, `created_at` | | Bookkeeping |

### `k8s_workload_tags`
| Column | Type | Description |
|--------|------|-------------|
| `workload_id` | uuid FK → k8s_workloads | Workload |
| `tag_id` | uuid FK → tags | Segmentra tag |
| `source` | text | `label_sync` (default) or `manual` (set by `map-tag`) |

### `k8s_network_policies`
| Column | Type | Description |
|--------|------|-------------|
| `id` | uuid PK | Policy identifier |
| `cluster_id` | uuid FK → k8s_clusters | Target cluster |
| `policy_version_id` | uuid FK → policy_versions | Source Segmentra policy version |
| `namespace` | text | Target namespace |
| `policy_name` | text | K8s resource name |
| `manifest` | jsonb | Full NetworkPolicy JSON |
| `status` | text | `GENERATED`, `APPLIED`, `FAILED`, `REMOVED` or `SUPERSEDED` (column default `PENDING`) |
| `deployed_hash` | text | SHA-256 of the manifest |
| `deployed_at` | timestamptz | Time the manifest was generated |
| `warnings` | jsonb | Generation warnings (migration 035) |
| `applied_at`, `applied_by` | | When and by whom it was last applied (migration 034) |
| `last_error` | text | Kubernetes error of a failed apply |
| `live_state`, `live_checked_at` | | Result and time of the last apply/check: `IN_SYNC`, `DRIFTED`, `MISSING` |

Migration 015 also adds `policy_sets.scope_k8s_cluster_id` and `policy_sets.scope_k8s_namespace`; the API does not use them (policy set scopes are TAG, VLAN and HOST_LIST).
