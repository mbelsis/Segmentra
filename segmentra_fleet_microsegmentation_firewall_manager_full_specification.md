# Segmentra

## Business description
**Segmentra** is an on‑premise, web-based **fleet firewall & microsegmentation management** tool for Linux servers. It lets security/infra teams define **intent-based access policies** (allow/deny traffic) and safely deploy them at scale to **iptables or nftables** across thousands of servers. Segmentra organizes servers by **tags and VLANs**, supports **multi-NIC interface-aware enforcement** (management/data/backup), provides **policy versioning**, **maker/checker approvals**, **safe staged rollouts**, **automatic host-local backups**, and a full **audit trail** of every change and deployment.

### Key capabilities (high level)
- Central inventory of Linux hosts with **tags**, **VLANs**, and **network interfaces** (role mapped)
- Policy builder to define **ACL rules** with explicit **interface scope** (all interfaces vs role-scoped)
- Targeting policies to **tag groups**, **VLANs**, or **specific hosts** (hostname/IP)
- **Policy versioning** (draft/approved/deployed) with diffs and rollback
- **Maker/Checker** workflow (one user proposes, another approves)
- Safe deployment orchestration (canary/progressive/full) via **Ansible CLI runner**
- Host-side **automatic backups** of previous rulesets and rollback safety
- Full **auditing**: who changed what, who approved, where/when deployed, per-host outcome
- Encrypted storage for sensitive configuration and **SSH keys**

---

## 1) System architecture
### 1.1 Containers (Docker)
- **segmentra-app**: React UI + Express API (TypeScript)
- **segmentra-db**: PostgreSQL (persistent volume)
- **segmentra-ansible-runner**: ansible-core runtime container (CLI execution)

### 1.2 Data flow
1. User authenticates via LDAP/AD.
2. User edits policy (draft) → creates a **Policy Version**.
3. Optional: submit for approval (maker/checker).
4. Approved policy version → create **Deployment** targeting tag/VLAN/hosts.
5. Backend compiles **Deployment Bundle** (immutable artifacts + manifest).
6. Backend triggers Ansible runner (CLI) to apply to target hosts.
7. Results (structured) are ingested into DB; UI shows status.

### 1.3 Execution engine abstraction
Segmentra treats “execution” as a pluggable adapter:
- v1: **Ansible CLI Executor**
- future: swap to **AWX/Tower** or **Puppet** without changing policy/compiler logic

---

## 2) Authentication, authorization, and approvals
### 2.1 LDAP/Active Directory integration
- LDAPS only (TLS).
- Bind using service account (recommended) + search for user.
- Map AD groups → Segmentra roles.

### 2.2 Roles (RBAC)
- **Viewer**: read-only
- **Operator**: manage inventory, create drafts, run simulations, create deployments
- **Approver**: approve/reject policy versions, approve high-risk deployments
- **Admin**: system settings, LDAP mappings, secret management, break-glass

### 2.3 Maker/Checker workflow
- Policy versions move through statuses:
  - `DRAFT` → `PENDING_APPROVAL` → `APPROVED` or `REJECTED`
- Approval requires a different user than the maker (configurable).
- Extra approvals required for **high-risk** (e.g., ALL_INTERFACES + large blast radius).

---

## 3) Inventory model (hosts, tags, VLANs, interfaces)
### 3.1 Hosts
Each host includes:
- Hostname, mgmt IP, environment, OS, firewall backend
- Tags (many-to-many)
- VLAN (optional)

### 3.2 Multi-NIC interface awareness
Hosts may have multiple NICs. Segmentra stores **host interfaces** with a logical **role**.
Roles (default): `management`, `data`, `backup`, `storage`, `dmz`, `other`.

Policies/rules may apply to:
- **ALL interfaces** (explicit)
- **One or more interface roles** (recommended default)
- **Explicit interface names** (advanced)

---

## 4) Policy model (intent-based ACL)
### 4.1 Policy Sets
A **Policy Set** is a named group of rules that applies to a scope:
- TAG scope (all hosts with a tag)
- VLAN scope (all hosts in a VLAN)
- HOST_LIST scope (explicit host selection)

### 4.2 Policy Versions
Every change creates a new **immutable version**.
Statuses:
- `DRAFT`, `PENDING_APPROVAL`, `APPROVED`, `REJECTED`, `ARCHIVED`

### 4.3 Interface scope (policy-level)
Policy version has:
- `interface_scope_type`: `ALL_INTERFACES | INTERFACE_ROLE | INTERFACE_NAME`
- roles/names list depending on type

### 4.4 Rules
Rule fields (inbound v1):
- action: `ALLOW | DENY`
- protocol: `tcp | udp | icmp | any`
- ports: list/range (tcp/udp)
- source:
  - `CIDR` (e.g., 10.0.0.0/24)
  - `TAG` (resolve to IP set at compile time)
  - `VLAN` (resolve to IP set)
  - `HOST` (specific host IP)
- logging: `NONE | LOG | LOG_RATE_LIMITED`
- comment/justification
- **interface override** (optional per rule):
  - `use_policy_interface_scope` boolean
  - if false: per-rule interface scope fields

### 4.5 Baseline firewall (non-removable)
Always enforced on hosts:
- loopback allow
- established/related allow
- management allowlist for SSH (from admin-configured mgmt CIDRs)
- default policy inbound drop (recommended)

---

## 5) Compilation & rendering (nftables / iptables)
### 5.1 Backend selection
- Prefer nftables if available; fallback to iptables.
- Backend per host:
  - inventory field + runtime detection in preflight

### 5.2 Interface attachment strategy
- If policy scope is `INTERFACE_ROLE`, compiler maps roles → interface names per host and generates interface-matched rules.
- If `ALL_INTERFACES`, rules apply without interface match.

### 5.3 Deterministic ordering
1. baseline rules
2. explicit allows
3. explicit denies
4. default deny inbound

### 5.4 Sets (scale)
- nftables sets or ipset to avoid huge per-IP rule lists when targeting tag/vlan.

---

## 6) Deployments (safe at scale)
### 6.1 Deployment modes
- `CANARY` (small subset)
- `PROGRESSIVE` (batches)
- `FULL`

### 6.2 Guardrails
- If targets > N (configurable): require canary then progressive.
- If `ALL_INTERFACES` and targets > M: require extra approvals.
- Hard safety: management SSH allow baseline cannot be removed.

### 6.3 Host-local backups & rollback
Before applying:
- nftables: save `/etc/nftables.conf` to `/var/backups/segmentra/nftables.conf.<ts>`
- iptables: save `iptables-save` to `/var/backups/segmentra/iptables.<ts>`
Retention: keep last K backups.
Rollback on failure/unreachable: restore latest backup.

---

## 7) Auditing
Audit events include:
- policy created/edited/submitted/approved/rejected
- deployment created/started/finished
- per-host outcome (success/fail/rollback)
- diffs and artifact hashes

Audit must be append-only.

---

## 8) Data protection & secret storage
- Store secrets (SSH keys, LDAP bind password) in DB as **encrypted blobs**.
- Encryption: AES-256-GCM in application layer.
- Key (KEK) from env/secret store; future: Vault integration.
- Ansible runner uses ephemeral key files created at runtime.

---

# 9) PostgreSQL schema (tables & fields)

> Naming convention: snake_case. UUID primary keys. `tenant_id` optional for future multi-tenancy.

## 9.1 Auth & RBAC
### `users`
- `id` uuid pk
- `username` text unique
- `display_name` text
- `email` text
- `directory_subject` text (AD GUID or DN)
- `is_active` boolean
- `created_at` timestamptz
- `last_login_at` timestamptz

### `roles`
- `id` uuid pk
- `name` text unique  // viewer, operator, approver, admin
- `description` text

### `user_roles`
- `user_id` uuid fk users
- `role_id` uuid fk roles
- pk `(user_id, role_id)`

### `ldap_settings`
- `id` uuid pk
- `enabled` boolean
- `url` text
- `bind_dn` text
- `bind_password_secret_id` uuid fk secret_store
- `base_dn` text
- `user_filter` text
- `group_filter` text
- `use_ldaps` boolean
- `tls_ca_cert_secret_id` uuid fk secret_store (optional)
- `created_at` timestamptz

### `ad_group_role_map`
- `id` uuid pk
- `ad_group_dn` text
- `role_id` uuid fk roles

## 9.2 Inventory
### `vlans`
- `id` uuid pk
- `vlan_tag` int
- `name` text
- `description` text

### `tags`
- `id` uuid pk
- `name` text unique
- `description` text

### `hosts`
- `id` uuid pk
- `hostname` text unique
- `mgmt_ip` inet
- `ssh_port` int default 22
- `environment` text  // prod/dev/etc
- `os_family` text  // rhel/debian/etc
- `firewall_backend` text  // nftables|iptables|auto
- `vlan_id` uuid fk vlans (nullable)
- `enabled` boolean
- `created_at` timestamptz
- `updated_at` timestamptz

### `host_tags`
- `host_id` uuid fk hosts
- `tag_id` uuid fk tags
- pk `(host_id, tag_id)`

### `host_interfaces`
- `id` uuid pk
- `host_id` uuid fk hosts
- `name` text  // ens160, bond0
- `role` text  // management/data/backup/...
- `ip_address` inet (nullable)
- `cidr` int (nullable) // optional prefix length if needed
- `vlan_id` uuid fk vlans (nullable)
- `is_primary` boolean default false
- `enabled` boolean default true
- `created_at` timestamptz

## 9.3 Policies
### `policy_sets`
- `id` uuid pk
- `name` text
- `description` text
- `scope_type` text  // TAG|VLAN|HOST_LIST
- `scope_tag_id` uuid fk tags (nullable)
- `scope_vlan_id` uuid fk vlans (nullable)
- `created_by` uuid fk users
- `created_at` timestamptz

### `policy_set_hosts` (only used when scope_type=HOST_LIST)
- `policy_set_id` uuid fk policy_sets
- `host_id` uuid fk hosts
- pk `(policy_set_id, host_id)`

### `policy_versions`
- `id` uuid pk
- `policy_set_id` uuid fk policy_sets
- `version_number` int
- `status` text  // DRAFT|PENDING_APPROVAL|APPROVED|REJECTED|ARCHIVED
- `change_summary` text
- `created_by` uuid fk users
- `created_at` timestamptz
- `submitted_at` timestamptz (nullable)
- `approved_by` uuid fk users (nullable)
- `approved_at` timestamptz (nullable)
- `rejected_by` uuid fk users (nullable)
- `rejected_at` timestamptz (nullable)
- `rejection_reason` text (nullable)

- `interface_scope_type` text  // ALL_INTERFACES|INTERFACE_ROLE|INTERFACE_NAME
- `interface_scope_roles` text[] (nullable)
- `interface_scope_names` text[] (nullable)

- `is_high_risk` boolean default false

### `policy_rules`
- `id` uuid pk
- `policy_version_id` uuid fk policy_versions
- `order_index` int
- `action` text  // ALLOW|DENY
- `protocol` text  // tcp|udp|icmp|any
- `ports` text (nullable) // normalize later; store as "22" or "80,443" or "1000-2000"

- `source_type` text  // CIDR|TAG|VLAN|HOST
- `source_value` text  // CIDR string OR tag_id/vlan_id/host_id serialized

- `log_mode` text  // NONE|LOG|LOG_RATE_LIMITED
- `comment` text

- `use_policy_interface_scope` boolean default true
- `interface_scope_type` text (nullable)
- `interface_scope_roles` text[] (nullable)
- `interface_scope_names` text[] (nullable)

## 9.4 Deployments & artifacts
### `deployments`
- `id` uuid pk
- `policy_version_id` uuid fk policy_versions
- `mode` text  // CANARY|PROGRESSIVE|FULL
- `target_query` jsonb  // {tags:[], vlans:[], hosts:[], filters:{...}}
- `target_count` int
- `created_by` uuid fk users
- `created_at` timestamptz
- `started_at` timestamptz (nullable)
- `finished_at` timestamptz (nullable)
- `status` text  // QUEUED|RUNNING|SUCCEEDED|FAILED|PARTIAL|CANCELLED

- `requires_approval` boolean default false
- `approved_by` uuid fk users (nullable)
- `approved_at` timestamptz (nullable)

- `canary_size` int (nullable)
- `batch_size` int (nullable)

### `deployment_hosts`
- `deployment_id` uuid fk deployments
- `host_id` uuid fk hosts
- `status` text  // PENDING|RUNNING|SUCCEEDED|FAILED|ROLLED_BACK|SKIPPED
- `started_at` timestamptz (nullable)
- `finished_at` timestamptz (nullable)
- `message` text (nullable)
- `applied_hash` text (nullable)
- `rollback_performed` boolean default false
- pk `(deployment_id, host_id)`

### `deployment_artifacts`
- `id` uuid pk
- `deployment_id` uuid fk deployments
- `bundle_path` text
- `bundle_hash` text
- `manifest` jsonb
- `created_at` timestamptz

### `execution_runs`
- `id` uuid pk
- `deployment_id` uuid fk deployments
- `executor_type` text  // ansible_cli
- `command` text
- `exit_code` int (nullable)
- `stdout_path` text (nullable)
- `stderr_path` text (nullable)
- `started_at` timestamptz
- `finished_at` timestamptz (nullable)
- `status` text  // RUNNING|DONE|ERROR

## 9.5 Auditing
### `audit_events`
- `id` uuid pk
- `actor_user_id` uuid fk users
- `action` text  // POLICY_CREATE, POLICY_EDIT, POLICY_SUBMIT, POLICY_APPROVE, DEPLOY_CREATE, DEPLOY_START...
- `entity_type` text  // policy_version, deployment, host, tag, vlan
- `entity_id` uuid
- `timestamp` timestamptz
- `ip_address` inet (nullable)
- `metadata` jsonb

## 9.6 Secrets (encrypted blobs)
### `secret_store`
- `id` uuid pk
- `name` text
- `type` text  // SSH_KEY, LDAP_BIND, TLS_CA_CERT
- `encrypted_blob` bytea
- `created_at` timestamptz
- `rotated_at` timestamptz (nullable)
- `is_active` boolean default true

### `ssh_credentials`
- `id` uuid pk
- `name` text
- `username` text
- `private_key_secret_id` uuid fk secret_store
- `passphrase_secret_id` uuid fk secret_store (nullable)
- `scope_type` text  // GLOBAL|TAG|VLAN|HOST
- `scope_id` uuid (nullable)
- `created_at` timestamptz

---

# 10) API endpoints (Express)

## 10.1 Auth
- `POST /api/auth/login` (LDAP)
- `POST /api/auth/logout`
- `GET /api/auth/me`

## 10.2 RBAC/Admin
- `GET /api/admin/roles`
- `POST /api/admin/ad-group-role-map`
- `GET /api/admin/ldap-settings`
- `PUT /api/admin/ldap-settings`

## 10.3 Inventory
- `GET /api/hosts?hostname=&tag=&vlan=&ip=&env=&backend=`
- `POST /api/hosts`
- `GET /api/hosts/:id`
- `PUT /api/hosts/:id`
- `DELETE /api/hosts/:id` (soft delete recommended)

- `POST /api/hosts/import` (CSV)
- `GET /api/hosts/export`

- `GET /api/tags`
- `POST /api/tags`
- `PUT /api/tags/:id`
- `DELETE /api/tags/:id`

- `GET /api/vlans`
- `POST /api/vlans`
- `PUT /api/vlans/:id`
- `DELETE /api/vlans/:id`

### Interfaces
- `GET /api/hosts/:id/interfaces`
- `POST /api/hosts/:id/interfaces`
- `PUT /api/interfaces/:interfaceId`
- `DELETE /api/interfaces/:interfaceId`

- `POST /api/inventory/discover-interfaces` (optional v1.1: ansible facts job)

## 10.4 Policies
### Policy sets
- `GET /api/policy-sets`
- `POST /api/policy-sets`
- `GET /api/policy-sets/:id`
- `PUT /api/policy-sets/:id`
- `DELETE /api/policy-sets/:id`

### Versions
- `GET /api/policy-sets/:id/versions`
- `POST /api/policy-sets/:id/versions` (create new DRAFT)

- `GET /api/policy-versions/:versionId`
- `PUT /api/policy-versions/:versionId` (edit metadata + interface scope)

- `POST /api/policy-versions/:versionId/submit-approval`
- `POST /api/policy-versions/:versionId/approve`
- `POST /api/policy-versions/:versionId/reject`

### Rules
- `GET /api/policy-versions/:versionId/rules`
- `POST /api/policy-versions/:versionId/rules`
- `PUT /api/policy-rules/:ruleId`
- `DELETE /api/policy-rules/:ruleId`

### Diff & render
- `GET /api/policy-versions/:versionId/diff?fromVersionId=...`
- `GET /api/policy-versions/:versionId/render/host/:hostId` (generated nft/iptables preview)

## 10.5 Simulation
- `POST /api/simulate/traffic`  
  Body: `{srcHostId|srcIp, dstHostId|dstIp, proto, port, interfaceRole?}`

## 10.6 Deployments
- `POST /api/deployments`  
  Body: `{policyVersionId, mode, targetQuery, canarySize?, batchSize?}`

- `GET /api/deployments`
- `GET /api/deployments/:deploymentId`
- `GET /api/deployments/:deploymentId/hosts`

- `POST /api/deployments/:deploymentId/approve` (if required)
- `POST /api/deployments/:deploymentId/start`
- `POST /api/deployments/:deploymentId/cancel`
- `POST /api/deployments/:deploymentId/retry-failed`

### Artifacts & logs
- `GET /api/deployments/:deploymentId/artifacts` (metadata)
- `GET /api/executions/:executionId/logs`

## 10.7 Audit
- `GET /api/audit?actor=&action=&entityType=&from=&to=`
- `GET /api/audit/export`

## 10.8 Secrets
- `GET /api/secrets` (admin)
- `POST /api/secrets` (admin)  // store encrypted
- `PUT /api/secrets/:id` (rotate)
- `DELETE /api/secrets/:id` (disable)

- `GET /api/ssh-credentials`
- `POST /api/ssh-credentials`
- `PUT /api/ssh-credentials/:id`

---

# 11) Deployment Bundle format (immutable)
For each deployment, Segmentra generates:
- `manifest.json`
  - deployment_id, policy_version_id
  - interface scope type + roles/names
  - target list + inventory snapshot hash
  - enforcement mode (fail/skip on missing interface role)
  - baseline policy hash

- `inventory.ini` or `inventory.yaml`
- `host_rules/<hostname>.nft` OR `host_rules/<hostname>.iptables`
- `checks.json` (preflight + post-check definitions)

The executor only ships + applies these artifacts. Interface selection is already resolved during compilation.

---

# 12) UI pages (minimum)
- Dashboard (recent deployments, pending approvals, failures)
- Inventory (hosts/tags/vlans/interfaces + filtering)
- Policy Sets (list)
- Policy Version editor (rules + interface scope)
- Approval queue (diff + approve/reject)
- Deployments (create + canary/progressive + per-host status)
- Audit Log (filters + export)
- Admin settings (LDAP, secrets, SSH credentials, guardrails)

---

# 13) Expanded Capabilities (v2)

## 13.1 Auto-Tagging with Rule-Based Criteria
Replace manual-only tag assignment with a rule engine. Define criteria like "hostname matches `web-*` → tag 'web-server'" or "VLAN 100 → tag 'production'". Rules auto-evaluate on host create/update and every 5 minutes via background job.

**Tables**: `tag_rules` (criteria as JSONB), `tag_rule_results`, extended `host_tags` with `source` column.
**API**: CRUD + evaluate endpoints under `/api/tag-rules`.

## 13.2 Template-Driven Policies
Reusable policy blueprints (e.g., "Web Server Template" = allow 80/443 in, allow 53 out). Instantiation creates real policy_sets/versions/rules in DRAFT status. Optional auto-apply when hosts gain a matching tag.

**Tables**: `policy_templates`, `policy_template_rules` (mirrors `policy_rules` schema), extended `policy_sets`/`policy_versions` with `source_template_id`.
**API**: CRUD + rules + instantiate/preview under `/api/policy-templates`.

## 13.3 Visual Policy Design
Network topology canvas where users define groups (tags, VLANs, CIDRs) as nodes and draw connections as allowed/denied flows. Connections translate into policy rules via bidirectional flow decomposition.

**Tables**: `topology_views` (JSONB layout), `topology_flows`.
**API**: CRUD + generate-policies + auto-discover under `/api/topology`.

## 13.4 Policy Auto-Recommendation
After a firewall audit session completes, analyze observed traffic flows and suggest policy rules. The engine resolves IPs to tags/VLANs, groups flows by port, assigns confidence scores, and deduplicates against existing deployed rules.

**Tables**: `policy_recommendations` (JSONB recommended_rules with confidence per rule).
**API**: Generate/accept/reject/apply under `/api/recommendations`.

## 13.5 Integrations (SIEM, SOAR, Vulnerability DB, Threat Intelligence)
Adapter-based integration framework. Each integration has a standard interface (sync, test, handleEvent). Credentials stored in existing `secret_store` with AES-256-GCM encryption.

**Tables**: `integrations`, `integration_events`, `host_vulnerabilities`, `threat_intel_entries`.
**API**: CRUD + test/sync under `/api/integrations`, vulnerability and threat intel queries.

## 13.6 On-Device Policy Testing
Structured "test mode" that deploys a policy version in log-only mode, captures real traffic, then analyzes observed flows against the policy rules to identify gaps before enforcement. Reuses existing audit infrastructure (compiler logOnlyMode, executor audit-ssh, log-parser).

**Tables**: `policy_test_sessions` (JSONB analysis_results with matched/unmatched/unexpected flows).
**API**: Start/stop/analyze under `/api/policy-test`.

## 13.7 Container Microsegmentation (Kubernetes)
Agentless Kubernetes NetworkPolicy management via K8s API. Discover namespaces/pods/services, map K8s labels to Segmentra tags, compile policy rules into NetworkPolicy manifests, deploy via API.

**Tables**: `k8s_clusters`, `k8s_workloads`, `k8s_workload_tags`, `k8s_network_policies`.
**API**: Cluster management, workload discovery, policy deployment under `/api/k8s`.

## 13.8 OT/IoT Microsegmentation
Passive traffic discovery + upstream enforcement for devices that can't run agents. Discover assets via NetFlow/sFlow/SPAN, fingerprint protocols, enforce via switch ACLs or gateway firewalls over SSH.

**Tables**: `iot_assets`, `iot_asset_tags`, `flow_collectors`, `iot_observed_flows`, `enforcement_points`, `enforcement_acls`.
**API**: Asset management under `/api/iot-assets`, collectors under `/api/flow-collectors`, enforcement under `/api/enforcement-points`.

---

# 14) UI pages (expanded)

In addition to the original pages (Section 12), v2 adds:

- **Policy Templates** (`/policy-templates`) — Template list by category, rule editor, instantiate wizard
- **Visual Topology** (`/topology`) — Topology views, flow editor, auto-discover, generate policies button
- **Policy Testing** (`/policy-testing`) — Test session management, analysis report (color-coded: green=matched, yellow=unmatched, red=blocked)
- **Integrations** (`/integrations`) — Integration catalog, config forms per type, sync status, event log, threat intel dashboard
- **Kubernetes** (`/kubernetes`) — Cluster management, workload browser, label-to-tag mapping, network policy status
- **OT/IoT** (`/iot`) — Asset inventory with OT-specific fields, flow collectors, enforcement points, traffic baseline

---

# 15) Background Jobs

| Job | Interval | Purpose |
|-----|----------|---------|
| Stale deployment timeout | 2 min | Timeout hosts stuck in RUNNING > 10 min |
| Scheduled deployments | 1 min | Process deployments scheduled for future execution |
| Expired audit sessions | 1 min | Auto-restore firewall rules after learning session expires |
| Tag rule evaluation | 5 min | Re-evaluate all enabled auto-tagging rules |
| Policy test session expiry | 1 min | Auto-stop test sessions past scheduled end time |

---

# 16) Cross-Cutting Patterns

All new code follows existing patterns:
- **Migrations**: Numbered .sql + .js files in `packages/db/migrations/` (009 through 016)
- **RBAC**: `requireAuth` + `requireRole()` on every route
- **Audit**: Insert `audit_events` for all state changes
- **Validation**: Zod schemas for all request bodies
- **API client**: New methods in `apps/web/src/lib/api.ts`
- **Background jobs**: `setInterval` in `apps/api/src/index.ts`

