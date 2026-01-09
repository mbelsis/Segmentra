# Segmentra Architecture Documentation

This document provides detailed technical information about Segmentra's architecture, API endpoints, database schema, file structure, and troubleshooting.

---

## Table of Contents

1. [File Structure](#file-structure)
2. [API Endpoints](#api-endpoints)
3. [Database Schema](#database-schema)
4. [Deployment Executors](#deployment-executors)
5. [Firewall Backend Configuration](#firewall-backend-configuration)
6. [Advanced Features](#advanced-features)
   - [Drift Detection & Configuration Compliance](#drift-detection--configuration-compliance)
   - [Safety Guardrails](#safety-guardrails)
   - [Policy Impact Analysis](#policy-impact-analysis)
   - [Host Readiness Verification](#host-readiness-verification)
   - [Scheduled Deployments](#scheduled-deployments)
   - [Host Policy Visualization](#host-policy-visualization)
7. [Troubleshooting](#troubleshooting)
8. [Configuration Details](#configuration-details)

---

## File Structure

```
apps/
  api/                         # Express API (TypeScript)
    src/
      db/                      # PostgreSQL pool
      middleware/              # JWT auth + RBAC
      routes/                  # REST endpoints
        admin.ts
        audit.ts
        auth.ts
        compliance.ts          # Drift detection & compliance checking
        dashboard.ts
        deployments.ts
        health.ts
        host-readiness.ts      # Host capability verification
        inventory/             # Hosts, tags, VLANs, interfaces
        policies/              # Policy sets, versions, rules
        ssh-credentials.ts
        troubleshoot.ts
      services/                # LDAP, secrets crypto, JWT, audit, ...
        policy-diff.ts         # Policy version comparison
        safety-check.ts        # Pre-deployment safety validation
      lib/                     # Environment config
      index.ts                 # Express app entry point
  web/                         # React UI (Vite)
    src/
      components/              # App shell, auth gate, visualization
        HostPolicyVisualization.tsx  # Policy visualization diagram
      pages/                   # Dashboard/Inventory/Policies/...
      lib/                     # API client, auth helpers
infra/
  app/Dockerfile               # App container (installs docker client + openssh-client)
  ansible-runner/              # Ansible container + playbooks (only needed for Ansible executor)
    Dockerfile
    playbooks/
      apply-firewall.yml
packages/
  db/                          # node-pg-migrate migrations + seed scripts
    migrations/
      001_init.sql
      007_add_scheduled_deployments.sql
    scripts/
      seed-roles.js
  shared/                      # shared TS types
  compiler/                    # nftables/iptables rendering
    src/
      compile.ts
  executor/                    # Ansible CLI runner + SSH direct executor
    src/
      run-ansible.ts
      run-ssh.ts
      read-rules.ts            # SSH-based firewall rule reading
      check-host-readiness.ts  # Host capability verification
      types.ts                 # Shared executor types
docker-compose.yml             # Postgres + app + ansible-runner
```

---

## API Endpoints

Base URL: `http://localhost:8080/api`

### Authentication

- `POST /auth/login` — LDAP login. Body: `{ "username": "...", "password": "..." }`
- `POST /auth/logout` — stateless (client drops JWT)
- `GET /auth/me` — returns current user + roles (Bearer token required)
- `POST /auth/change-password` — Change password for current user

### Admin (Admin role required)

- `POST /admin/bootstrap` — one-time bootstrap admin user (enabled by `SEGMENTRA_BOOTSTRAP_TOKEN`)
- `GET /admin/roles`
- `GET /admin/ldap-settings`
- `PUT /admin/ldap-settings`
- `POST /admin/ad-group-role-map`
- `GET /admin/executor-setting` — Get deployment executor preference (ansible/ssh)
- `PUT /admin/executor-setting` — Set deployment executor preference
- `GET /admin/management-vlan-setting` — Get management VLAN setting
- `PUT /admin/management-vlan-setting` — Set management VLAN setting

### Inventory (Operator/Admin role required)

#### Hosts
- `GET /hosts?hostname=&tag=&vlan=&ip=&enabled=&page=&limit=` — Returns hosts with tags and VLAN info
- `POST /hosts` — Body: `{ hostname, mgmtIp?, vlanId?, tagIds[]?, sshPort?, firewallBackend?, ... }`
- `GET /hosts/:id` — Returns host with tags and VLAN info
- `PUT /hosts/:id` — Body: `{ hostname?, mgmtIp?, vlanId?, tagIds[]?, ... }`
- `DELETE /hosts/:id` (soft delete via `enabled=false`)
- `POST /hosts/bulk/delete` — Bulk delete hosts
- `POST /hosts/bulk/assign-vlan` — Bulk assign VLAN
- `POST /hosts/bulk/assign-tag` — Bulk assign tag
- `POST /hosts/bulk/set-enabled` — Bulk enable/disable hosts
- `POST /hosts/bulk/import` — Import hosts from CSV

#### Tags
- `GET /tags`
- `POST /tags` — Body: `{ name, description? }`
- `PUT /tags/:id` — Body: `{ name?, description? }`
- `DELETE /tags/:id`

#### VLANs
- `GET /vlans`
- `POST /vlans` — Body: `{ vlanTag, name, description?, subnet? }`
- `PUT /vlans/:id` — Body: `{ vlanTag?, name?, description?, subnet? }`
- `DELETE /vlans/:id`

### Interfaces (Operator/Admin role required)

- `GET /hosts/:id/interfaces`
- `POST /hosts/:id/interfaces` — Body: `{ name, role?, ipAddress?, cidr?, vlanId?, isPrimary?, enabled? }`
- `PUT /interfaces/:interfaceId` — Body: `{ name?, role?, ipAddress?, cidr?, vlanId?, isPrimary?, enabled? }`
- `DELETE /interfaces/:interfaceId`

### Policies + Approvals

#### Policy Sets
- `GET /policy-sets`
- `POST /policy-sets` — Body: `{ name, description?, scopeType, scopeTagId?, scopeVlanId? }`
- `GET /policy-sets/:id`
- `PUT /policy-sets/:id` — Body: `{ name?, description?, scopeType?, scopeTagId?, scopeVlanId? }`
- `DELETE /policy-sets/:id`

#### Policy Versions
- `GET /policy-sets/:id/versions`
- `POST /policy-sets/:id/versions` — Creates `DRAFT` version. Body: `{ changeSummary?, interfaceScopeType?, interfaceScopeRoles?, interfaceScopeNames? }`
- `GET /policy-versions/:versionId`
- `PUT /policy-versions/:versionId` — Only while `DRAFT`. Body: `{ changeSummary?, interfaceScopeType?, interfaceScopeRoles?, interfaceScopeNames? }`
- `POST /policy-versions/:versionId/submit-approval` — Changes status to `PENDING_APPROVAL`
- `POST /policy-versions/:versionId/approve` — Approver/Admin role required; approver must differ from maker. Body: `{ changeSummary? }`
- `POST /policy-versions/:versionId/reject` — Approver/Admin role required. Body: `{ reason }`
- `POST /policy-versions/:versionId/clone` — Clone version as new DRAFT

#### Policy Rules
- `GET /policy-versions/:versionId/rules`
- `POST /policy-versions/:versionId/rules` — Body: `{ direction, action, protocol, ports?, sourceType, sourceValue, logMode?, comment?, usePolicyInterfaceScope?, interfaceScopeType?, interfaceScopeRoles?, interfaceScopeNames? }`
- `PUT /policy-rules/:ruleId` — Body: `{ direction?, action?, protocol?, ports?, sourceType?, sourceValue?, logMode?, comment?, usePolicyInterfaceScope?, interfaceScopeType?, interfaceScopeRoles?, interfaceScopeNames? }`
- `DELETE /policy-rules/:ruleId`

#### Policy Utilities
- `GET /policy-versions/:versionId/diff?fromVersionId=...` — Compare two policy versions (basic rule list diff)
- `GET /policy-versions/:versionId/render/host/:hostId` — Per-host nft/iptables preview. Returns: `{ backend, sha256, text }`
- `POST /policy-versions/:candidateVersionId/impact-diff` — Semantic policy impact analysis
  - Body: `{ currentVersionId: string, hostIds: string[] }`
  - Returns: `{ diff: Array<{ hostId, hostname, changes: { newAllows, removedAllows, newDenies, removedDenies }, summary }> }`
  - Shows what rules were added/removed/modified between versions

### Deployments

- `POST /deployments` — Body: `{ policyVersionId, mode, targetQuery, canarySize?, batchSize?, scheduledAt? }` (policy version must be APPROVED)
  - `targetQuery`: `{ tags?: uuid[], vlans?: uuid[], hosts?: uuid[] }`
  - `scheduledAt`: Optional ISO 8601 datetime string for deferred execution
  - **Safety Check**: Automatically validates SSH access preservation before deployment
    - FULL mode: Blocks deployment if SSH access would be blocked
    - CANARY/PROGRESSIVE: Warns but allows deployment
- `GET /deployments` — Returns all deployments
- `GET /deployments/:deploymentId` — Returns deployment details
- `GET /deployments/:deploymentId/hosts` — Returns host-level deployment status
- `GET /deployments/:deploymentId/artifacts` — Returns deployment artifacts (bundles)
- `POST /deployments/:deploymentId/start` — Creates bundle + runs executor (Ansible or SSH Direct, based on admin setting)
- `POST /deployments/:deploymentId/pause` — Pause a running deployment (marks RUNNING hosts as PAUSED, leaves PENDING hosts for resume)
- `POST /deployments/:deploymentId/resume` — Resume a paused deployment (marks PAUSED hosts back to RUNNING)
- `POST /deployments/:deploymentId/stop` — Stop a running or paused deployment (marks all PENDING/RUNNING/PAUSED hosts as SKIPPED)
- `POST /deployments/:deploymentId/cancel` — Best-effort cancellation (deprecated - use `/stop` instead)
- `POST /deployments/:deploymentId/retry-failed` — Retry failed hosts (v1 helper)
- `GET /executions/:executionId/logs` — Returns stdout and stderr from execution

**Note**: Host deployments automatically timeout after 10 minutes if they remain in `RUNNING` status. Timed-out hosts are marked as `FAILED` with the message "Deployment timeout: Host did not respond within 10 minutes". The timeout check runs automatically every 2 minutes and also when fetching deployments or deployment hosts.

### Dashboard

- `GET /dashboard/stats` — Returns dashboard statistics:
  - `totalDeployments`: Total number of deployments
  - `runningDeployments`: Number of currently running deployments
  - `successRate`: Percentage of successful deployments
  - `statusBreakdown`: Array of status counts
  - `topDeployers`: Array of most active users
  - `recentDeployments`: Last 10 deployments
  - `currentDeployments`: Currently running deployments with progress
  - `deploymentActivity`: Deployment activity over last 30 days

### Audit

- `GET /audit?actor=&action=&entityType=&from=&to=` — Returns last 500 audit events
  - `actor`: Filter by username
  - `action`: Filter by action (e.g., `DEPLOYMENT_CREATED`, `DEPLOYMENT_FINISHED`)
  - `entityType`: Filter by entity type (e.g., `DEPLOYMENT`, `POLICY_VERSION`)
  - `from`: Start timestamp (ISO format)
  - `to`: End timestamp (ISO format)

### Compliance & Drift Detection (Operator/Admin role required)

- `GET /compliance/hosts/:hostId` — Check compliance status for a specific host
  - Returns: `{ hostId, hostname, status: 'compliant'|'drifted'|'unknown'|'error', currentHash, expectedHash, backend, lastDeployment, error? }`
  - Reads current firewall rules via SSH and compares hash to `deployment_hosts.applied_hash`
- `POST /compliance/hosts/bulk` — Bulk compliance check for multiple hosts
  - Body: `{ hostIds: string[] }`
  - Returns: `{ results: Array<{ hostId, hostname, status, currentHash, expectedHash, error? }> }`

### Host Readiness (Operator/Admin role required)

- `POST /host-readiness/hosts/:hostId/check` — Check if a host is ready for deployments
  - Returns: `{ hostname, ready: boolean, backend: 'nftables'|'iptables'|'unknown', nftVersion?, iptablesVersion?, sudoAccess: boolean, kernelSupport: boolean, errors: string[], warnings: string[] }`
  - Verifies: nft/iptables availability, passwordless sudo access, kernel module support
  - Auto-updates `firewall_backend` if set to "auto"

### Troubleshoot

- `GET /troubleshoot/policies/by-ip?ip=...` — Find which policies apply to a specific IP
- `GET /troubleshoot/hosts/:hostId/policies` — Get all policies deployed to a host
- `GET /troubleshoot/policy-versions/:versionId/hosts` — Get all hosts with a specific policy version
- `POST /troubleshoot/simulate-communication` — Simulate communication between two IPs
  - Body: `{ sourceIp, sourcePort?, destIp, destPort?, protocol? }`
  - Returns: Analysis of whether communication would be blocked, matching rules, and host information

### SSH Credentials (Admin role required)

- `GET /ssh-credentials` — List all SSH credentials
- `POST /ssh-credentials` — Create new SSH credential. Body: `{ name, username, privateKeyPem, passphrase?, scopeType, scopeId? }` (stores private key encrypted)
- `PUT /ssh-credentials/:id` — Update SSH credential metadata. Body: `{ name?, username?, scopeType?, scopeId? }`
  - **Note**: The `PUT` endpoint does **not** update the private key or passphrase. SSH keys are immutable for security reasons. To rotate SSH keys, create a new credential via `POST` and delete the old one.

---

## Database Schema

Migrations live in `packages/db/migrations/`.

### Auth & RBAC

#### `users`
- `id` (uuid, PK)
- `username` (text, unique)
- `display_name` (text)
- `email` (text)
- `password_hash` (text, nullable) — For local authentication
- `directory_subject` (text) — AD GUID or DN for LDAP users
- `is_active` (boolean)
- `created_at` (timestamptz)
- `last_login_at` (timestamptz)

#### `roles`
- `id` (uuid, PK)
- `name` (text, unique) — `viewer|operator|approver|admin`
- `description` (text)

#### `user_roles`
- `user_id` (uuid, FK → users.id)
- `role_id` (uuid, FK → roles.id)
- Primary key: `(user_id, role_id)`

#### `ldap_settings`
- `id` (uuid, PK)
- `enabled` (boolean)
- `url` (text)
- `bind_dn` (text)
- `bind_password_secret_id` (uuid, FK → secret_store.id)
- `base_dn` (text)
- `user_filter` (text)
- `group_filter` (text)
- `use_ldaps` (boolean)
- `tls_ca_cert_secret_id` (uuid, FK → secret_store.id, nullable)
- `created_at` (timestamptz)

#### `ad_group_role_map`
- `id` (uuid, PK)
- `ad_group_dn` (text)
- `role_id` (uuid, FK → roles.id)

#### `secret_store`
- `id` (uuid, PK)
- `name` (text)
- `type` (text) — `SSH_KEY|LDAP_BIND|TLS_CA_CERT`
- `encrypted_blob` (bytea)
- `created_at` (timestamptz)
- `rotated_at` (timestamptz, nullable)
- `is_active` (boolean)

### Inventory

#### `tags`
- `id` (uuid, PK)
- `name` (text, unique)
- `description` (text)

#### `vlans`
- `id` (uuid, PK)
- `vlan_tag` (int)
- `name` (text)
- `description` (text)
- `subnet` (cidr, nullable) — Used for management VLAN baseline SSH access

#### `hosts`
- `id` (uuid, PK)
- `hostname` (text, unique)
- `mgmt_ip` (inet)
- `ssh_port` (int, default 22) — SSH port for deployments
- `environment` (text)
- `os_family` (text)
- `firewall_backend` (text) — `auto|nftables|iptables`
- `vlan_id` (uuid, FK → vlans.id, nullable)
- `enabled` (boolean, default true) — Disabled hosts are skipped from deployments
- `created_at` (timestamptz)
- `updated_at` (timestamptz)

**Important Notes**:
- **SSH Port**: The `ssh_port` field (default: 22) specifies which SSH port to use when connecting to the host for deployments. Both Ansible and SSH Direct executors automatically use the configured port for each host.
- **Disabled Hosts**: Hosts with `enabled=false` are **automatically skipped** from all policy deployments. Disabled hosts will never receive firewall policies, even if they are included in deployment target queries (tags, VLANs, or direct host selection). They will be marked as `SKIPPED` in deployment status with the message "Host is disabled".

#### `host_tags`
- `host_id` (uuid, FK → hosts.id)
- `tag_id` (uuid, FK → tags.id)
- Primary key: `(host_id, tag_id)` — Many-to-many relationship

#### `host_interfaces`
- `id` (uuid, PK)
- `host_id` (uuid, FK → hosts.id)
- `name` (text) — Interface name (e.g., `eth0`, `ens3`)
- `role` (text) — Interface role (e.g., `data`, `management`)
- `ip_address` (inet, nullable)
- `cidr` (cidr, nullable)
- `vlan_id` (int, nullable) — VLAN tag number
- `is_primary` (boolean)
- `enabled` (boolean)
- `created_at` (timestamptz)

### Policies

#### `policy_sets`
- `id` (uuid, PK)
- `name` (text)
- `description` (text)
- `scope_type` (text) — `TAG|VLAN|HOST_LIST`
- `scope_tag_id` (uuid, FK → tags.id, nullable)
- `scope_vlan_id` (uuid, FK → vlans.id, nullable)
- `created_by` (uuid, FK → users.id)
- `created_at` (timestamptz)

#### `policy_set_hosts`
- `policy_set_id` (uuid, FK → policy_sets.id)
- `host_id` (uuid, FK → hosts.id)
- Primary key: `(policy_set_id, host_id)` — Only used when `scope_type=HOST_LIST`

#### `policy_versions`
- `id` (uuid, PK)
- `policy_set_id` (uuid, FK → policy_sets.id)
- `version_number` (int)
- `status` (text) — `DRAFT|PENDING_APPROVAL|APPROVED|REJECTED`
- `change_summary` (text, nullable)
- `created_by` (uuid, FK → users.id)
- `created_at` (timestamptz)
- `submitted_at` (timestamptz, nullable)
- `approved_by` (uuid, FK → users.id, nullable)
- `approved_at` (timestamptz, nullable)
- `rejected_by` (uuid, FK → users.id, nullable)
- `rejected_at` (timestamptz, nullable)
- `rejection_reason` (text, nullable)
- `interface_scope_type` (text) — `ALL_INTERFACES|INTERFACE_NAME|INTERFACE_ROLE`
- `interface_scope_names` (text[], nullable)
- `interface_scope_roles` (text[], nullable)
- `is_high_risk` (boolean, default false)

#### `policy_rules`
- `id` (uuid, PK)
- `policy_version_id` (uuid, FK → policy_versions.id)
- `order_index` (int)
- `direction` (text) — `IN|OUT|BOTH`
- `action` (text) — `ALLOW|DENY`
- `protocol` (text) — `tcp|udp|icmp|any`
- `ports` (text, nullable) — Normalized format: `"22"` or `"80,443"` or `"1000-2000"`
- `source_type` (text) — `CIDR|TAG|VLAN|HOST`
- `source_value` (text) — CIDR string OR tag_id/vlan_id/host_id serialized
- `log_mode` (text) — `NONE|LOG|LOG_RATE_LIMITED`
- `comment` (text)
- `use_policy_interface_scope` (boolean, default true)
- `interface_scope_type` (text, nullable) — Rule-level override
- `interface_scope_roles` (text[], nullable)
- `interface_scope_names` (text[], nullable)

### Deployments & Execution

#### `deployments`
- `id` (uuid, PK)
- `policy_version_id` (uuid, FK → policy_versions.id) — Must be APPROVED
- `mode` (text) — `CANARY|PROGRESSIVE|FULL`
- `target_query` (jsonb) — `{ tags: uuid[], vlans: uuid[], hosts: uuid[] }`
- `target_count` (int)
- `created_by` (uuid, FK → users.id)
- `created_at` (timestamptz)
- `started_at` (timestamptz, nullable)
- `finished_at` (timestamptz, nullable)
- `status` (text) — `QUEUED|RUNNING|SUCCEEDED|FAILED|PARTIAL|CANCELLED|PAUSED`
- `requires_approval` (boolean, default false)
- `approved_by` (uuid, FK → users.id, nullable)
- `approved_at` (timestamptz, nullable)
- `canary_size` (int, nullable)
- `batch_size` (int, nullable)
- `scheduled_at` (timestamptz, nullable) — For deferred/scheduled deployments

#### `deployment_hosts`
- `deployment_id` (uuid, FK → deployments.id)
- `host_id` (uuid, FK → hosts.id)
- `status` (text) — `PENDING|RUNNING|SUCCEEDED|FAILED|ROLLED_BACK|SKIPPED|PAUSED`
- `started_at` (timestamptz, nullable)
- `finished_at` (timestamptz, nullable)
- `message` (text, nullable)
- `applied_hash` (text, nullable) — SHA-256 hash of compiled policy text (for drift detection)
- `rollback_performed` (boolean, default false)
- Primary key: `(deployment_id, host_id)`

#### `deployment_artifacts`
- `id` (uuid, PK)
- `deployment_id` (uuid, FK → deployments.id)
- `bundle_path` (text)
- `bundle_hash` (text)
- `manifest` (jsonb)
- `created_at` (timestamptz)

#### `execution_runs`
- `id` (uuid, PK)
- `deployment_id` (uuid, FK → deployments.id)
- `executor_type` (text) — `ansible_cli|ssh_direct`
- `command` (text)
- `exit_code` (int, nullable)
- `stdout_path` (text, nullable)
- `stderr_path` (text, nullable)
- `started_at` (timestamptz)
- `finished_at` (timestamptz, nullable)
- `status` (text) — `RUNNING|DONE|ERROR`

### Auditing

#### `audit_events`
- `id` (uuid, PK)
- `actor_user_id` (uuid, FK → users.id, nullable)
- `action` (text) — e.g., `DEPLOYMENT_CREATED`, `DEPLOYMENT_FINISHED`, `POLICY_APPROVED`
- `entity_type` (text) — e.g., `DEPLOYMENT`, `POLICY_VERSION`
- `entity_id` (uuid)
- `timestamp` (timestamptz)
- `ip_address` (inet, nullable)
- `metadata` (jsonb) — Rich metadata for the event

**Deployment Audit Metadata Structure**:
```json
{
  "policySetName": "DMZ Servers",
  "policyVersionNumber": 1,
  "deploymentMode": "CANARY",
  "targetType": "Tags, Hosts",
  "targetTags": ["web-servers", "dmz"],
  "targetVlans": [],
  "targetHosts": ["webserver01", "webserver02"],
  "result": "SUCCEEDED|FAILED|PARTIAL",
  "createdAt": "2026-01-08T18:10:43Z",
  "startedAt": "2026-01-08T18:11:02Z",
  "finishedAt": "2026-01-08T18:15:30Z",
  "hostCounts": {
    "total": 10,
    "succeeded": 8,
    "failed": 2,
    "skipped": 0
  }
}
```

### Secrets / SSH

#### `ssh_credentials`
- `id` (uuid, PK)
- `name` (text)
- `username` (text)
- `private_key_secret_id` (uuid, FK → secret_store.id)
- `passphrase_secret_id` (uuid, FK → secret_store.id, nullable)
- `scope_type` (text) — `GLOBAL|TAG|VLAN|HOST`
- `scope_id` (uuid, nullable) — Tag/VLAN/Host ID when scope_type is not GLOBAL
- `created_at` (timestamptz)

### System Settings

#### `system_settings`
- `key` (text, PK) — e.g., `deployment_executor`, `management_vlan_id`
- `value` (text)
- `description` (text, nullable)
- `updated_at` (timestamptz)

---

## Deployment Executors

Segmentra supports two deployment executors, selectable in Admin settings:

### Ansible (Default, Recommended)

- Uses Ansible playbook for deployments
- Better error handling and automatic rollback
- Parallel execution across hosts
- Requires Ansible container (`segmentra-ansible-runner`)
- Uses `become: true` (sudo) for all privileged operations

#### How Ansible Executor Connects to the Container

**Connection Mechanism: Docker Socket (Not SSH)**

The app connects to the Ansible executor container using **Docker's API**, not SSH.

**How it works:**

1. **Docker Socket Mounting**
   - The `segmentra-app` container mounts the Docker socket:
     ```yaml
     volumes:
       - /var/run/docker.sock:/var/run/docker.sock
     ```
   - This gives the API container access to the Docker daemon on the host.

2. **Docker Exec Command**
   - When Ansible executor is selected, the code runs:
     ```bash
     docker exec segmentra-ansible-runner ansible-playbook -i /bundles/.../inventory.ini /runner/playbooks/apply-firewall.yml
     ```
   - This executes `ansible-playbook` inside the `segmentra-ansible-runner` container.

3. **Shared Volume**
   - Both containers share the `segmentra_bundles` volume:
     ```yaml
     volumes:
       - segmentra_bundles:/bundles
     ```
   - The API container writes deployment bundles (inventory, policy files, SSH keys) to `/bundles/<deploymentId>/`
   - The Ansible runner container reads from the same path.

**Visual Flow:**

```
┌─────────────────────────────────┐
│  segmentra-app (API Container)  │
│                                  │
│  1. Generates deployment bundle │
│     → writes to /bundles/...    │
│                                  │
│  2. Executes:                    │
│     docker exec                  │
│       segmentra-ansible-runner   │
│       ansible-playbook ...       │
│                                  │
│  (via Docker socket)             │
└──────────┬──────────────────────┘
           │ Docker Socket
           │ /var/run/docker.sock
           ▼
┌─────────────────────────────────┐
│  Docker Daemon (Host)            │
│                                  │
│  Executes command in container  │
└──────────┬──────────────────────┘
           │
           ▼
┌─────────────────────────────────┐
│  segmentra-ansible-runner       │
│                                  │
│  - Runs ansible-playbook         │
│  - Reads from /bundles/...       │
│  - Connects to target hosts      │
│    via SSH (using SSH keys)      │
└─────────────────────────────────┘
```

**Important Points:**

- **No SSH between containers**: The API container uses Docker exec via the socket.
- **SSH is used by Ansible**: The Ansible runner connects to target hosts via SSH using the SSH credentials you configure.
- **Security Note**: Mounting `/var/run/docker.sock` gives the API container full Docker access. Treat it as **high trust**.

**Code Reference:**

The connection happens in `packages/executor/src/run-ansible.ts`:
```typescript
const child = spawn('docker', ['exec', params.runnerContainer, 'ansible-playbook', ...]);
```

This runs the `docker` CLI command from inside the API container, which communicates with the Docker daemon through the mounted socket.

### SSH Direct

- Lightweight direct SSH/SCP execution
- No Ansible dependency
- Requires `ssh` and `scp` commands on the API host
- Uses `sudo` prefix for all privileged operations
- Suitable for simpler environments or when Ansible is not available
- Runs sequentially (one host at a time)

**Both executors:**
- Support sudo-capable accounts (not root)
- Create backups before applying rules
- Attempt rollback on failure
- Work with nftables and iptables

---

## Advanced Features

### Drift Detection & Configuration Compliance

Segmentra provides **agentless drift detection** by comparing current firewall rules on hosts against the last successfully deployed policy hash.

#### How It Works

1. **Policy Hash Storage**: When a deployment succeeds, the SHA-256 hash of the compiled policy text is stored in `deployment_hosts.applied_hash`.

2. **Rule Reading**: The compliance check uses SSH to read current firewall rules:
   - For nftables: `sudo -n nft list ruleset`
   - For iptables: `sudo -n iptables-save`

3. **Normalization & Hashing**: Rules are normalized (removing timestamps, comments) and hashed using SHA-256.

4. **Comparison**: The current hash is compared to `applied_hash`:
   - **Compliant**: Hashes match — host matches last deployed policy
   - **Drifted**: Hashes differ — manual changes or failed apply detected
   - **Unknown**: No successful deployment found (never deployed or hash missing)
   - **Error**: Unable to read rules (SSH failure, permissions, etc.)

#### Usage

- **Per-Host Check**: Use the "Check Compliance" button in Inventory → Hosts
- **Bulk Check**: Select multiple hosts and use bulk compliance check
- **Status Display**: Compliance status is shown in the inventory table
- **API Access**: `GET /api/compliance/hosts/:hostId` or `POST /api/compliance/hosts/bulk`

#### Benefits

- **No Agent Required**: Uses existing SSH credentials
- **Real-time Detection**: Check compliance on-demand
- **Bulk Operations**: Check hundreds of hosts at once
- **Visual Indicators**: Color-coded status in UI

### Safety Guardrails

Segmentra includes pre-deployment safety checks to prevent administrators from locking themselves out.

#### Safety Check Process

Before allowing a deployment, the system:

1. **Compiles Policy**: Generates firewall ruleset for each target host
2. **Verifies SSH Access**: Checks that the compiled ruleset preserves SSH access from the management VLAN
3. **Validates Management CIDR**: Uses the configured management VLAN's subnet (from `system_settings.management_vlan_id`)
4. **Applies Mode-Specific Rules**:
   - **FULL mode**: **Blocks** deployment if SSH access would be blocked
   - **CANARY/PROGRESSIVE**: **Warns** but allows deployment (assumes canary/batch testing)

#### Implementation

- **Service**: `apps/api/src/services/safety-check.ts`
- **Integration**: Automatic check in `POST /deployments` endpoint
- **UI Feedback**: Visual warnings/errors in deployment creation form
- **Error Response**: Returns detailed safety check results with warnings/errors

#### Safety Check Result

```typescript
{
  safe: boolean;
  warnings: string[];
  errors: string[];
  sshAccessPreserved: boolean;
  blockingRules: Array<{ ruleIndex, action, source, protocol, ports?, comment? }>;
}
```

### Policy Impact Analysis

Before approving a policy version, reviewers can analyze the impact of changes.

#### Features

- **Semantic Diff**: Compares current deployed version vs. candidate version
- **Rule Categorization**: Identifies:
  - New allows (rules being added that allow traffic)
  - Removed allows (rules being removed that previously allowed traffic)
  - New denies (rules being added that block traffic)
  - Removed denies (rules being removed that previously blocked traffic)
- **Per-Host Analysis**: Shows impact for sample hosts (1-3 hosts)
- **Summary Counts**: Quick overview of total changes

#### Usage

- **In Approvals Screen**: When reviewing a policy version, select:
  1. Current deployed version ID
  2. Sample hosts to analyze
  3. Click "Analyze Impact"
- **API**: `POST /api/policy-versions/:candidateVersionId/impact-diff`

#### Benefits

- **Confidence**: Understand changes before deployment
- **Risk Assessment**: Identify potential connectivity issues
- **Documentation**: See exactly what will change

### Host Readiness Verification

Before deploying, verify that hosts are ready to receive firewall policies.

#### Checks Performed

1. **Firewall Backend Detection**:
   - Checks for `nft` command availability
   - Checks for `iptables` command availability
   - Determines preferred backend (nftables preferred)

2. **Version Detection**:
   - Reads `nft --version` if available
   - Reads `iptables --version` if available

3. **Sudo Access Verification**:
   - Tests passwordless sudo for `nft list ruleset`
   - Tests passwordless sudo for `iptables-save`
   - Verifies `iptables-restore` availability if needed

4. **Kernel Support**:
   - Checks for `nf_tables` kernel module (for nftables)

5. **Auto-Detection**:
   - If host `firewall_backend` is set to "auto", updates it based on detection

#### Usage

- **Per-Host**: Click "Check Readiness" button in Inventory → Hosts
- **API**: `POST /api/host-readiness/hosts/:hostId/check`

#### Result Format

```typescript
{
  hostname: string;
  ready: boolean;
  backend: 'nftables' | 'iptables' | 'unknown';
  nftVersion?: string;
  iptablesVersion?: string;
  sudoAccess: boolean;
  kernelSupport: boolean;
  errors: string[];      // Critical issues preventing deployment
  warnings: string[];   // Non-critical issues (may still work)
}
```

### Scheduled Deployments

Deployments can be scheduled for future execution, useful for maintenance windows.

#### Features

- **Simple Scheduling**: Specify `scheduledAt` datetime when creating deployment
- **Background Processing**: Background job checks every minute for ready deployments
- **Automatic Start**: Scheduled deployments automatically start when `scheduled_at <= now()`
- **No Calendar Logic**: Simple "tonight at 02:00" style scheduling

#### Usage

- **UI**: Use datetime picker in deployment creation form
- **API**: Include `scheduledAt: "2026-01-10T02:00:00Z"` in deployment creation payload
- **Format**: ISO 8601 datetime string

#### Implementation

- **Database**: `deployments.scheduled_at` field (added in migration 007)
- **Background Job**: Runs every minute in `apps/api/src/index.ts`
- **Processing**: `processScheduledDeployments()` function clears `scheduled_at` when ready

#### Example

```json
{
  "policyVersionId": "...",
  "mode": "FULL",
  "targetQuery": { "hosts": ["..."] },
  "scheduledAt": "2026-01-10T02:00:00Z"
}
```

### Host Policy Visualization

Segmentra provides a visual diagram showing all firewall policies applied to a specific host, making it easy to understand network connectivity at a glance.

#### Features

- **Interactive SVG Diagram**: Host displayed in center with sources arranged in a circle
- **Color-Coded Connections**: 
  - Green arrows for ALLOW connections
  - Red arrows for DENY connections (when enabled)
- **Connection Details**: 
  - Port numbers displayed on arrows
  - Protocol badges (T=TCP, U=UDP, I=ICMP)
  - Source type icons (🌐 CIDR, 🏷️ TAG, 🔌 VLAN, 🖥️ HOST)
- **Direction Filtering**: Toggle between IN, OUT, or BOTH directions
- **Denied Connections Toggle**: Show or hide denied connections
- **Source Resolution**: Automatically resolves TAG/VLAN/HOST sources to display names

#### Usage

- **Access**: Click "View Visualization" button in Inventory → Hosts table
- **Modal Dialog**: Opens full-screen modal with interactive diagram
- **Controls**: 
  - Direction dropdown: Filter by IN/OUT/BOTH
  - Checkbox: Show/hide denied connections
  - Close button: Return to inventory

#### Visual Layout

The diagram uses a circular layout algorithm:
- Host icon (🖥️) positioned at center
- Sources arranged in a circle around the host
- Radius automatically adjusts based on number of sources
- Arrows connect sources to host, showing connection direction
- Port numbers and protocol badges displayed along arrows

#### Implementation

- **Component**: `apps/web/src/components/HostPolicyVisualization.tsx`
- **Data Source**: Uses existing `GET /api/troubleshoot/hosts/:hostId/policies` endpoint
- **Source Resolution**: Fetches tags, VLANs, and hosts for name resolution
- **Rendering**: Pure SVG using React SVG elements (no external dependencies)
- **Layout Algorithm**: Trigonometric calculations for circular positioning

#### Example Visual Structure

```
        [🌐 Network Icon]
        "192.168.1.0/24"
            ↓ (green, port 22)
    [🖥️ Host Name] ← (red, port 80) [🏷️ Tag Icon "web-servers"]
            ↑ (green, port 443)
        [🔌 VLAN Icon]
        "VLAN-10"
```

#### Benefits

- **Quick Understanding**: See all connections to/from a host at a glance
- **Visual Debugging**: Identify connectivity issues visually
- **Policy Review**: Understand what policies are actually applied
- **Documentation**: Visual representation of network security posture

---

## Firewall Backend Configuration

Segmentra supports multiple firewall backends to accommodate different Linux distributions and system configurations. Each host can be configured with a specific firewall backend, and the system automatically handles mixed environments during deployments.

### Firewall Backend Options

- **`auto`** (default): Automatically uses `nftables` unless explicitly set to `iptables`. This is the recommended setting for most modern Linux systems.
- **`nftables`**: Uses nftables (modern Linux firewall, preferred). Used by default on RHEL 8+, Ubuntu 20.04+, and other modern distributions.
- **`iptables`**: Uses iptables (legacy Linux firewall). Required for older systems that don't support nftables.

### How Mixed Backend Deployments Work

When deploying policies to multiple hosts with different firewall backends (e.g., 200 hosts where 10 use `iptables` and 190 use `nftables`), Segmentra handles this automatically:

1. **Individual Policy Compilation**: Each host's policy is compiled separately based on its configured `firewall_backend` field:
   - Hosts with `nftables` or `auto` → generates `.nft` files (nftables format)
   - Hosts with `iptables` → generates `.iptables` files (iptables format)

2. **Separate Policy Files**: Each host receives its own policy file with the appropriate format:
   - `hostname.nft` for nftables hosts
   - `hostname.iptables` for iptables hosts

3. **Unified Deployment**: All hosts are included in a single deployment operation:
   - The Ansible inventory includes all hosts regardless of backend
   - Each host's inventory entry points to its specific policy file format
   - The Ansible playbook automatically detects the file extension and applies the correct firewall commands

4. **Independent Status Tracking**: Each host's deployment status is tracked independently, so you can see which hosts succeeded or failed regardless of their firewall backend.

### Example: Mixed Environment Deployment

```
Deployment: Policy Set "Web Servers" v2
Target: 200 hosts (mixed backends)

Bundle Contents:
├── host_rules/
│   ├── web-01.nft          (nftables host)
│   ├── web-02.nft          (nftables host)
│   ├── web-03.iptables     (iptables host)
│   ├── web-04.nft          (nftables host)
│   └── ... (197 more files)

Ansible Inventory:
[all]
web-01 ansible_host=... segmentra_policy_file=/bundles/xxx/host_rules/web-01.nft
web-02 ansible_host=... segmentra_policy_file=/bundles/xxx/host_rules/web-02.nft
web-03 ansible_host=... segmentra_policy_file=/bundles/xxx/host_rules/web-03.iptables
web-04 ansible_host=... segmentra_policy_file=/bundles/xxx/host_rules/web-04.nft
...
```

**Result**: All 200 hosts receive the correct firewall rules for their backend type in a single deployment operation, with no conflicts or manual intervention required.

### Best Practices

- **Use `auto` for most hosts**: Modern Linux systems will automatically use nftables, which is preferred.
- **Set `iptables` explicitly**: Only when you know a host requires iptables (older systems, compatibility requirements).
- **Set `nftables` explicitly**: When you want to ensure nftables is used even if the system might support both.

---

## Troubleshooting

### Communication Simulation

The communication simulation feature (`POST /troubleshoot/simulate-communication`) provides a powerful analytical tool to predict whether network traffic between two IP addresses would be blocked by deployed firewall policies. This is particularly useful for troubleshooting connectivity issues and validating policy configurations before deployment.

#### How Simulation Works

The simulation engine performs a comprehensive analysis by:

1. **Host Resolution**: 
   - Queries the inventory to find hosts matching the source and destination IPs
   - Supports both exact IP matches and CIDR notation (e.g., `192.168.1.10` matches `192.168.1.10/32`)
   - Returns host information including hostname, management IP, and deployment status

2. **Policy Discovery**:
   - Retrieves all successfully deployed (`SUCCEEDED` status) and approved (`APPROVED` status) policy versions for both source and destination hosts
   - Only considers policies that have been successfully deployed to the hosts (not just created)
   - Filters out failed or cancelled deployments

3. **Rule Evaluation** (Source Host - OUT Direction):
   - For each policy deployed to the source host, evaluates rules with `OUT` or `BOTH` direction
   - Checks if the destination IP matches the rule's source specification:
     - **CIDR**: Uses CIDR matching algorithm to check if destination IP falls within the CIDR range
     - **HOST**: Resolves the host ID to its management IP and compares with destination IP
     - **TAG**: Resolves all hosts with the tag, extracts their management IPs, and checks if destination IP matches
     - **VLAN**: Resolves all hosts in the VLAN, extracts their management IPs, and checks if destination IP matches
   - Validates protocol match (rule protocol must be `any` or match the specified protocol)
   - Validates port match for TCP/UDP (supports single ports, comma-separated lists, and ranges like `1000-2000`)
   - If all conditions match, records the rule as either `ALLOW` or `DENY`

4. **Rule Evaluation** (Destination Host - IN Direction):
   - For each policy deployed to the destination host, evaluates rules with `IN` or `BOTH` direction
   - Checks if the source IP matches the rule's source specification (same resolution logic as above)
   - Validates protocol and port matches (same as source host evaluation)
   - Records matching rules

5. **Result Determination**:
   - Collects all matching rules from both source and destination hosts
   - Sorts rules by order index to determine precedence
   - Applies firewall rule evaluation logic:
     - **First DENY rule wins**: If any DENY rule matches before an ALLOW rule, communication is blocked
     - **ALLOW rules**: If an ALLOW rule matches and no DENY rule precedes it, communication is allowed
     - **Default DENY**: If no rules match, the default policy is DENY (typical firewall behavior)
   - Returns the blocking rule (if any) and all matching rules for review

#### Technical Implementation Details

The simulation uses simplified rule matching logic designed for quick analysis. **Important**: The simulation is intentionally approximate and should be used as a guidance tool, not as exact ground truth. Key implementation aspects:

- **CIDR Matching**: Implements bitwise AND operations with network masks for IPv4 CIDR range checking. **Note**: IPv6 is not supported in the simulation.
- **Port Parsing**: Handles port specifications including:
  - Single ports: `"80"`
  - Multiple ports: `"80,443"`
  - Port ranges: `"1000-2000"`
- **Source Type Resolution**: Dynamically resolves TAG, VLAN, and HOST source types to actual IP addresses at simulation time
- **Direction Handling**: Correctly evaluates both IN and OUT directions, understanding that:
  - Source host OUT rules control traffic leaving the source
  - Destination host IN rules control traffic arriving at the destination
- **Rule Ordering**: Attempts to respect the `order_index` field, but **simplified evaluation**:
  - For combined IN/OUT paths, the simulation builds separate lists of blocking and allowing rules
  - **Pessimistic DENY interpretation**: The simulation treats DENY rules pessimistically - if any DENY rule matches, it assumes communication is blocked, even though firewalls evaluate rules strictly in order (first-match wins)
  - This means the simulation may indicate blocking when an earlier ALLOW rule would actually permit the traffic
  - **Recommendation**: Use simulation results as guidance, but verify critical paths by reviewing actual compiled firewall rules or testing in a non-production environment

**Limitations**:
- Does not perform exact first-match rule evaluation like actual firewalls
- IPv6 addresses are not supported
- Does not account for interface scoping or interface-specific rules
- Does not model connection state (established/related) or other advanced firewall features
- User IP safety warnings use very simplified CIDR matching (first octet comparison) and may produce false positives/negatives

#### Use Cases

- **Pre-deployment Validation**: Test if a new policy would block critical communication paths
- **Connectivity Troubleshooting**: Determine why two hosts cannot communicate
- **Policy Audit**: Verify that deployed policies match intended security posture
- **Change Impact Analysis**: Understand the effect of policy changes on existing communication patterns

### Compliance & Drift Detection Issues

#### Compliance Check Fails with SSH Error
**Symptom**: Compliance check returns "error" status with SSH connection failure

**Causes**:
- SSH credentials not configured (no GLOBAL SSH credential)
- Host is unreachable or SSH port incorrect
- SSH key authentication failure
- Host firewall blocking SSH access

**Solutions**:
1. Verify SSH credentials exist: `GET /api/ssh-credentials`
2. Test SSH manually: `ssh -i <key> user@host`
3. Check host `ssh_port` configuration matches actual port
4. Verify host is reachable: `ping <host_ip>`
5. Check host firewall isn't blocking SSH from Segmentra server

#### Compliance Shows "Unknown" Status
**Symptom**: Host shows "Unknown" compliance status

**Causes**:
- Host has never had a successful deployment
- Last deployment failed (no `applied_hash` stored)
- Deployment was created but never started

**Solutions**:
1. Deploy a policy to the host successfully
2. Check deployment history for the host
3. Verify previous deployments completed with SUCCEEDED status

#### Compliance Shows "Drifted" Status
**Symptom**: Host shows "Drifted" status (hash mismatch)

**Causes**:
- Manual firewall rule changes on the host
- Failed deployment that partially applied
- Policy was rolled back manually
- Another tool modified firewall rules

**Solutions**:
1. Review current rules on host: `ssh host "sudo nft list ruleset"` or `ssh host "sudo iptables-save"`
2. Compare to expected policy: Use policy render endpoint
3. Redeploy the policy to restore compliance
4. Investigate what caused the drift (manual changes, other tools, etc.)

### Host Readiness Issues

#### Readiness Check Fails: "Passwordless sudo access required"
**Symptom**: Readiness check shows `sudoAccess: false` with error about passwordless sudo

**Causes**:
- SSH user doesn't have sudo access
- Sudo requires password (not passwordless)
- Sudoers configuration doesn't allow nft/iptables commands

**Solutions**:
1. Verify sudo access: `ssh user@host "sudo -n nft list ruleset"`
2. Configure passwordless sudo for firewall commands:
   ```bash
   # On the host, add to /etc/sudoers.d/segmentra:
   segmentra_user ALL=(ALL) NOPASSWD: /usr/sbin/nft, /usr/sbin/iptables, /usr/sbin/iptables-save, /usr/sbin/iptables-restore
   ```
3. Test: `sudo -n nft list ruleset` should work without password

#### Readiness Check Shows "nf_tables kernel module not loaded"
**Symptom**: Warning about kernel module (but may still work)

**Causes**:
- Kernel module not loaded (but may load on demand)
- Older kernel without nftables support

**Solutions**:
1. Check if module loads automatically: `modprobe nf_tables`
2. If nftables works, this is just a warning (can be ignored)
3. If nftables doesn't work, use iptables backend instead

### Safety Check Issues

#### Deployment Blocked: "SSH access would be blocked"
**Symptom**: FULL mode deployment fails with safety check error

**Causes**:
- Policy rules don't include SSH allow rule from management VLAN
- Management VLAN not configured
- Policy has DENY rules that block management CIDR before ALLOW rules

**Solutions**:
1. Verify management VLAN is configured: `GET /api/admin/management-vlan-setting`
2. Review policy rules - ensure SSH allow rule exists for management CIDR
3. Check rule ordering - DENY rules before ALLOW rules will block
4. Use CANARY or PROGRESSIVE mode if you need to test (warns but allows)
5. Review compiled policy: `GET /api/policy-versions/:id/render/host/:hostId`

#### Safety Check Warning: "Your IP may be blocked"
**Symptom**: Warning that current user's IP would be blocked

**Causes**:
- Policy has DENY rules matching user's source IP
- User is deploying from outside management VLAN

**Solutions**:
1. Verify you're deploying from management network
2. Review DENY rules in the policy
3. Consider using CANARY mode to test safely
4. Ensure management VLAN CIDR includes your IP

### Scheduled Deployment Issues

#### Scheduled Deployment Not Starting
**Symptom**: Deployment with `scheduled_at` never starts

**Causes**:
- Background job not running
- `scheduled_at` is in the future
- API server was restarted and background job didn't restart
- Timezone mismatch

**Solutions**:
1. Check API logs for scheduled deployment processing
2. Verify `scheduled_at` timestamp is in the past
3. Use UTC timezone for `scheduled_at` to avoid timezone issues
4. Manually start deployment if needed: `POST /api/deployments/:id/start`

#### Scheduled Deployment Starts Immediately
**Symptom**: Deployment starts even though `scheduled_at` is in the future

**Causes**:
- Background job processes immediately (bug)
- `scheduled_at` parsing error

**Solutions**:
1. Verify `scheduled_at` format is correct ISO 8601
2. Check that deployment status is QUEUED (not RUNNING)
3. Review background job implementation

### Deployment Issues

#### Host Timeout
**Symptom**: Hosts show `FAILED` status with message "Deployment timeout: Host did not respond within 10 minutes"

**Causes**:
- Network connectivity issues
- SSH connection problems
- Host is overloaded or unresponsive
- Firewall blocking SSH access

**Solutions**:
1. Verify SSH connectivity: `ssh -i <key> user@host`
2. Check host is responsive: `ping <host_ip>`
3. Verify SSH credentials are correct
4. Check firewall rules on target host aren't blocking SSH
5. Review execution logs: `GET /executions/:executionId/logs`

#### Deployment Fails Immediately
**Symptom**: Deployment fails immediately with no host-level failures

**Causes**:
- Missing SSH credentials
- Ansible container not running (if using Ansible executor)
- Bundle generation failure
- Invalid policy version (not APPROVED)

**Solutions**:
1. Check Admin → SSH Credentials has a GLOBAL credential configured
2. Verify Ansible container is running: `docker ps | grep ansible-runner`
3. Check API logs for bundle generation errors
4. Verify policy version status is APPROVED

#### Partial Success (Some Hosts Fail)
**Symptom**: Deployment shows `PARTIAL` status with some hosts succeeded and some failed

**Causes**:
- Host-specific issues (SSH, permissions, firewall backend mismatch)
- Network issues affecting subset of hosts
- Host-specific configuration problems

**Solutions**:
1. Review individual host status in deployment details
2. Check host messages for specific error details
3. Verify SSH access to failed hosts
4. Check firewall backend configuration matches host capabilities
5. Review execution logs for specific hosts

### Policy Issues

#### Policy Won't Approve
**Symptom**: Policy version stuck in `PENDING_APPROVAL` or approval fails

**Causes**:
- Approver is the same user who created the policy (separation of duties)
- User doesn't have approver/admin role
- Policy version has validation errors

**Solutions**:
1. Verify approver has `approver` or `admin` role
2. Ensure approver is different from creator
3. Check policy version for validation errors
4. Review rejection reason if rejected

#### Policy Rules Not Applying
**Symptom**: Rules are defined but not appearing in rendered output

**Causes**:
- Interface scope mismatch
- Source type resolution issues
- Rule order/index problems

**Solutions**:
1. Use preview endpoint: `GET /policy-versions/:versionId/render/host/:hostId`
2. Verify interface scope matches host interfaces
3. Check source type values (tag/VLAN IDs, host IDs)
4. Verify rule order_index values

### Authentication Issues

#### LDAP Login Fails
**Symptom**: Cannot login with LDAP credentials

**Causes**:
- LDAP not enabled
- Incorrect LDAP URL or credentials
- AD group mapping not configured
- User filter not matching

**Solutions**:
1. Verify LDAP is enabled in Admin → LDAP Settings
2. Test LDAP connection with `ldapsearch` or similar tool
3. Check AD group mappings in Admin → AD Group → Role map
4. Verify user filter matches your LDAP structure
5. Check API logs for LDAP connection errors

#### Local User Login Fails
**Symptom**: Cannot login with local user credentials

**Causes**:
- User doesn't exist
- Password incorrect
- User is inactive (`is_active=false`)

**Solutions**:
1. Verify user exists: Check `users` table
2. Reset password via API or database
3. Check `is_active` flag in database

### Database Issues

#### Migration Failures
**Symptom**: Database migrations fail on startup

**Causes**:
- Database connection issues
- Existing schema conflicts
- Migration version conflicts

**Solutions**:
1. Verify `DATABASE_URL` is correct
2. Check PostgreSQL is running and accessible
3. Review migration files in `packages/db/migrations/`
4. Check migration history: `SELECT * FROM pgmigrations;`
5. Reset database if needed: `SEGMENTRA_RESET_DB=1`

### Performance Issues

#### Slow Deployments
**Symptom**: Deployments take a long time to complete

**Causes**:
- Large number of hosts
- Network latency
- Sequential execution (SSH Direct executor)
- Host response time

**Solutions**:
1. Use Ansible executor for parallel execution
2. Reduce batch size for progressive deployments
3. Check network connectivity and latency
4. Monitor host resource usage
5. Consider canary deployments for large changes

---

## Configuration Details

### Environment Variables

The API reads env vars in `apps/api/src/lib/env.ts`:

- `PORT` (default `8080`) — API server port
- `DATABASE_URL` (**required**) — PostgreSQL connection string
- `JWT_SECRET` (**required**, min 16 chars) — Secret for JWT token signing
- `SEGMENTRA_KEK_B64` (optional) — Base64 of 32-byte key for AES-256-GCM secret encryption. If not provided, derives from JWT_SECRET (dev only).
- `SEGMENTRA_BOOTSTRAP_TOKEN` (optional) — Enables `POST /api/admin/bootstrap` endpoint for one-time admin creation
- `BUNDLES_DIR` (default `./data/bundles`) — Directory where deployment bundles/logs are written
- `ANSIBLE_RUNNER_CONTAINER` (default `segmentra-ansible-runner`) — Name of the Ansible runner container

### Docker Compose Configuration

The `docker-compose.yml` file defines:

- **PostgreSQL**: Database container on port 15432
- **App Container**: API server with Docker socket mount
- **Ansible Runner**: Optional container for Ansible executor
- **Volumes**: Shared bundle storage between containers

### Security Considerations

1. **Docker Socket Mount**: The app container mounts `/var/run/docker.sock` for Ansible executor. This gives full Docker access - treat as high trust.
2. **Secret Encryption**: SSH keys and LDAP passwords are encrypted using AES-256-GCM. Store `SEGMENTRA_KEK_B64` securely.
3. **JWT Tokens**: Tokens expire after 12 hours. Store `JWT_SECRET` securely.
4. **SSH Credentials**: Use sudo-capable accounts, not root. Ensure passwordless sudo for firewall commands.
5. **LDAP**: Use LDAPS (port 636) for secure LDAP connections in production.

### Current v1 Limitations

- Canary/progressive orchestration and advanced guardrails are stubbed at the API level (basic deployment flow is implemented). The deployment modes (`CANARY`, `PROGRESSIVE`, `FULL`) are accepted and stored, but all selected hosts are processed immediately without host-by-host orchestration.
- Baseline mgmt SSH CIDR is configured via the management VLAN setting (`/admin/management-vlan-setting`). The system uses the `subnet` field from the VLAN referenced by `system_settings.management_vlan_id` to determine which CIDR ranges should have baseline SSH access. This is configurable per environment. If no management VLAN is configured, baseline SSH access is disabled (no hardcoded CIDR).
- SSH Direct executor runs sequentially (one host at a time); Ansible runs in parallel.
- Deployment timeout is fixed at 10 minutes per host.
- No built-in rollback UI (rollback happens automatically on failure).
- Firewall backend `auto` setting is now auto-detected before compilation via SSH. If auto-detection fails, it defaults to `nftables`. The detected backend is stored in the host record for future deployments. Executors validate that the compiled policy format matches the detected backend at runtime.
- Drift detection requires SSH access and passwordless sudo. Hosts without SSH credentials configured cannot be checked for compliance.
- Scheduled deployments use simple datetime comparison. No support for recurring schedules, timezone handling, or complex scheduling rules.
- **High-risk policy logic is not yet implemented**: The database has `policy_versions.is_high_risk` field, but there is currently no code that sets this flag, enforces extra approvals for high-risk changes, or restricts deployment modes based on target counts. The only approval constraint currently implemented is "maker ≠ checker" (with admin self-override).

---

## Additional Resources

- **API Documentation**: See API endpoints section above
- **Database Schema**: See database schema section above
- **Deployment Flow**: See deployment executors section above
- **Policy Compilation**: See `packages/compiler/src/compile.ts` for policy rendering logic
- **Ansible Playbook**: See `infra/ansible-runner/playbooks/apply-firewall.yml` for deployment playbook
