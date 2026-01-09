# Segmentra Architecture Documentation

This document provides detailed technical information about Segmentra's architecture, API endpoints, database schema, file structure, and troubleshooting.

---

## Table of Contents

1. [File Structure](#file-structure)
2. [API Endpoints](#api-endpoints)
3. [Database Schema](#database-schema)
4. [Deployment Executors](#deployment-executors)
5. [Firewall Backend Configuration](#firewall-backend-configuration)
6. [Troubleshooting](#troubleshooting)
7. [Configuration Details](#configuration-details)

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
        dashboard.ts
        deployments.ts
        health.ts
        inventory/             # Hosts, tags, VLANs, interfaces
        policies/              # Policy sets, versions, rules
        ssh-credentials.ts
        troubleshoot.ts
      services/                # LDAP, secrets crypto, JWT, audit, ...
      lib/                     # Environment config
      index.ts                 # Express app entry point
  web/                         # React UI (Vite)
    src/
      components/              # App shell, auth gate
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
- `GET /policy-versions/:versionId/diff?fromVersionId=...` — Compare two policy versions
- `GET /policy-versions/:versionId/render/host/:hostId` — Per-host nft/iptables preview. Returns: `{ backend, sha256, text }`

### Deployments

- `POST /deployments` — Body: `{ policyVersionId, mode, targetQuery, canarySize?, batchSize? }` (policy version must be APPROVED)
  - `targetQuery`: `{ tags?: uuid[], vlans?: uuid[], hosts?: uuid[] }`
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

### Troubleshoot

- `GET /troubleshoot/policies/by-ip?ip=...` — Find which policies apply to a specific IP
- `GET /troubleshoot/hosts/:hostId/policies` — Get all policies deployed to a host
- `GET /troubleshoot/policy-versions/:versionId/hosts` — Get all hosts with a specific policy version

### SSH Credentials (Admin role required)

- `GET /ssh-credentials`
- `POST /ssh-credentials` — Body: `{ name, username, privateKey, passphrase?, scopeType, scopeId? }` (stores private key encrypted)
- `PUT /ssh-credentials/:id` — Body: `{ name?, username?, privateKey?, passphrase?, scopeType?, scopeId? }`

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

#### `deployment_hosts`
- `deployment_id` (uuid, FK → deployments.id)
- `host_id` (uuid, FK → hosts.id)
- `status` (text) — `PENDING|RUNNING|SUCCEEDED|FAILED|ROLLED_BACK|SKIPPED|PAUSED`
- `started_at` (timestamptz, nullable)
- `finished_at` (timestamptz, nullable)
- `message` (text, nullable)
- `applied_hash` (text, nullable)
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
3. **JWT Tokens**: Tokens expire after 24 hours. Store `JWT_SECRET` securely.
4. **SSH Credentials**: Use sudo-capable accounts, not root. Ensure passwordless sudo for firewall commands.
5. **LDAP**: Use LDAPS (port 636) for secure LDAP connections in production.

### Current v1 Limitations

- Canary/progressive orchestration and advanced guardrails are stubbed at the API level (basic deployment flow is implemented).
- Baseline mgmt SSH CIDR is currently hardcoded (`10.0.0.0/8`) in v1 rendering; this should move to admin config.
- SSH Direct executor runs sequentially (one host at a time); Ansible runs in parallel.
- Deployment timeout is fixed at 10 minutes per host.
- No built-in rollback UI (rollback happens automatically on failure).

---

## Additional Resources

- **API Documentation**: See API endpoints section above
- **Database Schema**: See database schema section above
- **Deployment Flow**: See deployment executors section above
- **Policy Compilation**: See `packages/compiler/src/compile.ts` for policy rendering logic
- **Ansible Playbook**: See `infra/ansible-runner/playbooks/apply-firewall.yml` for deployment playbook
