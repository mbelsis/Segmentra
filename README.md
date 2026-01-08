<div align="center">
  <img src="logo/segmentra.png" alt="Segmentra" style="max-width: 300px; height: auto;" />
</div>

# Segmentra

Segmentra is an on‑prem, web-based **fleet firewall & microsegmentation management** tool for Linux servers. It lets security/infra teams define **intent-based access policies** (allow/deny) and deploy them safely at scale to **nftables/iptables**, with versioning, approvals, deployment bundles, and an audit trail.

This repository is a **TypeScript monorepo**:
- **API**: Express + PostgreSQL (`apps/api`)
- **UI**: React (Vite) (`apps/web`)
- **Compiler**: policy → per-host firewall rules (`packages/compiler`)
- **Executor**: Ansible CLI runner wrapper + SSH direct executor (`packages/executor`)
- **DB**: migrations + seed scripts (`packages/db`)

---

## File structure

```
apps/
  api/                         # Express API (TypeScript)
    src/
      db/                      # PostgreSQL pool
      middleware/              # JWT auth + RBAC
      routes/                  # REST endpoints
      services/                # LDAP, secrets crypto, JWT, ...
  web/                         # React UI (Vite)
    src/
      components/              # App shell, auth gate
      pages/                   # Dashboard/Inventory/Policies/...
infra/
  app/Dockerfile               # App container (installs docker client + openssh-client)
  ansible-runner/              # Ansible container + playbooks (only needed for Ansible executor)
packages/
  db/                          # node-pg-migrate migrations + seed scripts
  shared/                      # shared TS types
  compiler/                    # nftables/iptables rendering
  executor/                    # Ansible CLI runner + SSH direct executor
docker-compose.yml             # Postgres + app + ansible-runner
```

---

## API

Base URL: `http://localhost:8080/api`

### Auth
- `POST /auth/login` — LDAP login. Body: `{ "username": "...", "password": "..." }`
- `POST /auth/logout` — stateless (client drops JWT)
- `GET /auth/me` — returns current user + roles (Bearer token required)

### Admin (Admin role required)
- `POST /admin/bootstrap` — one-time bootstrap admin user (enabled by `SEGMENTRA_BOOTSTRAP_TOKEN`)
- `GET /admin/roles`
- `GET /admin/ldap-settings`
- `PUT /admin/ldap-settings`
- `POST /admin/ad-group-role-map`
- `GET /admin/executor-setting` — Get deployment executor preference (ansible/ssh)
- `PUT /admin/executor-setting` — Set deployment executor preference

### Inventory (Operator/Admin role required)
- `GET /hosts?hostname=&tag=&vlan=&ip=&env=&backend=` — Returns hosts with tags and VLAN info
- `POST /hosts` — Body: `{ hostname, mgmtIp?, vlanId?, tagIds[]?, ... }`
- `GET /hosts/:id` — Returns host with tags and VLAN info
- `PUT /hosts/:id` — Body: `{ hostname?, mgmtIp?, vlanId?, tagIds[]?, ... }`
- `DELETE /hosts/:id` (soft delete via `enabled=false`)

- `GET /tags`
- `POST /tags`
- `PUT /tags/:id`
- `DELETE /tags/:id`

- `GET /vlans`
- `POST /vlans`
- `PUT /vlans/:id`
- `DELETE /vlans/:id`

### Interfaces (Operator/Admin role required)
- `GET /hosts/:id/interfaces`
- `POST /hosts/:id/interfaces`
- `PUT /interfaces/:interfaceId`
- `DELETE /interfaces/:interfaceId`

### Policies + approvals
- `GET /policy-sets`
- `POST /policy-sets`
- `GET /policy-sets/:id`
- `PUT /policy-sets/:id`
- `DELETE /policy-sets/:id`

- `GET /policy-sets/:id/versions`
- `POST /policy-sets/:id/versions` (creates `DRAFT`)

- `GET /policy-versions/:versionId`
- `PUT /policy-versions/:versionId` (only while `DRAFT`)
- `POST /policy-versions/:versionId/submit-approval`
- `POST /policy-versions/:versionId/approve` (Approver/Admin role required; approver must differ from maker)
- `POST /policy-versions/:versionId/reject` (Approver/Admin role required)

- `GET /policy-versions/:versionId/rules`
- `POST /policy-versions/:versionId/rules`
- `PUT /policy-rules/:ruleId`
- `DELETE /policy-rules/:ruleId`

- `GET /policy-versions/:versionId/diff?fromVersionId=...`
- `GET /policy-versions/:versionId/render/host/:hostId` (per-host nft/iptables preview)

### Deployments
- `POST /deployments` — Body: `{ policyVersionId, mode, targetQuery, canarySize?, batchSize? }` (policy version must be APPROVED)
- `GET /deployments`
- `GET /deployments/:deploymentId`
- `GET /deployments/:deploymentId/hosts`
- `GET /deployments/:deploymentId/artifacts`
- `POST /deployments/:deploymentId/start` — Creates bundle + runs executor (Ansible or SSH Direct, based on admin setting)
- `POST /deployments/:deploymentId/cancel` (best-effort v1)
- `POST /deployments/:deploymentId/retry-failed` (v1 helper)
- `GET /executions/:executionId/logs`

### Audit
- `GET /audit?actor=&action=&entityType=&from=&to=` (returns last 500)

### SSH Credentials (Admin role required)
- `GET /ssh-credentials`
- `POST /ssh-credentials` (stores private key encrypted)
- `PUT /ssh-credentials/:id`

---

## Database schema (PostgreSQL)

Migrations live in `packages/db/migrations/`.

### Auth & RBAC
- `users`: `id`, `username`, `display_name`, `email`, `directory_subject`, `is_active`, `created_at`, `last_login_at`
- `roles`: `id`, `name` (`viewer|operator|approver|admin`), `description`
- `user_roles`: `user_id`, `role_id`
- `ldap_settings`: `enabled`, `url`, `bind_dn`, `bind_password_secret_id`, `base_dn`, `user_filter`, `group_filter`, `use_ldaps`, `tls_ca_cert_secret_id`, `created_at`
- `ad_group_role_map`: `ad_group_dn`, `role_id`
- `secret_store`: `name`, `type`, `encrypted_blob`, `created_at`, `rotated_at`, `is_active`

### Inventory
- `tags`: `id`, `name`, `description`
- `vlans`: `id`, `vlan_tag`, `name`, `description`
- `hosts`: `id`, `hostname`, `mgmt_ip`, `ssh_port`, `environment`, `os_family`, `firewall_backend`, `vlan_id`, `enabled`, `created_at`, `updated_at`
  - **SSH Port**: The `ssh_port` field (default: 22) specifies which SSH port to use when connecting to the host for deployments. This allows you to deploy to hosts using non-standard SSH ports (e.g., 2022, 2222). Both Ansible and SSH Direct executors automatically use the configured port for each host.
  - **Important**: Hosts with `enabled=false` are **automatically skipped** from all policy deployments. Disabled hosts will never receive firewall policies, even if they are included in deployment target queries (tags, VLANs, or direct host selection). They will be marked as `SKIPPED` in deployment status with the message "Host is disabled".
- `host_tags`: `host_id`, `tag_id` — many-to-many relationship for assigning tags to hosts
- `host_interfaces`: `host_id`, `name`, `role`, `ip_address`, `cidr`, `vlan_id`, `is_primary`, `enabled`, `created_at`

### Policies
- `policy_sets`: `name`, `description`, `scope_type` (`TAG|VLAN|HOST_LIST`), `scope_tag_id`, `scope_vlan_id`, `created_by`, `created_at`
- `policy_set_hosts`: `policy_set_id`, `host_id` — only used when `scope_type=HOST_LIST`
- `policy_versions`: `policy_set_id`, `version_number`, `status`, `change_summary`, `created_by`, timestamps for submit/approve/reject, interface scope fields, `is_high_risk`
- `policy_rules`: rule definition + interface override fields + `direction` (`IN|OUT|BOTH`)

### Deployments & execution
- `deployments`: `policy_version_id` (must be APPROVED), `mode` (`CANARY|PROGRESSIVE|FULL`), `target_query` (JSONB with `tags[]`, `vlans[]`, `hosts[]`), `target_count`, `status`, approvals fields, `canary_size`, `batch_size`, timestamps
- `deployment_hosts`: per-host status + outcome fields (`status`, `started_at`, `finished_at`, `message`, `applied_hash`, `rollback_performed`)
- `deployment_artifacts`: bundle metadata (`bundle_path`, `bundle_hash`, `manifest` JSONB)
- `execution_runs`: `executor_type` (`ansible_cli` or `ssh_direct`), command, stdout/stderr paths, exit code, status/timestamps

### Auditing
- `audit_events`: `actor_user_id`, `action`, `entity_type`, `entity_id`, `timestamp`, `ip_address`, `metadata`

### Secrets / SSH
- `ssh_credentials`: `name`, `username`, secret references, `scope_type` (`GLOBAL|TAG|VLAN|HOST`), `scope_id`, `created_at`

### System Settings
- `system_settings`: `key` (primary key), `value`, `description`, `updated_at` — Stores executor preference and other system-wide settings

---

## Install & run (dev)

### Prereqs
- **Node.js 20+**
- **Docker Desktop**
- A reachable **PostgreSQL** (or use the docker compose DB)

### Quick Start (Recommended)

**Windows:**
```batch
start.bat dev
```

**macOS/Linux:**
```bash
./start.sh dev
```

This will automatically:
- Install dependencies
- Start PostgreSQL (data persists between runs)
- Run migrations and seed roles
- Create default admin user (if it doesn't exist)
- Start API and UI servers

**Note**: The database persists between runs. To reset the database (deletes all data), set the environment variable:
```batch
set SEGMENTRA_RESET_DB=1
start.bat dev
```

### Default Login Credentials

After starting the application, use these credentials to login:

- **Username**: `admin`
- **Password**: `admin`

⚠️ **Important**: Change the default password after first login! You can change it in the UI or via API endpoint `POST /api/auth/change-password`.

### Manual Setup (Alternative)

### 1) Install deps

```bash
npm install
```

### 2) Start Postgres (recommended)

```bash
docker compose up -d segmentra-db
```

### 3) Run migrations + seed roles

Set `DATABASE_URL` (example for the compose DB):

```bash
set DATABASE_URL=postgres://segmentra:segmentra@127.0.0.1:15432/segmentra
npm run db:migrate
npm run db:seed
```

The seed script automatically creates a default admin user:
- **Username**: `admin`
- **Password**: `admin`

### 4) Start the API

Set required env vars (minimum: `DATABASE_URL`, `JWT_SECRET`):

```bash
set JWT_SECRET=change-me-to-a-long-random-string
npm run dev -w apps/api
```

API listens on `http://localhost:8080`.

### 5) Start the UI

```bash
cd apps/web
npm run dev
```

---

## Configuration (env vars)

The API reads env vars in `apps/api/src/lib/env.ts`:
- `PORT` (default `8080`)
- `DATABASE_URL` (**required**)
- `JWT_SECRET` (**required**, min 16 chars)
- `SEGMENTRA_KEK_B64` (optional; base64 of 32-byte key for AES-256-GCM secret encryption)
- `SEGMENTRA_BOOTSTRAP_TOKEN` (optional; enables `POST /api/admin/bootstrap`)
- `BUNDLES_DIR` (default `./data/bundles`) — where deployment bundles/logs are written
- `ANSIBLE_RUNNER_CONTAINER` (default `segmentra-ansible-runner`)

---

## How to use (happy path)

### 1) Login with default admin account

**Default credentials (created automatically on first run):**
- **Username**: `admin`
- **Password**: `admin`

⚠️ **Important**: Change the default password after first login! You can change it in the UI or via API endpoint `POST /api/auth/change-password`.

**Alternative: LDAP Authentication**

If you have LDAP configured and AD group mappings, you can login via `/api/auth/login` with your LDAP credentials. The system will:
1. First check for local users (with password_hash)
2. If not found, fall back to LDAP authentication

### 2) Configure LDAP + role mappings
- In the UI: **Admin → LDAP Settings**, then **Admin → AD Group → Role map**
- Ensure at least one of your AD groups maps to `admin` or `operator`

### 3) Configure deployment settings
- In the UI: **Admin → Deployment Executor** — Choose between Ansible (recommended) or SSH Direct
- In the UI: **Admin → SSH Credentials** — Create a **GLOBAL** SSH credential
  - **Important**: Use a **sudo-capable account** (not root). Most modern Linux systems disable root SSH login.
  - The account must have passwordless sudo access to firewall commands (`nft`, `iptables`, `iptables-restore`)
  - The system automatically uses `sudo` for all privileged operations

### 4) Add inventory
- **Tags & VLANs**: Create tags and VLANs first (Inventory → Tags/VLANs tabs)
- **Hosts**: Add hosts with hostname, management IP, assign VLAN and tags
  - **SSH Port**: Configure the SSH port for deployments (default: 22). Use custom ports (e.g., 2022, 2222) for hosts that don't use the standard SSH port. The system automatically uses the configured port for both Ansible and SSH Direct deployments.
  - **Firewall Backend**: Choose the firewall backend for each host (`auto`, `nftables`, or `iptables`). See [Firewall Backend Configuration](#firewall-backend-configuration) below for details.
  - **Note**: Disabled hosts (`enabled=false`) are automatically skipped from all policy deployments. They will never receive firewall policies and will be marked as `SKIPPED` in deployment status.
- **Interfaces**: Add interfaces per host (name + role such as `data`, `management`, etc.)

### 5) Create & approve a policy version
- Create a **Policy Set**
- Create a **Policy Version** (DRAFT), add rules, then **Submit for approval**
- Approver/Admin approves in **Approvals**

### 6) Deploy
- Create a Deployment targeting hosts/tags/vlans (policy version must be APPROVED)
- Start it (creates bundle + runs selected executor: Ansible or SSH Direct)
- Review results in **Deployments** and logs via execution logs endpoint

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

Both executors:
- Support sudo-capable accounts (not root)
- Create backups before applying rules
- Attempt rollback on failure
- Work with nftables and iptables

## Notes / current v1 limitations
- Canary/progressive orchestration and advanced guardrails are stubbed at the API level (basic deployment flow is implemented).
- Baseline mgmt SSH CIDR is currently hardcoded (`10.0.0.0/8`) in v1 rendering; this should move to admin config.
- SSH Direct executor runs sequentially (one host at a time); Ansible runs in parallel.


