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

### 4) Start the API

Set required env vars (minimum: `DATABASE_URL`, `JWT_SECRET`):

```bash
set JWT_SECRET=change-me-to-a-long-random-string
npm run dev
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

### 1) Bootstrap an admin (first run only)

Option A: enable bootstrap in env:
- set `SEGMENTRA_BOOTSTRAP_TOKEN` in the API env
- call `POST /api/admin/bootstrap` with `{ "token": "...", "username": "bootstrap_admin" }`

Option B: if you already have LDAP configured and AD group mappings, just login via `/api/auth/login`.

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

## Deployment Executors

Segmentra supports two deployment executors, selectable in Admin settings:

### Ansible (Default, Recommended)
- Uses Ansible playbook for deployments
- Better error handling and automatic rollback
- Parallel execution across hosts
- Requires Ansible container (`segmentra-ansible-runner`)
- Uses `become: true` (sudo) for all privileged operations

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


