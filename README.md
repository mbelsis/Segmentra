<div align="center">
  <img src="logo/segmentra.png" alt="Segmentra" style="max-width: 300px; height: auto;" />
</div>

# Segmentra

***Segmentra*** is an on-prem, web-based **fleet firewall & microsegmentation management** tool for Linux servers. It lets security and infrastructure teams centrally define **host firewall policies** (allow/deny), and deploy them at scale to nftables/iptables, via SSH or Ansible Playbook. It extends enforcement to **Kubernetes containers** and **OT/IoT devices** through gateway firewalls.

The platform enables:
- **Inventory creation and auto-tagging**
- **Policy versioning**
- **Policy impact analysis**
- **Policy troubleshooting**
- **Policy canary testing**
- **Policy templates and auto-assignment**
- **Segregation of duties**
- **Approval tracking**
- **Audit trails**
- **Compliance monitoring**
- **Topology building**
- **Default access rules for each policy**

**Future plans** include integrations with Syslog, Threat Intelligence feeds and SOAR, and automatic rollback when a policy expires (today, expiry only marks the deployment expired and sends a notification).

---

## Features & Capabilities

### Authentication & Authorization
- **LDAP/Active Directory Integration** with AD group-to-role mapping
- **Local User Management** — create, edit, disable, and reset passwords for local users directly in the Admin UI (no LDAP required for small teams)
- **Role-Based Access Control (RBAC)** enforced at both API and UI level:
  - **Viewer** — read-only access to all dashboards, inventory, policies, and deployments
  - **Operator** — manage inventory, create policies/rules, run deployments, troubleshoot, manage IoT assets
  - **Approver** — approve/reject policy versions (separation of duties — cannot create policies)
  - **Admin** — full access including users, LDAP, SSH credentials, integrations, notifications, and system settings
- **JWT Authentication** — stateless tokens in browser localStorage, sent as `Authorization: Bearer <token>`
- **Separation of Duties** — a policy version cannot be approved by the user who created, edited or submitted it; high-risk policies require a different approver even for admins

### Inventory Management
- **Host Management** — add Linux servers with management IPs, SSH ports, firewall backend selection (nftables/iptables/auto)
- **Tags & VLANs** — organize hosts by custom tags and VLAN membership; VLANs also serve as OT/IoT zones
- **Auto-Tagging Rule Engine** — define criteria (hostname regex, CIDR ranges, OS family, VLAN, existing tags) with AND/OR logic to automatically classify hosts; evaluates every 5 minutes and on-demand
- **Automated Discovery** — discovery profiles scan IPv4 networks (CIDRs and/or VLAN subnets, max /20 per network and 8192 addresses per run) for SSH, log in with existing or new SSH credentials (read-only fact collection: hostname, OS, nft/iptables, sudo) and import new hosts with a default tag (`new-server`); manual **Run Now** or on a schedule, with per-address run history
- **System Tags** — `iot-gateway` and `bastion` are protected tags that cannot be deleted
- **Interface Configuration** — define network interfaces with roles (data, management, backup, etc.)
- **Bulk Operations** — CSV import, bulk tag/VLAN assignment, bulk enable/disable
- **Host Readiness Check** — verify nftables/iptables, sudo access, and kernel support before deployment
- **Compliance & Drift Detection** (agentless) — SSH-based comparison of current firewall rules vs. last deployed policy hash
- **Policy Visualization** — interactive SVG diagrams showing connections per host (color-coded allow/deny)

<div align="center">
  <img src="docs/images/inventory.png" alt="Inventory Management" style="max-width: 100%; height: auto;" />
</div>

### Policy Management
- **Policy Sets** — organize rules by scope (TAG, VLAN, or HOST_LIST)
- **Version Control** — every change creates a new version with the lifecycle DRAFT → PENDING_APPROVAL → APPROVED / REJECTED → DEPLOYED; approved, deployed and pending versions can be ARCHIVED
- **Policy Templates** — reusable blueprints (e.g., "Web Server") with one-click instantiation; optional auto-apply when hosts gain a matching tag
- **Visual Topology Design** — draw network flows between groups, auto-discover from existing infrastructure, and generate policies automatically
- **Policy Recommendations** — after firewall learning, auto-generate rules from observed traffic with confidence scoring and IP-to-tag resolution
- **Policy Impact Analysis** — semantic diff showing new/removed allows and denies per host before approval
- **High-Risk Detection** — audit policies to flag broad rules, wide scopes, and sensitive port exposure
- **Policy Expiry** — optional time-limited deployments with 24-hour warnings. On expiry the deployment is marked `EXPIRED` and a notification is sent. The `REMOVE` and `REVERT` expiry actions currently only send a "manual rollback required" / "redeploy previous version" notification — rules on the hosts are **not** changed automatically
- **Policy Archive & Delete** — archive deployed/approved versions (read-only), delete DRAFT/REJECTED versions

### Deployment Management
- **Deployment Modes** — Full, Canary, and Progressive (canary/progressive modes currently process all hosts in a single batch)
- **Scheduled Deployments** — schedule for future execution (e.g., maintenance windows); auto-starts via background job
- **Two Executors** — Ansible (parallel, recommended) or SSH Direct (lightweight, no Ansible dependency)
- **Safety Guardrails** — pre-deployment validation ensures SSH access from management VLAN is preserved
- **Automatic Rollback** — failed deployments restore previous state from host-local backups
- **Real-time Tracking** — per-host deployment status with 10-minute timeout for unresponsive hosts

<div align="center">
  <img src="docs/images/deployments.png" alt="Deployments" style="max-width: 100%; height: auto;" />
</div>

### Troubleshooting & Analysis
- **Communication Simulation** — test if traffic between two IPs would be blocked by deployed policies
- **Firewall Learning** (agentless) — deploy log-only rules via SSH, capture all traffic for a set duration, auto-restore original rules, parse and display communication flows
- **On-Device Policy Testing** — deploy a specific policy in log-only mode, then analyze observed traffic for coverage gaps (matched, unmatched, unexpected blocks)
- **Policy Search** — find which policies apply to a specific IP, host, or policy version

<div align="center">
  <img src="docs/images/troubleshooting.png" alt="Troubleshooting" style="max-width: 100%; height: auto;" />
</div>

### OT/IoT Microsegmentation
- **Separate Asset Inventory** — register PLCs, HMIs, sensors, cameras, HVAC, medical devices with vendor/model/firmware/criticality metadata
- **Gateway Model** — IoT devices are assigned to gateway firewalls (regular Linux hosts tagged `iot-gateway` in the inventory); policies deploy to gateways via the normal SSH/Ansible pipeline
- **VLANs as Zones** — OT network zones (Purdue levels) are defined as VLANs in the inventory
- **Traffic Discovery** — run Firewall Learning on the gateway host to observe IoT traffic passively
- **Deployment Warning** — deploying to IoT gateways triggers a warning about impact on protected devices

### Kubernetes Microsegmentation
- **Agentless K8s Management** — connect to Kubernetes API servers to discover workloads and generate NetworkPolicy manifests
- **Workload Discovery** — sync namespaces, pods, deployments, services, and labels
- **Label-to-Tag Mapping** — map K8s labels to Segmentra tags for unified policy management
- **NetworkPolicy Generation** — translate Segmentra rules into K8s NetworkPolicy JSON manifests for export; apply to clusters via `kubectl` or CI/CD pipelines
- **Multi-Cluster Support** — manage multiple clusters from a single instance

### Security & Compliance
- **Security Posture Audit** — on-demand scan of all deployed policies for excessive permissions (8 categories: sensitive ports open to any, broad CIDRs, any-protocol rules, ALL_INTERFACES exposure, duplicate rules, unmanaged hosts, stale policies)
- **Comprehensive Audit Trail** — every action logged with actor, timestamp, entity, and rich metadata
- **Notification System** — Slack webhooks, generic HTTP webhooks, email (stub); subscribe channels to 10 event types (policy approvals, deployment failures, compliance drift, expiry warnings, security findings)
- **Encrypted Secret Storage** — SSH keys/passwords and LDAP passwords encrypted with AES-256-GCM (key: `SEGMENTRA_KEK_B64`)
- **Integrations** — administrative registry for SIEM, SOAR, vulnerability scanners, and threat intelligence feeds. Track integration configuration, credentials, and sync status. Actual data exchange with external systems requires custom adapter implementation.

### Dashboard
- **Real-time Overview** — deployment status, success rates, activity charts
- **Current Deployments** — live progress tracking with per-host status
- **Top Deployers** — most active users

<div align="center">
  <img src="docs/images/dashboard.png" alt="Dashboard" style="max-width: 100%; height: auto;" />
</div>

---
### ACL Audit 

<div align="center">
  <img src="docs/images/Policies_audit.png" alt="Dashboard" style="max-width: 100%; height: auto;" />
</div>


### Topology 

<div align="center">
  <img src="docs/images/Topology.png" alt="Dashboard" style="max-width: 100%; height: auto;" />
</div>


Still Work in progress :) :) 

### IOT / OT 

<div align="center">
  <img src="docs/images/IOT.png" alt="Dashboard" style="max-width: 100%; height: auto;" />
</div>

### Kubernetes 

<div align="center">
  <img src="docs/images/Kubernetes.png" alt="Dashboard" style="max-width: 100%; height: auto;" />
</div>

### Integrations 

<div align="center">
  <img src="docs/images/Integrations.png" alt="Dashboard" style="max-width: 100%; height: auto;" />
</div>


## User Journey

This is the typical path from an empty installation to enforced firewall rules. Each step names the page in the left-hand menu and the role needed.

### 1. One-time setup (Admin, `admin` role)

- **Deployment executor:** choose **SSH Direct** (lightweight) or **Ansible** (needs the runner container).
- **SSH credentials:** add the account Segmentra uses to reach your hosts, with either a private key or a password. It needs `sudo` rights for `nft` / `iptables`. Credentials are stored encrypted. A global credential applies to all hosts unless a host has its own.
- **Management VLAN:** pick the VLAN whose subnet may always reach SSH on every host. Without one, SSH is allowed from any source so hosts can't be locked out.
- **Users and roles:** create accounts and give them roles (`viewer`, `operator`, `approver`, `admin`). You need at least two people who can approve, because nobody can approve their own changes (see step 5).

### 2. Inventory: tell Segmentra what you have (`operator` or `admin`)

- **Hosts:** add hosts one by one or with **Bulk Import** (CSV). Each host has a management IP, SSH port and firewall backend (`nftables`, `iptables` or auto).
- **Check Readiness:** confirms Segmentra can log in over SSH, use `sudo`, and find the firewall tool.
- **Tags and VLANs:** group hosts (e.g. `web`, `db`) and network zones (VLANs with subnets). Rules can target whole groups instead of single IPs.
- **Auto-Tagging:** tag hosts automatically by hostname, IP, OS and so on. Use **Preview Matches** before saving.
- **Discovery:** instead of typing hosts in, create a discovery profile (admin): pick SSH credentials (or add one inline), the networks or VLANs to scan, a schedule (manual or every N minutes/hours) and a tag for new hosts (default `new-server`). **Run Now** (operator/admin) scans for open SSH ports, logs in read-only and imports hosts that are not yet in inventory; hosts that already exist are left untouched. Each run shows per-address results (imported, already present, login failed and why).
- **Optional:** use **Topology** to draw flows between groups and generate draft policies from them, or **Templates** to start from a reusable rule set.

### 3. Policy Sets: decide where a policy applies (`operator` or `admin`)

A **policy set** is a named policy with a **scope**: the hosts it applies to, chosen by tag, VLAN or an explicit host list. Create one under **Policy Sets → + Create Policy Set**.

### 4. Versions and rules: describe the access (`operator` or `admin`)

- Open the policy set and click **+ New Version** (or **Clone** an existing version to change it). A new version starts as `DRAFT`.
- Add **rules**: direction (in / out / both), allow or deny, protocol, ports, and source (CIDR, tag, VLAN or host). Rules are evaluated in order. Anything not allowed inbound is dropped; outbound is allowed by default.
- You never need rules for loopback, established connections or management SSH. Segmentra adds those automatically.
- On IoT/OT gateways (hosts tagged `iot-gateway`), use direction **FORWARD (through gateway)** for traffic routed *through* the gateway. A FORWARD rule has a source and a **destination** (CIDR, tag, VLAN, host or IoT device). Traffic to the IoT devices assigned to that gateway is denied unless a FORWARD rule allows it. Other forwarded traffic is not affected. See [docs/iot.md](docs/iot.md).
- When the version is ready, go back to the policy set and click **Submit for Approval**. The version becomes `PENDING_APPROVAL` and can no longer be edited.

### 5. Approvals: a second person reviews (`approver` or `admin`, but not the author)

- New versions must be approved by a user with the **`approver` or `admin` role who did not create, edit or submit that version**. The app blocks self-approval ("You cannot approve a policy version that you created, edited or submitted").
- On the **Approvals** page, the reviewer can expand a version, use **Analyze Impact** to compare it with an earlier approved or deployed version on sample hosts, and then **Approve** or **Reject** it with a reason.
- A rejected version can be fixed and resubmitted. An approved version becomes `APPROVED` and can be deployed.
- **High-risk deployments** (rules that open sensitive or management ports to very broad sources, "any/any"-style rules, or a wide interface scope across many hosts) also need a deployment-level approval by an `approver`/`admin` other than the person who created the deployment.

### 6. Deployments: push the rules to hosts (`operator` or `admin`)

- **Deployments → + Create Deployment:** pick an approved version, the targets and a mode (`FULL`, `CANARY` or `PROGRESSIVE`). You can also schedule it for later and set an expiry date with an action (notify only, remove the rules, or revert to the previous version).
- Click **Start**. Each host is backed up first, the rules are applied, and Segmentra checks that it can still reach the host over SSH. If not, the change is reverted automatically after about two minutes.
- Follow progress on the deployment page. If some hosts fail, use **Retry Failed Hosts** once the problem is fixed. A successful deployment marks the version `DEPLOYED`, and the policy set page shows which version is **active** on how many hosts.
- Only Segmentra's own firewall rules are replaced. Rules from Docker, Kubernetes or fail2ban are left alone.

### 7. Operate: verify, troubleshoot and audit

- **Inventory → Check Compliance:** detects drift when someone changes Segmentra's rules on a host by hand.
- **Troubleshoot:** simulate whether traffic between two IPs would be allowed, search which policies affect an IP or host, or run **Firewall Learning** (log-only mode) to discover real traffic.
- **Policy Impact Analysis:** run a version in log-only mode on a host before enforcing it, then analyze which observed traffic it would allow or block.
- **Security Audit, Audit Log, Notifications and Integrations:** scan for risky rules, review who did what, get alerts (Slack or webhook), and forward audit events to a SIEM.

Typical lifecycle of a version: `DRAFT` → `PENDING_APPROVAL` → `APPROVED` (or `REJECTED` → fix → resubmit) → `DEPLOYED`; old versions can be `ARCHIVED`.

---

## Installation & Quick Start

### Automated Installation

**Linux/macOS:**
```bash
./install.sh --development    # Local dev environment
./install.sh --production     # Docker production deployment
```

**Windows (PowerShell):**
```powershell
.\install.ps1 --development
.\install.ps1 --production
.\run.ps1 -start -development     # note: run.ps1 uses single-dash switches
```

`--production` generates `JWT_SECRET`, `SEGMENTRA_KEK_B64`, `POSTGRES_PASSWORD` and `SEGMENTRA_ADMIN_PASSWORD` into `.env` (kept if already present) and prints the initial admin password. Back up `.env` — losing `SEGMENTRA_KEK_B64` makes stored SSH/LDAP secrets unrecoverable.

### Running

```bash
./run.sh --start --development    # Start dev (API + UI + DB)
./run.sh --stop --development     # Stop dev
./run.sh --start --production     # Start production (all Docker containers; the API runs migrations on start)
./run.sh --stop --production      # Stop production
```

### Default Login

- **Development**: `admin` / `admin123` (created by the seed when `SEGMENTRA_ADMIN_PASSWORD` is not set — change it after first login)
- **Production** (`NODE_ENV=production`): `admin` / the value of `SEGMENTRA_ADMIN_PASSWORD` (min. 12 chars). Without it the seed refuses to create the default admin; use `SEGMENTRA_BOOTSTRAP_TOKEN` instead if you only use LDAP.

### Docker

Production runs entirely in Docker; the images are built from this repository (no Node.js needed on the host):

```bash
./install.sh --production        # creates .env with generated secrets, builds and starts everything
# or manually, after creating .env:
docker compose up -d --build     # build the images and start db, API, web (nginx) and Ansible runner
```

Then open `http://<host>` (port 80). To upgrade: `git pull && docker compose up -d --build` (migrations run automatically). See [Building the Docker Images](docs/installation.md#building-the-docker-images) and [Upgrading](docs/installation.md#upgrading-to-a-new-version) for what each image contains, rebuilding single images and pushing to a registry.

For detailed installation instructions, see [installation.md](docs/installation.md).

---

## Integration Tests

Segmentra includes a Docker-based integration test for the SSH deployment path. If you want to validate a new local version of the app, you can run the starter script from the repository root:

```bash
npm run test:integration:ssh-docker
```

This builds the current code, starts a temporary API + PostgreSQL + 3 target-container environment, deploys sample firewall ACLs through the real API using both SSH password and SSH key authentication, verifies the resulting `iptables` state, and runs live `ping` checks between the targets. For full details, see [tests/README.md](tests/README.md).

---

## Architecture

TypeScript monorepo:

| Component | Location | Purpose |
|-----------|----------|---------|
| **API** | `apps/api` | Express + PostgreSQL backend |
| **UI** | `apps/web` | React (Vite) frontend |
| **Compiler** | `packages/compiler` | Policy → nftables/iptables rules |
| **Executor** | `packages/executor` | SSH Direct + Ansible deployment |
| **DB** | `packages/db` | PostgreSQL migrations + seed scripts |

Production runs 4 Docker containers: `segmentra-web` (nginx, port 80), `segmentra-app` (API, published on 127.0.0.1:8080 only), `segmentra-db` (PostgreSQL, 127.0.0.1:15432 only), `segmentra-ansible-runner` (Ansible executor).

> **Security note — Docker socket:** `segmentra-app` mounts `/var/run/docker.sock` so the Ansible executor can run `docker exec segmentra-ansible-runner ansible-playbook ...`. Access to the Docker socket is equivalent to root on the Docker host. If you only use the SSH executor, remove that mount (and `group_add`) from `docker-compose.yml`.

For detailed technical documentation, see [Architecture.md](docs/Architecture.md).

---

## Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | Yes | — | PostgreSQL connection string |
| `JWT_SECRET` | Yes | — | JWT signing secret. Min. 32 chars when `NODE_ENV=production` (16 in dev); known placeholder values are refused in production |
| `SEGMENTRA_KEK_B64` | Prod: yes | — | 32 random bytes, base64 (`openssl rand -base64 32`): key for AES-256-GCM secret encryption. If unset, the key is **derived from `JWT_SECRET`**, so rotating `JWT_SECRET` makes stored secrets undecryptable. Set it explicitly in production and **before** storing any secrets; changing it later requires re-entering secrets. The Docker image refuses to start without it |
| `NODE_ENV` | No | — | `production` enables strict checks (JWT length, KEK required in Docker, no default admin password) |
| `PORT` | No | `8080` | API server port |
| `BUNDLES_DIR` | No | `./data/bundles` | Deployment bundle directory (`/bundles` in Docker, shared with the Ansible runner) |
| `ANSIBLE_RUNNER_CONTAINER` | No | `segmentra-ansible-runner` | Ansible runner container name used with `docker exec` |
| `CORS_ORIGIN` | No | — (allow all) | Comma-separated allowed browser origins; set in production |
| `TRUST_PROXY` | No | — | Express `trust proxy` value (`1`, `loopback`, CIDR, `true`) when the API is behind a reverse proxy, so client IPs (login rate limiting, audit) are correct. docker-compose sets `1` (nginx) |
| `SEGMENTRA_KNOWN_HOSTS` | No | `~/.ssh/known_hosts` | known_hosts file for SSH executor / readiness / audit connections. Unknown hosts are trusted on first use (`StrictHostKeyChecking=accept-new`); changed host keys are rejected |
| `SEGMENTRA_ALLOW_PRIVATE_WEBHOOKS` | No | `false` | Set `true` to allow notification webhooks to loopback, link-local and cloud-metadata addresses (blocked by default to prevent SSRF; RFC1918 private ranges are always allowed) |
| `SEGMENTRA_BOOTSTRAP_TOKEN` | No | — | Enables the one-time `POST /api/admin/bootstrap` endpoint (only while no users exist) |
| `SEGMENTRA_ADMIN_PASSWORD` | Prod: yes | `admin123` in dev | Password for the initial `admin` user created by `npm run db:seed` (min. 12 chars in production) |
| `SEGMENTRA_SSH_COMMAND_TIMEOUT_MS` | No | `300000` | Per-command SSH timeout |

docker-compose additionally reads `POSTGRES_PASSWORD` (or legacy `DB_PASSWORD`), `DB_USER`, `DB_NAME`, `DB_PORT`, `API_PORT`, `API_BIND`, `WEB_PORT` and `DOCKER_GID` (group owning `/var/run/docker.sock`).

---

## Coexistence with Docker, Kubernetes and fail2ban

Segmentra only manages its own firewall objects and leaves rules created by other tools alone:

- **nftables:** everything lives in `table inet segmentra`, which is replaced atomically on each deploy. Other tables (Docker, Kubernetes, fail2ban) are not touched.
- **iptables / ip6tables:** rules live in the dedicated chains `SEGMENTRA-IN` and `SEGMENTRA-OUT`, applied with `iptables-restore --noflush` and reached from a single jump at the top of `INPUT` / `OUTPUT`. `DOCKER*`, `KUBE-*` and `f2b-*` chains, the `FORWARD` chain (except the one jump described below for gateways) and the built-in chain policies are not modified. The default inbound drop is the last rule of `SEGMENTRA-IN`. Allowed traffic leaves Segmentra's chain with `RETURN` (not `ACCEPT`), so rules after the jump still apply, such as fail2ban bans or your own `DROP`s. This matches nftables, where an accept in `table inet segmentra` doesn't override a drop in another table. If you set the `INPUT` policy to `DROP` yourself, you also need your own accept rules for traffic Segmentra allows.
- **Backend tools:** a host configured for iptables only needs `iptables-restore`, and one configured for nftables only needs `nft`. Having both installed is fine; modern distributions ship `iptables-nft` alongside `nft`.
- **Upgrading hosts deployed by older versions** (which replaced the whole iptables filter table): the first deploy removes the old Segmentra rules from `INPUT`/`OUTPUT` and resets the `INPUT`/`OUTPUT` policy to `ACCEPT` (only if Segmentra had set it to `DROP`). Rules that can't be positively identified as Segmentra's are left in place and reported as warnings in the deployment output. `FORWARD` is left at `DROP` when Docker or Kubernetes chains are present.

- **Forwarded traffic (IoT/OT gateways):** forwarding is filtered only on hosts whose policy has FORWARD rules or that protect IoT devices (assets assigned to the host on the OT/IoT page). With nftables this is a `chain forward` inside `table inet segmentra` (policy `accept`). With iptables it is a `SEGMENTRA-FWD` chain reached from a single jump at the top of `FORWARD`. Only traffic *to protected devices* is dropped unless a FORWARD rule allows it. Other forwarded traffic, including Docker's, passes as before. Allowed traffic leaves `SEGMENTRA-FWD` with `RETURN`, so `DOCKER-USER` and other `FORWARD` rules after the jump still apply. Deploying a version without forwarding, or removing the policy, deletes the forward chain and its jump. On other hosts nothing changes.

Drift detection only fingerprints Segmentra's own table/chains (including `SEGMENTRA-FWD` and its jump), so rule changes made by Docker, Kubernetes or fail2ban are not reported as drift.

## Known Limitations

- **Restores on legacy iptables hosts.** Backups and restores (lockout auto-revert, failure rollback, firewall-learning / policy-test restores, `scripts/restore-previous-policy.sh`) only cover Segmentra's own `table inet segmentra` or `SEGMENTRA-IN` / `SEGMENTRA-OUT` chains, so other tools' rules are never replaced. The exception is a host still running a policy deployed by an older version that replaced the whole iptables filter table: restoring that backup replaces the `filter` table, so filter rules other tools added after the backup are lost. Redeploying once moves the host to the chain-based design.
- **Drift baselines from older versions.** Hosts last deployed before drift fingerprints were scoped to Segmentra's own rules show compliance status `unknown` until they are redeployed once.
- **Policy expiry actions.** If a REMOVE or REVERT action fails, the error is recorded and a notification is sent, but it is not retried automatically. REVERT redeploys the previous version only to hosts that actually ran it; other hosts keep the expired policy and are listed in the notification.
- **sudo on target hosts.** Hosts that use SSH-key credentials need passwordless `sudo`. For password credentials, the SSH password is also used as the sudo password.
- **SIEM forwarding.** Notification webhooks connect only to the exact address that was validated, so DNS rebinding doesn't work against them. Syslog/SIEM destinations configured by admins don't get the same connect-time address check.
- **Docker socket.** The Ansible executor runs `docker exec` and therefore needs `/var/run/docker.sock`, which is root-equivalent on the Docker host. SSH-executor-only installations can remove the mount.

---

## Not Yet Tested

The core workflow was tested end to end through the web UI against Docker containers running iptables and nftables. That covers inventory, policy sets, versions, approvals, deployments, drift, expiry REMOVE/REVERT, simulator, topology, templates, OT/IoT, security audit, SIEM syslog, webhooks and role-based access. The automated Docker SSH integration test also passes. These parts have **not** been verified yet:

- **Traffic capture in Firewall Learning and Policy Impact Analysis.** Deploying log-only rules, restoring and analyzing all work, but the test containers can't log kernel firewall messages, so no real flows were captured or analyzed. This needs a real host with rsyslog or journald.
- **Threat Intelligence (AbuseIPDB) sync and auto-block.** Needs internet access and an API key.
- **LDAP / Active Directory login and group-to-role mapping.** Saving settings was tested; logging in against a real directory was not.
- **Kubernetes workload sync.** Registering a cluster and generating NetworkPolicy manifests was tested; there was no real cluster to sync from or apply to.
- **High-risk deployment approval, deployment pause/resume and password change** were not exercised in the UI tests. (Auto-tagging and template auto-apply were tested: rules on hostname, IP, OS, backend, VLAN and tags; AND/OR; disable, retarget and delete removing only rule-assigned tags; priority between rules; the 5-minute job adding and removing tags; discovery imports; and auto-apply creating a DRAFT policy when a tag is first assigned.)
- **Canary and progressive deployment modes** across larger fleets (only `FULL` deployments to two hosts were tested).
- **Automatic revert under systemd** (`systemd-run`). The containers have no systemd; the equivalent `nohup` path was tested.
- **Real Linux distributions** (Debian, Ubuntu, RHEL). Testing used Alpine containers.
- **Windows scripts** (`start.bat`, `run.ps1`, `install.ps1`, `scripts/check-db-status.ps1`).
- **Slack and email notification channels** (only the generic webhook was tested).
- **IoT gateway forwarding:** tested live with one gateway and one PLC on nftables and iptables (allow/deny, edit, expiry REMOVE, drift, simulator). Not tested: IPv6 forwarding, the Ansible executor with FORWARD rules, expiry REVERT on a gateway, several gateways protecting the same device, and real OT protocols beyond a TCP test listener. See the [OT/IoT guide](docs/iot.md#8-limitations-and-what-is-not-tested).
- **Inventory discovery:** tested with password credentials on a /24 (import, skip of existing hosts, failed logins, scheduled runs). Not tested: hosts that need a sudo password, large subnets close to the /20 limit, and real networks with firewalls that drop rather than reject SSH probes.

---

## Documentation

| Document | Description |
|----------|-------------|
| [Installation Guide](docs/installation.md) | Dev and production setup |
| [Architecture](docs/Architecture.md) | API endpoints, database schema, RBAC matrix |
| [User Guide](docs/guide.md) | Step-by-step usage for all features |
| [Security: Credentials and Secrets](docs/security.md) | How SSH passwords/keys and LDAP passwords are encrypted, the encryption key, and who can access them |
| [OT/IoT Guide](docs/iot.md) | IoT microsegmentation with gateway model |
| [Gateway Setup](docs/gateway-setup-guide.md) | Linux gateway firewall configuration |
| [Kubernetes Guide](docs/kubernetes.md) | K8s NetworkPolicy management |
| [Ansible Playbook](docs/playbook-ansible.md) | Deployment playbook documentation |
| [Full Specification](docs/segmentra_fleet_microsegmentation_firewall_manager_full_specification.md) | Complete technical specification |

---

## License

See [LICENSE.md](LICENSE.md) for details.
