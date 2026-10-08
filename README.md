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

**Future plans** include more integration adapters (SOAR, vulnerability databases), live Kubernetes workload sync and direct NetworkPolicy apply, and a real email notification channel. See [Future Work](#future-work).

---

## Screenshots

Click an image to open it full size.

<table>
  <tr>
    <td align="center" width="33%">
      <a href="screehsots/01-dashboard.png"><img src="screehsots/01-dashboard.png" alt="Dashboard" width="100%"></a><br>
      <b>Dashboard</b><br>
      <sub>Deployment statistics, managed hosts, pending approvals and the latest security audit</sub>
    </td>
    <td align="center" width="33%">
      <a href="screehsots/02-policy-sets.png"><img src="screehsots/02-policy-sets.png" alt="Policy Sets" width="100%"></a><br>
      <b>Policy Sets</b><br>
      <sub>Policies with their scope (tag, VLAN or host list) and version status</sub>
    </td>
    <td align="center" width="33%">
      <a href="screehsots/03-policy-templates.png"><img src="screehsots/03-policy-templates.png" alt="Policy Templates" width="100%"></a><br>
      <b>Policy Templates</b><br>
      <sub>Reusable rule sets, optionally auto-applied when a host gets a tag</sub>
    </td>
  </tr>
  <tr>
    <td align="center" width="33%">
      <a href="screehsots/04-inventory.png"><img src="screehsots/04-inventory.png" alt="Inventory" width="100%"></a><br>
      <b>Inventory</b><br>
      <sub>Hosts with tags, VLAN, firewall backend, effective SSH credential and compliance</sub>
    </td>
    <td align="center" width="33%">
      <a href="screehsots/05-topology.png"><img src="screehsots/05-topology.png" alt="Topology" width="100%"></a><br>
      <b>Topology</b><br>
      <sub>Draw allowed and denied flows between groups and generate policies from them</sub>
    </td>
    <td align="center" width="33%">
      <a href="screehsots/06-troubleshoot.png"><img src="screehsots/06-troubleshoot.png" alt="Troubleshoot" width="100%"></a><br>
      <b>Troubleshoot</b><br>
      <sub>Firewall Learning (log-only traffic discovery) and the communication simulator</sub>
    </td>
  </tr>
  <tr>
    <td align="center" width="33%">
      <a href="screehsots/07-policy-impact-analysis.png"><img src="screehsots/07-policy-impact-analysis.png" alt="Policy Impact Analysis" width="100%"></a><br>
      <b>Policy Impact Analysis</b><br>
      <sub>Test a policy against real traffic in log-only mode before enforcing it</sub>
    </td>
    <td align="center" width="33%">
      <a href="screehsots/08-security-audit.png"><img src="screehsots/08-security-audit.png" alt="Security Audit" width="100%"></a><br>
      <b>Security Audit</b><br>
      <sub>Findings by severity, e.g. hosts without a deployed policy</sub>
    </td>
    <td align="center" width="33%">
      <a href="screehsots/09-audit-log.png"><img src="screehsots/09-audit-log.png" alt="Audit Log" width="100%"></a><br>
      <b>Audit Log</b><br>
      <sub>Every change and deployment, with actor and details</sub>
    </td>
  </tr>
</table>

---

## Features & Capabilities

### Authentication & Authorization
- **LDAP/Active Directory Integration** with AD group-to-role mapping (group DNs are matched case- and whitespace-insensitively; LDAP users' passwords can't be reset in Segmentra)
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
- **Tags & VLANs** — organize hosts by custom tags and VLAN membership; VLANs also serve as OT/IoT zones. A tag or VLAN that policy or template rules still reference can't be deleted
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
- **Policy Templates** — reusable blueprints (e.g., "Web Server") with one-click instantiation; optional auto-apply creates a DRAFT policy when a matching tag is first assigned to hosts
- **Visual Topology Design** — draw network flows between groups, auto-discover from existing infrastructure, and generate policies automatically
- **Policy Recommendations** — after firewall learning, auto-generate rules from observed traffic with confidence scoring and IP-to-tag resolution
- **Policy Impact Analysis** — semantic diff showing new/removed allows and denies per host before approval
- **High-Risk Detection** — audit policies to flag broad rules, wide scopes, and sensitive port exposure
- **Policy Expiry** — optional time-limited deployments with 24-hour warnings. On expiry the deployment is marked `EXPIRED`, a notification is sent and the expiry action runs: `NOTIFY_ONLY` does nothing else, `REMOVE` removes Segmentra's rules (`table inet segmentra` or the `SEGMENTRA-*` chains) from the hosts, and `REVERT` redeploys the previous successfully deployed version of the same policy set
- **Policy Archive & Delete** — archive deployed/approved versions (read-only), delete DRAFT/REJECTED versions

### Deployment Management
- **Deployment Modes** — Full, Canary, and Progressive. With the SSH Direct executor hosts are deployed one at a time in hostname order: Canary stops if one of the first *N* canary hosts (default 1) fails, Progressive stops at the end of a batch (default 5 hosts) that had a failure; halted hosts are marked skipped and can be resumed with **Retry Failed Hosts**. The Ansible executor deploys all target hosts in one playbook run
- **Scheduled Deployments** — schedule for future execution (e.g., maintenance windows); auto-starts via background job
- **Two Executors** — Ansible (parallel, recommended) or SSH Direct (lightweight, no Ansible dependency)
- **Safety Guardrails** — pre-deployment validation ensures SSH access from management VLAN is preserved
- **Automatic Rollback** — failed deployments restore previous state from host-local backups
- **Real-time Tracking** — per-host deployment status with 10-minute timeout for unresponsive hosts; **Retry Failed Hosts**, pause/resume/stop, and a deployment-level approval for high-risk deployments
- **Lockout protection** — after applying rules Segmentra checks that it can still reach the host over SSH; if not, the previous rules are restored automatically after 120 seconds

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
- **Cluster Registry** — register multiple clusters (API server URL, auth details) from a single instance
- **Workloads and Label-to-Tag Mapping** — view workloads stored for a cluster and map them to Segmentra tags. **Workload sync is not implemented**: the sync endpoint returns 501 and Segmentra does not contact the Kubernetes API, so workloads are not discovered automatically (the demo data seeds some)
- **NetworkPolicy Generation** — **Generate NetworkPolicy** translates the ALLOW rules of an approved or deployed policy version into an Ingress-only `networking.k8s.io/v1` NetworkPolicy manifest (DENY, FORWARD and other rules that cannot be expressed exactly are skipped with a warning). Segmentra does not apply it: copy the `kubectl apply` command or download the JSON

### Security & Compliance
- **Security Posture Audit** — on-demand scan of all deployed policies for excessive permissions (8 categories: sensitive port open to any, all ports open to any, very broad source CIDRs, any-protocol / any-port rules, `ALL_INTERFACES` with a broad source, duplicate rules, unmanaged hosts, stale policies)
- **Comprehensive Audit Trail** — changes logged with actor, timestamp, entity, and rich metadata
- **Notification System** — Slack webhooks and generic HTTP webhooks (email channels are not implemented: there is no SMTP support and sends are logged as failed); subscribe channels to 11 event types (policy submitted/approved/rejected, deployment started/completed/failed, policy expiring soon/expired, excessive rules detected, firewall-learning restore failed, compliance drift). The compliance-drift event can be selected but is not emitted yet, and the optional per-rule `filter` is stored but not applied
- **Encrypted Secret Storage** — SSH keys, key passphrases, SSH and sudo passwords and LDAP passwords encrypted with AES-256-GCM (key: `SEGMENTRA_KEK_B64`); see [docs/security.md](docs/security.md)
- **Integrations** — registry for SIEM, SOAR, vulnerability databases and threat intelligence feeds. Working adapters: **SIEM** (syslog over UDP/TCP; every Audit Log entry is forwarded once, see [docs/security.md](docs/security.md)) and **AbuseIPDB** threat intelligence (sync, optional auto-block into a DRAFT version of a policy set; repeated syncs reuse the open auto-block draft and skip IPs already blocked). SOAR and vulnerability-database entries only store configuration and sync status.

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
- **SSH credentials:** add the account Segmentra uses to reach your hosts, with a private key (optionally passphrase-protected) or a password, and choose how it becomes root: **sudo without password**, **sudo with the login password**, or **sudo with a separate password**. The account needs full sudo rights (it runs `sh` as root); nothing is installed on the hosts. Credentials are stored encrypted. Each credential **applies to** all hosts (global), hosts with a tag, hosts in a VLAN, one host, or no host automatically (*not assigned*, for discovery or explicit assignment). Each host uses its explicitly assigned credential, else a host-, tag-, VLAN- and finally the global credential; the Inventory host list shows which one each host uses.
- **Management VLAN:** pick the VLAN whose subnet may always reach SSH on every host. Without one, SSH is allowed from any source so hosts can't be locked out.
- **Users and roles:** create accounts and give them roles (`viewer`, `operator`, `approver`, `admin`). You need at least two people who can approve, because nobody can approve their own changes (see step 5).

### 2. Inventory: tell Segmentra what you have (`operator` or `admin`)

- **Hosts:** add hosts one by one or with **Bulk Import** (CSV). Each host has a management IP, SSH port and firewall backend (`nftables`, `iptables` or auto).
- **Check Readiness:** confirms Segmentra can log in over SSH, use `sudo`, and find the firewall tool.
- **Tags and VLANs:** group hosts (e.g. `web`, `db`) and network zones (VLANs with subnets). Rules can target whole groups instead of single IPs.
- **Auto-Tagging:** tag hosts automatically by hostname, IP, OS and so on. Use **Preview Matches** before saving.
- **Discovery:** instead of typing hosts in, create a discovery profile (admin): pick SSH credentials (or add one inline), the networks or VLANs to scan, a schedule (manual or every N minutes/hours) and a tag for new hosts (default `new-server`). **Run Now** (operator/admin) scans for open SSH ports, logs in read-only and imports hosts that are not yet in inventory; hosts that already exist are left untouched. Each run shows per-address results (imported, already present, login failed and why). Credentials added inline in a profile are stored as *not assigned* (unless you make them global), so they never change the credential of other hosts; each imported host is assigned the credential that logged in.
- **Optional:** use **Topology** to draw flows between groups and generate draft policies from them, or **Templates** to start from a reusable rule set.

### 3. Policy Sets: decide where a policy applies (`operator` or `admin`)

A **policy set** is a named policy with a **scope**: the hosts it applies to, chosen by tag, VLAN or an explicit host list. Create one under **Policy Sets → + Create Policy Set**.

### 4. Versions and rules: describe the access (`operator` or `admin`)

- Open the policy set and click **+ New Version** (or **Clone** an existing version to change it). A new version starts as `DRAFT`.
- Add **rules**: direction (in / out / both, or FORWARD on gateways), allow or deny, protocol, ports, and source (CIDR, tag, VLAN or host). Rules are evaluated in order. Anything not allowed inbound is dropped; outbound is allowed by default.
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
- **Security Audit, Audit Log, Notifications and Integrations:** scan for risky rules, review who did what, get alerts (Slack or webhook), and forward the audit log to a SIEM.

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

### Security hardening

Segmentra can change the firewall of every managed host and stores SSH credentials with `sudo` rights on all of them, so a compromised Segmentra means compromised hosts. Before going to production:

- **Use the hardened override:** `docker compose -f docker-compose.yml -f docker-compose.hardened.yml up -d --build`. This removes the Docker socket, makes the containers read-only, drops Linux capabilities, sets resource limits and publishes only nginx. It requires the SSH Direct executor.
- **Network:** serve the UI over TLS (reverse proxy) and make it reachable only from a management network or VPN.
- **Managed hosts:** use a dedicated SSH user with keys, restricted to logins from the Segmentra host, and set a management VLAN.
- **Secrets:** `chmod 600 .env` and back it up separately from database backups.
- **People:** use LDAP with MFA at your identity provider, keep few admins, and monitor the audit log (forward it to your SIEM).

The full guide, including what is already hardened and the remaining gaps, is in [docs/security.md](docs/security.md#hardening-a-production-install).

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

Production runs 4 Docker containers: `segmentra-web` (nginx, port 80), `segmentra-app` (API, published on 127.0.0.1:8080 only), `segmentra-db` (PostgreSQL, 127.0.0.1:15432 only), `segmentra-ansible-runner` (Ansible executor). With the hardened override (`docker-compose.hardened.yml`) the Ansible runner is not started (only with `--profile ansible`) and only nginx is published.

> **Security note — Docker socket:** `segmentra-app` mounts `/var/run/docker.sock` so the Ansible executor can run `docker exec segmentra-ansible-runner ansible-playbook ...`. Access to the Docker socket is equivalent to root on the Docker host. If you only use the SSH executor, remove that mount (and `group_add`) from `docker-compose.yml`, or use the hardened override, which does this.

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
| `SEGMENTRA_ASKPASS_DIR` | No | OS temp dir | Directory for the `SSH_ASKPASS` helper script used for passphrase-protected keys (the script contains no secret) |
| `SEGMENTRA_SKIP_MIGRATIONS` | No | `0` | API Docker image only: `1` skips the migrations and seed the entrypoint runs on start |

docker-compose additionally reads `POSTGRES_PASSWORD` (or legacy `DB_PASSWORD`), `DB_USER`, `DB_NAME`, `DB_PORT`, `API_PORT`, `API_BIND`, `WEB_PORT` and `DOCKER_GID` (group owning `/var/run/docker.sock`). The local launchers (`start.sh`, `run.sh`) also accept `SEGMENTRA_DATABASE_URL` (custom database URL), and `start.sh` accepts `SEGMENTRA_RESET_DB=1` (wipes the Docker volumes first, data loss).

---

## Coexistence with Docker, Kubernetes and fail2ban

Segmentra only manages its own firewall objects and leaves rules created by other tools alone:

- **nftables:** everything lives in `table inet segmentra`, which is replaced atomically on each deploy. Other tables (Docker, Kubernetes, fail2ban) are not touched.
- **iptables / ip6tables:** rules live in the dedicated chains `SEGMENTRA-IN` and `SEGMENTRA-OUT`, applied with `iptables-restore --noflush` and reached from a single jump at the top of `INPUT` / `OUTPUT`. `DOCKER*`, `KUBE-*` and `f2b-*` chains, the `FORWARD` chain (except the one jump described below for gateways) and the built-in chain policies are not modified. The default inbound drop is the last rule of `SEGMENTRA-IN`. Allowed traffic leaves Segmentra's chain with `RETURN` (not `ACCEPT`), so rules after the jump still apply, such as fail2ban bans or your own `DROP`s. This matches nftables, where an accept in `table inet segmentra` doesn't override a drop in another table. If you set the `INPUT` policy to `DROP` yourself, you also need your own accept rules for traffic Segmentra allows.
- **Backend tools:** a host configured for iptables only needs `iptables-restore`, and one configured for nftables only needs `nft`. Having both installed is fine; modern distributions ship `iptables-nft` alongside `nft`.
- **Upgrading hosts deployed by older versions** (which replaced the whole iptables filter table): the first deploy removes the old Segmentra rules from `INPUT`/`OUTPUT` and resets the `INPUT`/`OUTPUT` policy to `ACCEPT` (only if Segmentra had set it to `DROP`). Rules that can't be positively identified as Segmentra's are left in place and reported as warnings in the deployment output. `FORWARD` is left at `DROP` when Docker or Kubernetes chains are present.

- **Forwarded traffic (IoT/OT gateways):** forwarding is filtered only on hosts whose policy has FORWARD rules or that protect IoT devices (assets assigned to the host on the OT/IoT page). With nftables this is a `chain forward` inside `table inet segmentra` (policy `accept`). With iptables it is a `SEGMENTRA-FWD` chain reached from a single jump at the top of `FORWARD`. Only traffic *to protected devices* is dropped unless a FORWARD rule allows it. Other forwarded traffic, including Docker's, passes as before. Allowed traffic leaves `SEGMENTRA-FWD` with `RETURN`, so `DOCKER-USER` and other `FORWARD` rules after the jump still apply. Deploying a version without forwarding, or removing the policy, deletes the forward chain and its jump. On other hosts nothing changes.

- **Reboot persistence** uses the distribution's own service and touches only Segmentra's part of its files: one `include` line plus `segmentra.nft` for nftables, or only the `SEGMENTRA-*` lines of the `*filter` section in `rules.v4`/`rules.v6` or `/etc/sysconfig/iptables`/`ip6tables`. Docker and Kubernetes chains are never written into these files (they recreate their own rules when they start). See [Persistence across reboots](#persistence-across-reboots).

Drift detection only fingerprints Segmentra's own table/chains (including `SEGMENTRA-FWD` and its jump), so rule changes made by Docker, Kubernetes or fail2ban are not reported as drift.

### Persistence across reboots

Deployments load the rules into the running kernel. To make them survive a reboot, Segmentra writes them into the files the **distribution's own firewall service** loads at boot. Segmentra stays agentless: no Segmentra service, timer, cron job or script runs at boot.

| | Debian, Ubuntu | RHEL, Rocky, AlmaLinux (Fedora, CentOS Stream) |
|---|---|---|
| **nftables** | `/etc/nftables.d/segmentra.nft` + one `include` line at the end of `/etc/nftables.conf`; `nftables.service` enabled | `/etc/nftables/segmentra.nft` + one `include` line at the end of `/etc/sysconfig/nftables.conf`; `nftables.service` enabled |
| **iptables** | Segmentra's chains and jumps merged into `/etc/iptables/rules.v4` / `rules.v6`; needs `iptables-persistent` (`netfilter-persistent.service` enabled) | merged into `/etc/sysconfig/iptables` / `ip6tables`; needs `iptables-services` (`iptables` / `ip6tables.service` enabled) |

- **What is written:** the nft file holds `table inet segmentra` behind `add table` + `delete table`, so it is safe to load at boot. The include line is added once, below a `# managed by Segmentra` marker; the rest of `nftables.conf` is not changed (if the file is missing it is created without `flush ruleset`). For iptables only Segmentra's lines are replaced; every other line of the saved file stays byte-identical. A missing rules file is created with only Segmentra's chains (and only if the package is installed). The previous version of each file is kept in `/var/backups/segmentra/persist/`.
- **Services are only enabled, never started or restarted** (a restart would reload the whole saved configuration and, with `flush ruleset`, remove Docker's rules at runtime). Debian/Ubuntu's stock `nftables.conf` starts with `flush ruleset`; at boot that runs before Docker or Kubernetes start, so it is harmless, and it is reported as a note.
- **Never done:** installing packages or disabling firewalld. What is missing is reported per host as a warning in the deployment ("Survives reboot" column: ✓ or ⚠ with the reason) and in the readiness check: `firewalld_active`, `iptables_persistent_missing`, `iptables_services_missing`, `no_nftables_service`, `unsupported_distro`.
- **Always the final, enforced state:** SSH Direct persists only after the reachability check passed and the lockout auto-revert was cancelled. The auto-revert, the rollback after a failed apply, Firewall Learning / policy-test restores and `scripts/restore-previous-policy.sh` re-sync the boot configuration to the restored state. A log-only Firewall Learning or policy-test policy is never persisted: a reboot during a session brings back the last enforced policy. Removing the policy (expiry REMOVE) removes Segmentra's include line, file and merged lines; the distribution service stays enabled. The Ansible executor runs the same steps.
- **Drift:** the compliance check also reports whether the boot configuration matches the running Segmentra rules (`persistence.state`: `in_sync`, `differs`, `missing`).

## Known Limitations

- **Restores on legacy iptables hosts.** Backups and restores (lockout auto-revert, failure rollback, firewall-learning / policy-test restores, `scripts/restore-previous-policy.sh`) only cover Segmentra's own `table inet segmentra` or `SEGMENTRA-IN` / `SEGMENTRA-OUT` chains, so other tools' rules are never replaced. The exception is a host still running a policy deployed by an older version that replaced the whole iptables filter table: restoring that backup replaces the `filter` table, so filter rules other tools added after the backup are lost. Redeploying once moves the host to the chain-based design.
- **SSH credential scope.** Credentials apply to all hosts, a tag, a VLAN or a single host, or are assigned to hosts explicitly; there is no per-environment scope or credential set with automatic fallback (if the chosen credential fails, Segmentra does not try the next one). Tag/VLAN/host scopes have no foreign key: deleting the tag, VLAN or host leaves the credential in place, matching nothing. Hosts imported by discovery before credential scoping kept their host-scoped copies named `… (discovered: <host>)`; they still work and can be deleted once the host is assigned a credential.
- **Drift baselines from older versions.** Hosts last deployed before drift fingerprints were scoped to Segmentra's own rules show compliance status `unknown` until they are redeployed once.
- **Policy expiry actions.** If a REMOVE or REVERT action fails, the error is recorded and a notification is sent, but it is not retried automatically. REVERT redeploys the previous version only to hosts that actually ran it; other hosts keep the expired policy and are listed in the notification.
- **sudo on target hosts.** Segmentra is agentless and runs every root step as `sudo sh -c '…'`, so the account needs **full sudo rights** (`ALL`): a sudoers rule limited to `nft` / `iptables` is not enough. sudo may ask for a password (the login password or a separate sudo password, set per credential), or be passwordless. Not supported: sudoers with `Defaults requiretty` for the account (readiness checks and deployments report it with a clear error; disable it for that account), privilege escalation other than sudo (`su`, `doas`, `pbrun`), and sudo configured to ask for the root or target user's password via `rootpw` / `targetpw` unless you enter that password as the separate sudo password.
- **SIEM forwarding.** Notification webhooks connect only to the exact address that was validated, so DNS rebinding doesn't work against them. Syslog/SIEM destinations configured by admins don't get the same connect-time address check.
- **Sessions after a password change.** Changing or resetting a password does not end existing sessions: JWTs stay valid until they expire (up to 12 hours). Deactivating the user blocks them immediately (roles are also re-read on every request), but reactivating the account within those 12 hours makes its unexpired tokens valid again.
- **Reboot persistence on RHEL-family hosts with firewalld.** firewalld conflicts with `nftables.service` and `iptables-services`, and Segmentra neither disables it nor translates policies into firewalld zones/policies. While firewalld is active or enabled, Segmentra's rules work at runtime (next to firewalld's own table, whose rejects still apply) but are gone after a reboot until the next deployment; deployments and the readiness check warn (`firewalld_active`). Disable firewalld and let Segmentra enable `nftables.service` (or install `iptables-services`) to persist them.
- **Reboot persistence on other distributions.** Only Debian, Ubuntu and RHEL-family distributions (detected from `/etc/os-release`) are supported. On Alpine, SUSE, Arch and others the rules are applied but not persisted (`unsupported_distro` warning). Missing packages (`nftables` with its systemd unit, `iptables-persistent`, `iptables-services`) are reported, never installed. If the saved iptables file of the distribution ends `INPUT` with its own catch-all `REJECT`/`DROP` (RHEL's stock `/etc/sysconfig/iptables` does), that rule also applies after a reboot to traffic Segmentra allows; this is reported as a note.
- **Docker socket.** The Ansible executor runs `docker exec` and therefore needs `/var/run/docker.sock`, which is root-equivalent on the Docker host. SSH-executor-only installations can remove the mount.
- **Ansible executor:**
  - It needs **Python on the target hosts** (readiness warns if it's missing).
  - It deploys all hosts in one run: canary and progressive modes have no effect.
  - It has no lockout auto-revert. A policy that cuts off SSH is detected and reported as FAILED ("possible lockout"), but not undone automatically.
  - Use SSH Direct for these protections.
- **`scripts/restore-previous-policy.sh`** needs SSH key or agent login and passwordless sudo on the hosts (it reports clearly when sudo asks for a password).

---

## Not Yet Tested

### What has been tested

Everything below was exercised against Docker containers. The core workflow went through the web UI; the rest went through the same REST calls the UI makes.

- **Core workflow (web UI), on Alpine containers with iptables and nftables:** inventory, policy sets and versions, approvals, deployments, drift, expiry REMOVE and REVERT, simulator, topology, templates, OT/IoT, security audit, SIEM syslog, webhooks and role-based access. The automated Docker SSH integration test also passes.
- **Real distributions:** Debian 12, Ubuntu 24.04 and Rocky Linux 9.3, each running its stock packages and PAM-based sudo with a password:
  - discovery, readiness, nftables and iptables deployments, drift and expiry REMOVE;
  - **reboot persistence** through each OS's own service. Restarting a systemd container wipes the firewall like a reboot; the rules came back, saved admin rules stayed byte-identical, and removal cleaned up. Rocky with firewalld running is correctly reported as not persisted.
- **Credentials:**
  - private keys (ed25519, and RSA in PEM format) with and without a passphrase, and password login;
  - sudo with no password, with the login password, or with a separate password;
  - a wrong sudo password and `requiretty` (both give a clear error);
  - credential scoping: global, tag, VLAN, host, not assigned, and explicit host assignment, including the Admin and Inventory UI.
- **Executors:**
  - SSH Direct, including lockout auto-revert through both `nohup` and `systemd-run` (Debian with systemd);
  - Ansible end to end through the API with all three credential types, including rescue rollback, FORWARD/IPv6 rules, per-host results from the play recap, lockout detection and an unresponsive host.
- **Rollout modes:** canary and progressive with 6–8 hosts, plus pause, resume and stop.
- **Approvals:** high-risk deployment approval, including the creator not being allowed to approve.
- **Firewall Learning and Policy Impact Analysis with real captured traffic** on Debian 12 (rsyslog, kernel logging enabled for the test): flows, recommendations and impact-analysis coverage.
- **IoT gateways:**
  - FORWARD rules on nftables and iptables, including IPv6 devices and rules;
  - two gateways protecting one device;
  - expiry REVERT on a gateway, and unassigning a device;
  - the Ansible executor with FORWARD rules.
- **Discovery:**
  - a /24, and a /20 (4,094 addresses in about 100 s);
  - hosts that drop or reject SSH probes are counted as closed without hanging;
  - scheduled runs, and credentials that need a sudo password.
- **Auto-tagging and template auto-apply:**
  - all condition fields, including `environment`, with AND/OR;
  - disable, retarget and delete, and priority between rules;
  - the 5-minute job adding and removing tags;
  - auto-apply creating a DRAFT policy.
- **LDAP** against OpenLDAP:
  - group-to-role mapping, both via memberOf and via a group-filter lookup;
  - injection attempts;
  - disabled LDAP, and deactivated users.
- **Notifications:**
  - webhook delivery, and Slack against a mock webhook;
  - event subscriptions;
  - SSRF checks.
- **Threat intelligence:** AbuseIPDB against a mock of its API (error handling, auto-block drafts, deduplication).
- **SIEM forwarding:** every audit event forwarded exactly once (including a second API replica and a reconnect), with no secrets in messages. Integration and notification secrets are encrypted at rest; a database dump showed none of them.
- **Kubernetes:** generated NetworkPolicy manifests were applied to k3s v1.30 and enforced.
- **Other:** `scripts/restore-previous-policy.sh` (`--latest` / `--timestamp`); password change and reset; and the PowerShell scripts parse under PowerShell 7 and as Windows PowerShell 5.1 would read them.

### Not yet tested or not implemented

- **Email notifications are not implemented.** There is no SMTP sending; email channels report FAILED.
- **Kubernetes workload sync is not implemented.** The sync endpoint returns `501`, so workload-to-tag mapping can't be used. Generated manifests use `podSelector: {}` (all pods in the namespace).
- **Microsoft Active Directory itself, and LDAPS with a real certificate.** Only OpenLDAP was tested.
- **The real AbuseIPDB service**, as opposed to the mock, and real Slack workspaces.
- **Hosts that log only to journald (no rsyslog).** Firewall Learning reads the rsyslog file, so such hosts capture no flows. FORWARD traffic on gateways is not analyzed by Learning or Policy Impact Analysis, by design.
- **RHEL with SELinux enforcing and firewalld running**, and SUSE, Arch, older releases and Alpine. Persistence reports `unsupported_distro` on the last group.
- **ECDSA and PKCS#8-encrypted keys** on a live host (they pass validation), and OpenSSH clients older than 8.4.
- **The Windows scripts were not run on Windows.** `start.bat` was only reviewed.
- **Real OT protocols** beyond a TCP test listener on gateways.
- **A full deployment through a browser with the Ansible executor.** Ansible was tested through the API.

See also [Known Limitations](#known-limitations) and the [OT/IoT guide](docs/iot.md#8-limitations-and-what-is-not-tested).

---

## Future Work

### Features not implemented yet

- **Email notifications.** Email channels can be configured but there is no SMTP sending yet; they report FAILED with "Email delivery is not implemented yet". Plan: add an SMTP client (e.g. nodemailer) with TLS, authentication stored encrypted like other secrets, and a test-send button.
- **Kubernetes workload sync and direct apply.** The sync endpoint returns `501 not_implemented`; Segmentra does not connect to the Kubernetes API. Plan:
  - read namespaces, workloads and labels from the cluster;
  - map labels to tags;
  - generate NetworkPolicies that select the right pods (today they use `podSelector: {}`, i.e. all pods in the namespace);
  - optionally apply them directly instead of `kubectl apply`.
- **UI for API-only features.** These work through the API but have no screens yet: policy recommendations, enforcement points (network device ACLs), IoT baselines and observed flows, host interfaces, the per-host compiled-policy preview (`render`) and Kubernetes workload-to-tag mapping.
- **More integrations.** SOAR and vulnerability-database integrations can be configured but don't do anything yet.

### Testing still to do

- **Microsoft Active Directory** (only OpenLDAP was tested), and LDAPS with a real certificate.
- **The real AbuseIPDB service and real Slack workspaces.** Both were tested against mocks.
- **Hosts that log only to journald** (no rsyslog) for Firewall Learning and Policy Impact Analysis.
- **RHEL with SELinux enforcing and firewalld running.** Today, persistence is reported as not possible while firewalld manages the firewall.
- **ECDSA and PKCS#8-encrypted SSH keys** on live hosts, and OpenSSH clients older than 8.4.
- **Running the Windows scripts on Windows** (`start.bat`, `run.ps1`, `install.ps1`, `scripts/check-db-status.ps1`). They were only parsed and reviewed.

---

## Documentation

| Document | Description |
|----------|-------------|
| [Installation Guide](docs/installation.md) | Dev and production setup |
| [Architecture](docs/Architecture.md) | API endpoints, database schema, RBAC matrix |
| [User Guide](docs/guide.md) | Step-by-step usage for all features |
| [Security: Credentials, Secrets and Hardening](docs/security.md) | How credentials are encrypted, the encryption key, who can access them, and how to harden a production install |
| [OT/IoT Guide](docs/iot.md) | IoT microsegmentation with gateway model |
| [Gateway Setup](docs/gateway-setup-guide.md) | Linux gateway firewall configuration |
| [Kubernetes Guide](docs/kubernetes.md) | K8s NetworkPolicy management |
| [Ansible Playbook](docs/playbook-ansible.md) | Deployment playbook documentation |
| [Original Specification](docs/segmentra_fleet_microsegmentation_firewall_manager_full_specification.md) | The original product specification (historical; the implementation differs in places) |

---

## License

See [LICENSE.md](LICENSE.md) for details.
