<div align="center">
  <img src="logo/segmentra.png" alt="Segmentra" style="max-width: 300px; height: auto;" />
</div>

# Segmentra

***Segmentra*** is an on-prem, web-based **fleet firewall & microsegmentation management** tool for Linux servers. It lets security and infrastructure teams centrally define **host firewall policies** (allow/deny), and deploy them at scale to nftables/iptables, via SSH or Ansible Playbook. It extends enforcement to **Kubernetes containers** and **OT/IoT devices** through gateway firewalls.

The platform enables: 
-**Intentory creation and Auto tagging**,
-**Policy Versioning**, 
-**Policy Impact Analysis**
-**Policy Troubleshooting**,
-**Policy Canary Testing**, 
-**Policy Templates and auto assigment**
-**Duties Segrgation**, 
-**Approvals tracking**, 
-**audit trails**, 
-**compliance monitoring**,
-**Topology building**, 
-**Default Access Rules for each Policy**,


**Future plans** include integrations with Syslog, Threat Intelligence feeds, SOAR, and Policy Expiration and auto Rollback 
 

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
- **Separation of Duties** — policy approvers must differ from creators; high-risk policies require a different approver even for admins

### Inventory Management
- **Host Management** — add Linux servers with management IPs, SSH ports, firewall backend selection (nftables/iptables/auto)
- **Tags & VLANs** — organize hosts by custom tags and VLAN membership; VLANs also serve as OT/IoT zones
- **Auto-Tagging Rule Engine** — define criteria (hostname regex, CIDR ranges, OS family, VLAN, existing tags) with AND/OR logic to automatically classify hosts; evaluates every 5 minutes and on-demand
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
- **Version Control** — every change creates an immutable version (DRAFT → APPROVED → DEPLOYED → ARCHIVED)
- **Policy Templates** — reusable blueprints (e.g., "Web Server") with one-click instantiation; optional auto-apply when hosts gain a matching tag
- **Visual Topology Design** — draw network flows between groups, auto-discover from existing infrastructure, and generate policies automatically
- **Policy Recommendations** — after firewall learning, auto-generate rules from observed traffic with confidence scoring and IP-to-tag resolution
- **Policy Impact Analysis** — semantic diff showing new/removed allows and denies per host before approval
- **High-Risk Detection** — audit policies to flag broad rules, wide scopes, and sensitive port exposure
- **Policy Expiry** — optional time-limited deployments with 24-hour warnings and configurable expiry actions (notify, remove, revert)
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
- **Encrypted Secret Storage** — SSH keys and LDAP passwords encrypted with AES-256-GCM
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
```

### Running

```bash
./run.sh --start --development    # Start dev (API + UI + DB)
./run.sh --stop --development     # Stop dev
./run.sh --start --production     # Start production (all Docker containers)
./run.sh --stop --production      # Stop production
```

### Default Login

- **Username**: `admin`
- **Password**: `admin123`

For detailed installation instructions, see [installation.md](docs/installation.md).

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

Production runs 4 Docker containers: `segmentra-web` (nginx), `segmentra-app` (API), `segmentra-db` (PostgreSQL), `segmentra-ansible-runner` (Ansible executor).

For detailed technical documentation, see [Architecture.md](docs/Architecture.md).

---

## Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | Yes | — | PostgreSQL connection string |
| `JWT_SECRET` | Yes | — | JWT signing secret (min 16 chars) |
| `PORT` | No | `8080` | API server port |
| `SEGMENTRA_KEK_B64` | No | — | Base64 key for AES-256-GCM encryption |
| `BUNDLES_DIR` | No | `./data/bundles` | Deployment bundle directory |
| `ANSIBLE_RUNNER_CONTAINER` | No | `segmentra-ansible-runner` | Ansible Docker container name |

---

## Documentation

| Document | Description |
|----------|-------------|
| [Installation Guide](docs/installation.md) | Dev and production setup |
| [Architecture](docs/Architecture.md) | API endpoints, database schema, RBAC matrix |
| [User Guide](docs/guide.md) | Step-by-step usage for all features |
| [OT/IoT Guide](docs/iot.md) | IoT microsegmentation with gateway model |
| [Gateway Setup](docs/gateway-setup-guide.md) | Linux gateway firewall configuration |
| [Kubernetes Guide](docs/kubernetes.md) | K8s NetworkPolicy management |
| [Ansible Playbook](docs/playbook-ansible.md) | Deployment playbook documentation |
| [Full Specification](docs/segmentra_fleet_microsegmentation_firewall_manager_full_specification.md) | Complete technical specification |

---

## License

See [LICENSE.md](LICENSE.md) for details.
