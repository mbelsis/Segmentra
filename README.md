<div align="center">
  <img src="logo/segmentra.png" alt="Segmentra" style="max-width: 300px; height: auto;" />
</div>

# Segmentra

Segmentra is an on‑prem, web-based **fleet firewall & microsegmentation management** tool for Linux servers. It lets security/infra teams define **intent-based access policies** (allow/deny) and deploy them safely at scale to **nftables/iptables**, with versioning, approvals, deployment bundles, and an audit trail.

---

## Features & Capabilities

### 🔐 Authentication & Authorization
- **LDAP/Active Directory Integration**: Seamless authentication with your existing directory services
- **Role-Based Access Control (RBAC)**: Four roles (Viewer, Operator, Approver, Admin) with granular permissions
- **AD Group Mapping**: Automatically assign roles based on Active Directory group membership

### 📦 Policy Management
- **Policy Sets**: Organize firewall policies by scope (Tags, VLANs, or Host Lists)
- **Version Control**: Track all policy changes with versioning and change summaries
- **Approval Workflow**: Multi-stage approval process with separation of duties
- **Policy Impact Analysis**: Compare policy versions before approval to see what will change
  - View semantic diff: new allows, removed allows, new denies, removed denies
  - Per-host impact analysis for sample hosts
  - Available in the Approvals screen for confident decision-making
- **Rule Management**: Define firewall rules with support for:
  - Multiple protocols (TCP, UDP, ICMP, any)
  - Port ranges and specific ports
  - Source types (CIDR, Tags, VLANs, Hosts)
  - Interface scoping (all interfaces, by name, or by role)
  - Logging modes
  - Directional rules (IN, OUT, BOTH)

### 🚀 Deployment Management
- **Multiple Deployment Modes** (v1: modes are accepted and stored, but all selected hosts are processed immediately):
  - **Canary**: Deploy to a small subset first (mode stored, but currently processes all hosts immediately)
  - **Progressive**: Deploy in batches (mode stored, but currently processes all hosts immediately)
  - **Full**: Deploy to all targets at once
  - **Note**: Canary and Progressive modes are currently experimental. The system accepts and stores these modes, but all selected hosts are processed in a single batch. Full orchestration (host-by-host canary testing and progressive batching) is planned for future versions.
- **Scheduled Deployments**: Schedule deployments for future execution (e.g., maintenance windows)
- **Deployment Executors**:
  - **Ansible** (Recommended): Better error handling, automatic rollback, parallel execution
  - **SSH Direct**: Lightweight, no Ansible dependency
- **Real-time Progress Tracking**: Monitor deployment status per host
- **Automatic Rollback**: Failed deployments automatically rollback to previous state
- **Deployment Timeout**: Hosts timeout after 10 minutes if unresponsive
- **Safety Guardrails**: Pre-deployment checks ensure SSH access from management VLAN is preserved
  - **FULL mode**: Blocks deployments that would lock out administrators
  - **CANARY/PROGRESSIVE**: Warns about potential lockouts but allows deployment

### 📊 Dashboard & Monitoring
- **Real-time Dashboard**: Visual overview of deployment status and metrics
- **Deployment Activity Charts**: Track deployment trends over time
- **Status Breakdown**: Visual representation of deployment outcomes
- **Top Deployers**: See who's most active in your organization

<div align="center">
  <img src="docs/images/dashboard.png" alt="Dashboard" style="max-width: 100%; height: auto;" />
</div>

### 🏷️ Inventory Management
- **Host Management**: Add and manage Linux servers with management IPs
- **Tagging System**: Organize hosts with custom tags
- **VLAN Support**: Group hosts by VLAN membership
- **Interface Configuration**: Define network interfaces with roles (data, management, etc.)
- **Firewall Backend Selection**: Choose nftables or iptables per host
- **Bulk Operations**: Import hosts via CSV, bulk assign tags/VLANs
- **Host Readiness Check**: Verify host capabilities before deployment
  - Checks for nftables/iptables availability and versions
  - Verifies passwordless sudo access for firewall commands
  - Confirms kernel/module support for nftables
  - Auto-detects and updates firewall backend if set to "auto"
- **Compliance Monitoring**: Track configuration drift detection
  - Compare current firewall rules on hosts vs. last deployed policy
  - Identify hosts with manual changes or failed deployments
  - Bulk compliance checking for multiple hosts
- **Policy Visualization**: Visual diagram of applied firewall policies
  - Interactive SVG diagram showing host in center with connected sources
  - Color-coded arrows: green for allowed connections, red for denied connections
  - Shows port numbers, protocols, and source types (CIDR, Tags, VLANs, Hosts)
  - Toggle between IN/OUT/BOTH directions
  - Option to show/hide denied connections
  - Accessible from Inventory page for each host

### 🔍 Audit & Compliance
- **Comprehensive Audit Trail**: Track all actions with timestamps and user attribution
- **Deployment Audit Records**: Detailed logs of who deployed what, when, and where
- **Filterable Audit Log**: Search by actor, action, entity type, and date range
- **Metadata Storage**: Rich metadata for deployment events including:
  - Policy information
  - Deployment mode and targets
  - Results (success, failed, partial success)
  - Host-level outcomes
- **Drift Detection** (No Agent Required): 
  - Automatically detect configuration drift by comparing current firewall rules to last deployed policy hash
  - SSH-based rule reading (`nft list ruleset` / `iptables-save`)
  - Status indicators: Compliant, Drifted, Unknown, or Error
  - Per-host and bulk compliance checking
  - Visual compliance status in inventory view

<div align="center">
  <img src="docs/images/audit-log.png" alt="Audit Log" style="max-width: 100%; height: auto;" />
</div>

### 🛠️ Troubleshooting
Segmentra provides comprehensive troubleshooting tools to help diagnose and resolve firewall policy issues. The **Communication Simulation** feature allows you to test whether communication between two IP addresses would be blocked by deployed firewall policies. Simply enter the source IP, destination IP, optional ports, and protocol, and the system will analyze all deployed policies on both hosts to determine if the traffic would be allowed or blocked, showing you exactly which rules match and their actions.

Additional troubleshooting capabilities include:
- **Policy Troubleshooting**: Query which policies apply to specific IPs
- **Host Policy View**: See all policies deployed to a specific host
- **Policy Version Hosts**: View which hosts have a specific policy version deployed
- **Execution Logs**: Access stdout/stderr from deployment executions
- **Policy Impact Analysis**: Compare policy versions before deployment
  - See semantic diff between current and candidate policy versions
  - Identify new allows, removed allows, new denies, and removed denies
  - Per-host impact analysis for sample hosts
  - Available in the Approvals screen for policy reviewers
- **Policy Visualization**: Visual diagram of firewall policies per host
  - Interactive network diagram showing host in center with all connected sources
  - Color-coded connection arrows (green=allowed, red=denied)
  - Displays port numbers, protocols, and source information
  - Filter by connection direction (IN/OUT/BOTH)
  - Toggle visibility of denied connections
  - Accessible via "View Visualization" button in Inventory → Hosts

<div align="center">
  <img src="docs/images/troubleshooting.png" alt="Troubleshooting" style="max-width: 100%; height: auto;" />
</div>






---

## Installation & Quick Start

### Prerequisites
- **Node.js 20+**
- **Docker Desktop** (for PostgreSQL and optional Ansible runner)
- **PostgreSQL** (or use the docker compose DB)

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

**Windows (cmd.exe):**
```batch
set SEGMENTRA_RESET_DB=1
start.bat dev
```

**Windows (PowerShell):**
```powershell
$env:SEGMENTRA_RESET_DB="1"
start.bat dev
```

### Default Login Credentials

After starting the application, use these credentials to login:

- **Username**: `admin`
- **Password**: `admin`

⚠️ **Important**: Change the default password after first login! You can change it in the UI or via API endpoint `POST /api/auth/change-password`.

### Manual Setup (Alternative)

#### 1) Install dependencies

```bash
npm install
```

#### 2) Start Postgres (recommended)

```bash
docker compose up -d segmentra-db
```

#### 3) Run migrations + seed roles

Set `DATABASE_URL` (example for the compose DB):

**Windows (cmd.exe):**
```batch
set DATABASE_URL=postgres://segmentra:segmentra@127.0.0.1:15432/segmentra
npm run db:migrate
npm run db:seed
```

**Windows (PowerShell):**
```powershell
$env:DATABASE_URL="postgres://segmentra:segmentra@127.0.0.1:15432/segmentra"
npm run db:migrate
npm run db:seed
```

**Note**: On Windows, use `set` in cmd.exe or `$env:` in PowerShell. The examples above show both syntaxes.

**macOS/Linux:**
```bash
export DATABASE_URL=postgres://segmentra:segmentra@127.0.0.1:15432/segmentra
npm run db:migrate
npm run db:seed
```

The seed script automatically creates a default admin user:
- **Username**: `admin`
- **Password**: `admin`

#### 4) Start the API

Set required env vars (minimum: `DATABASE_URL`, `JWT_SECRET`):

**Windows (cmd.exe):**
```batch
set JWT_SECRET=change-me-to-a-long-random-string
npm run dev -w apps/api
```

**Windows (PowerShell):**
```powershell
$env:JWT_SECRET="change-me-to-a-long-random-string"
npm run dev -w apps/api
```

**macOS/Linux:**
```bash
export JWT_SECRET=change-me-to-a-long-random-string
npm run dev -w apps/api
```

API listens on `http://localhost:8080`.

#### 5) Start the UI

```bash
cd apps/web
npm run dev
```

UI listens on `http://localhost:5173`.

---

## How to Use (Quick Guide)

### 1) Login with default admin account

**Default credentials (created automatically on first run):**
- **Username**: `admin`
- **Password**: `admin`

⚠️ **Important**: Change the default password after first login!

**Alternative: LDAP Authentication**

If you have LDAP configured and AD group mappings, you can login via `/api/auth/login` with your LDAP credentials. The system will:
1. First check for local users (with password_hash)
2. If not found, fall back to LDAP authentication

### 2) Configure deployment settings

- In the UI: **Admin → Deployment Executor** — Choose between Ansible (recommended) or SSH Direct
- In the UI: **Admin → SSH Credentials** — Create a **GLOBAL** SSH credential
  - **Important**: Use a **sudo-capable account** (not root). Most modern Linux systems disable root SSH login.
  - The account must have passwordless sudo access to firewall commands (`nft`, `iptables`, `iptables-restore`)
  - The system automatically uses `sudo` for all privileged operations

<div align="center">
  <img src="docs/images/administration.png" alt="Administration" style="max-width: 100%; height: auto;" />
</div>

### 3) Add inventory

- **Tags & VLANs**: Create tags and VLANs first (Inventory → Tags/VLANs tabs)
- **Hosts**: Add hosts with hostname, management IP, assign VLAN and tags
  - **SSH Port**: Configure the SSH port for deployments (default: 22). Use custom ports (e.g., 2022, 2222) for hosts that don't use the standard SSH port.
  - **Firewall Backend**: Choose the firewall backend for each host (`auto`, `nftables`, or `iptables`)
  - **Note**: Disabled hosts (`enabled=false`) are automatically skipped from all policy deployments
- **Interfaces**: Add interfaces per host (name + role such as `data`, `management`, etc.)

<div align="center">
  <img src="docs/images/inventory.png" alt="Inventory Management" style="max-width: 100%; height: auto;" />

### 4) Create & approve a policy version

- Create a **Policy Set** (e.g., "DMZ Servers")

<div align="center">
  <img src="docs/images/policy-sets.png" alt="Policy Sets" style="max-width: 100%; height: auto;" />
</div>

- Create a **Policy Version** (DRAFT), add rules, then **Submit for approval**
- Approver/Admin approves in **Approvals**

<div align="center">
  <img src="docs/images/policy-version.png" alt="Policy Version" style="max-width: 100%; height: auto;" />
</div>

- Add Rules to **Policy Version**

<div align="center">
  <img src="docs/images/policy-rules.png" alt="Policy Version" style="max-width: 100%; height: auto;" />
</div>

### 5) Deploy

- Create a Deployment targeting hosts/tags/vlans (policy version must be APPROVED)
- Start it (creates bundle + runs selected executor: Ansible or SSH Direct)
- Review results in **Deployments** and logs via execution logs endpoint

<div align="center">
  <img src="docs/images/deployments.png" alt="Deployments" style="max-width: 100%; height: auto;" />
</div>

<div align="center">
  <img src="docs/images/deployment-details.png" alt="Deployment Details" style="max-width: 100%; height: auto;" />
</div>

---

## Recent Enhancements

Segmentra now includes several advanced features for production-ready firewall management:

### ✅ Drift Detection & Compliance (No Agent Required)
- **Agentless Compliance Checking**: SSH-based drift detection compares current firewall rules to last deployed policy
- **Visual Status Indicators**: See compliance status (Compliant/Drifted/Unknown) directly in the inventory
- **Bulk Operations**: Check compliance for multiple hosts simultaneously
- **Automatic Detection**: Identifies manual changes, failed deployments, or configuration drift

### ✅ Safety Guardrails
- **Pre-Deployment Validation**: Automatically checks that SSH access from management VLAN is preserved
- **Mode-Specific Protection**: FULL mode blocks dangerous deployments; CANARY/PROGRESSIVE modes warn
- **Visual Feedback**: Clear warnings and errors in the deployment creation UI
- **Prevents Lockouts**: Ensures administrators can always access hosts via SSH

### ✅ Policy Impact Analysis
- **Semantic Diff**: Compare policy versions to see exactly what will change
- **Rule Categorization**: Identify new allows, removed allows, new denies, and removed denies
- **Per-Host Analysis**: Understand impact for specific hosts before deployment
- **Approval Confidence**: Make informed decisions when approving policy versions

### ✅ Host Readiness Verification
- **Pre-Flight Checks**: Verify hosts are ready before deployment
- **Capability Detection**: Checks for nftables/iptables, sudo access, kernel support
- **Auto-Configuration**: Automatically updates firewall backend if set to "auto"
- **Detailed Results**: See exactly what's missing or misconfigured

### ✅ Scheduled Deployments
- **Future Execution**: Schedule deployments for maintenance windows
- **Simple Scheduling**: "Tonight at 02:00" style datetime scheduling
- **Automatic Processing**: Background job automatically starts scheduled deployments
- **No Complex Logic**: Simple and reliable deferred execution

---

## Architecture Overview

This repository is a **TypeScript monorepo**:
- **API**: Express + PostgreSQL (`apps/api`)
- **UI**: React (Vite) (`apps/web`)
- **Compiler**: policy → per-host firewall rules (`packages/compiler`)
- **Executor**: Ansible CLI runner wrapper + SSH direct executor (`packages/executor`)
- **DB**: migrations + seed scripts (`packages/db`)

For detailed technical documentation, see [Architecture.md](Architecture.md).

---

## Configuration

### Environment Variables

The API reads env vars in `apps/api/src/lib/env.ts`:
- `PORT` (default `8080`)
- `DATABASE_URL` (**required**)
- `JWT_SECRET` (**required**, min 16 chars)
- `SEGMENTRA_KEK_B64` (optional; base64 of 32-byte key for AES-256-GCM secret encryption)
- `SEGMENTRA_BOOTSTRAP_TOKEN` (optional; enables `POST /api/admin/bootstrap`)
- `BUNDLES_DIR` (default `./data/bundles`) — where deployment bundles/logs are written
- `ANSIBLE_RUNNER_CONTAINER` (default `segmentra-ansible-runner`)

---

## License

See [LICENSE.md](LICENSE.md) for details.

---

## Support

For technical documentation, troubleshooting, and API reference, see [Architecture.md](Architecture.md).
