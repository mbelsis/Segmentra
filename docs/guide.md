# Segmentra User Guide

This guide walks through every step of using Segmentra — from initial setup to deploying firewall policies across your Linux fleet. It covers both deployment executors (SSH Direct and Ansible), firewall learning, policy testing, and the newer capabilities like auto-tagging, templates, integrations, Kubernetes, and OT/IoT.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Initial Setup](#2-initial-setup)
3. [Building Your Inventory](#3-building-your-inventory)
4. [Auto-Tagging with Rules](#4-auto-tagging-with-rules)
5. [Creating Firewall Policies](#5-creating-firewall-policies)
6. [Using Policy Templates](#6-using-policy-templates)
7. [Visual Topology Design](#7-visual-topology-design)
8. [Approval Workflow](#8-approval-workflow)
9. [Deploying Policies](#9-deploying-policies)
10. [How SSH Direct Deployment Works](#10-how-ssh-direct-deployment-works)
11. [How Ansible Deployment Works](#11-how-ansible-deployment-works)
12. [Firewall Learning (Traffic Discovery)](#12-firewall-learning-traffic-discovery)
13. [Policy Auto-Recommendations](#13-policy-auto-recommendations)
14. [On-Device Policy Testing](#14-on-device-policy-testing)
15. [Troubleshooting & Simulation](#15-troubleshooting--simulation)
16. [Compliance & Drift Detection](#16-compliance--drift-detection)
17. [Integrations](#17-integrations)
18. [Kubernetes Microsegmentation](#18-kubernetes-microsegmentation)
19. [OT/IoT Microsegmentation](#19-otiot-microsegmentation)
20. [Policy Expiry](#20-policy-expiry-time-limited-deployments)
21. [Notifications](#21-notifications)
22. [Security Posture Audit](#22-security-posture-audit)
23. [Background Jobs](#23-background-jobs)

---

## 1. Prerequisites

### On the Segmentra Server

- **Node.js 20+**
- **Docker Desktop** (for PostgreSQL; also for Ansible executor if used)
- **PostgreSQL** (via Docker Compose or external)
- `ssh` and `scp` commands available (included in the Docker container; needed for SSH Direct executor)

### On Target Linux Hosts

- **SSH access** with a dedicated user (not root, since most distros disable root SSH), using a private key (optionally passphrase-protected) or a password. No agent is installed on the host.
- **Full sudo rights**, with or without a password. Segmentra runs its scripts as `sudo sh -c '…'`, so a sudo rule limited to firewall commands is not enough:
  ```bash
  # /etc/sudoers.d/segmentra — sudo asks for a password (set "Privilege escalation" on the credential)
  segmentra_user ALL=(ALL) ALL
  # or passwordless (service account; choose "sudo without password")
  segmentra_user ALL=(ALL) NOPASSWD: ALL
  ```
  Do not enable `Defaults requiretty` for this account. Restrict where it can log in from (see [security.md](security.md#checklist)).
- One supported backend: **nftables**, **iptables**, **firewalld**, or **UFW**. `auto` prefers an active firewalld/UFW manager before raw tools.
- Native firewalld/UFW require **Python 3**, **systemd**, and an already active manager. Firewalld requires the policy API and nftables backend; UFW requires `IPV6=yes` and both IPv4/IPv6 save/restore tools. See [native firewall managers](firewall-managers.md).
- **rsyslog** installed for firewall learning/audit on raw nftables/iptables. Native-manager learning/log-only mode is not yet supported.
- **For rules that survive a reboot** (Segmentra never installs packages or disables firewalld; see [Persistence across reboots](../README.md#persistence-across-reboots)):

  | Distribution | nftables backend | iptables backend |
  |---|---|---|
  | Debian, Ubuntu | `nftables` package (`nftables.service`; Segmentra enables it) | `iptables-persistent` package (`netfilter-persistent.service`) |
  | RHEL, Rocky, AlmaLinux (Fedora, CentOS Stream) | `nftables` package (`nftables.service`) and **firewalld disabled** | `iptables-services` package (`iptables` / `ip6tables.service`) and **firewalld disabled** |

  This table covers raw nftables/iptables persistence. With firewalld active, use the native `firewalld` backend instead of a conflicting raw boot service. Native firewalld writes permanent policy XML; UFW writes marked IPv4/IPv6 before-rule blocks. Both verify boot-service enablement and saved/live state, and roll back on persistence failure. Raw persistence on other distributions is unsupported; native manager support depends on its prerequisites, not this distribution table.

---

## 2. Initial Setup

### Step 1: Start Segmentra

**Linux/macOS:**
```bash
./install.sh --development
./run.sh --start --development
```

**Windows (PowerShell):**
```powershell
.\install.ps1 --development
.\run.ps1 -start -development
```

This starts PostgreSQL (port 15432), runs migrations, seeds roles, creates the default admin user, and starts the API (port 8080) and UI (port 5173).

### Step 2: Login

Open `http://localhost:5173` and login with:
- **Username:** `admin`
- **Password:** `admin123` (development default; if `SEGMENTRA_ADMIN_PASSWORD` was set when the database was first seeded, use that instead. Production installs use the `SEGMENTRA_ADMIN_PASSWORD` from `.env`.)

Change the password immediately after first login.

### Step 3: Configure the Deployment Executor

Go to **Admin** in the sidebar.

Under **Deployment Executor**, choose:
- **Ansible** (recommended) — requires the `segmentra-ansible-runner` Docker container
- **SSH Direct** — lightweight, no Ansible dependency

The hardened Docker override (`docker-compose.hardened.yml`) does not start the Ansible runner, so choose **SSH Direct** there (see [installation.md](installation.md)).

### Step 4: Add SSH Credentials

In **Admin → SSH Credentials**, create a credential:
- **Name:** e.g., "Global SSH Key"
- **Username:** The sudo-capable user on target hosts (e.g., `segmentra`)
- **Private Key:** Paste the private key (OpenSSH or PEM format), plus its **passphrase** if it has one (checked when saving)
- **Privilege escalation:** *sudo without password*, *sudo with the login password* (password credentials only) or *sudo with a separate password* (enter the sudo password)
- **Applies to:** which hosts use the credential automatically:
  - *All hosts (global)*: the default for every host without a more specific credential (the newest global one wins);
  - *Hosts with tag* / *Hosts in VLAN* / *A specific host*: pick the tag, VLAN or host;
  - *Not assigned (manual use)*: never chosen automatically; use it in a discovery profile or assign it to hosts explicitly.
- **Priority** (optional): breaks ties when several credentials match at the same level, e.g. a host with two tags that each have a credential. Higher wins.

For each host Segmentra uses: the credential assigned to the host (Inventory → edit host → *SSH credential*, admins only) → a credential for that host → for one of its tags → for its VLAN → the global one. The **SSH credential** column in Inventory → Hosts shows the result for every host, e.g. `demo-boxes (global)` or `web-creds (tag web)`. Use **Edit** in the credential list to change a credential's name, scope or priority (and, for password credentials, the password) without re-entering the key; **Delete** is refused while a discovery profile uses the credential or hosts are assigned to it.

Example: keep one global credential for most servers, and add a credential for the tag `web` for the web servers that use a different account. Only hosts tagged `web` switch to it.

Keys, passphrases and passwords are encrypted at rest using AES-256-GCM. The sudo password is sent to `sudo -S` on standard input, never on a command line (see [security.md](security.md#how-secrets-are-used-when-connecting-to-hosts)).

### Step 5: (Optional) Configure Management VLAN

In **Admin → Management VLAN (Baseline SSH Access)**, select the VLAN used for SSH management access. This enables:
- Automatic SSH baseline rules in compiled policies (SSH from the management VLAN subnet is always allowed)
- Safety guardrails that prevent deployments from locking out administrators

Without a management VLAN, SSH is allowed from any source so hosts cannot be locked out.

---

## 3. Building Your Inventory

### Step 1: Create Tags

Go to **Inventory → Tags** tab and create tags that describe your server roles:
- `web-server`, `db-server`, `app-server`, `monitoring`, `dmz`, etc.

Tags are the primary way to group hosts for policy targeting. A tag (or VLAN) cannot be deleted while policy or template rules reference it (`409`).

### Step 2: Create VLANs

Go to **Inventory → VLANs** tab and add your network VLANs:
- **VLAN Tag:** The 802.1Q tag number (e.g., 100)
- **Name:** Descriptive name (e.g., "Production Data")
- **Subnet:** CIDR notation (e.g., `10.0.100.0/24`) — used for management baseline and CIDR matching

### Step 3: Add Hosts

Go to **Inventory → Hosts** tab:

**Individual hosts:**
- Click **+ Add Host**
- Enter hostname, management IP, SSH port (default 22)
- Select firewall backend (`auto`, `nftables`, `iptables`, `firewalld`, or `ufw`)
- **Docker** section: mark the host as a Docker Swarm node (swarm name, manager/worker, address) so the cluster ports between the nodes are always allowed, and optionally apply your inbound rules to Docker-published ports (they never reach the INPUT chain, so ordinary rules do not restrict them). iptables and nftables only; see [docker-swarm.md](docker-swarm.md)
- Assign VLAN and tags
- *SSH credential* (admins only): leave *Automatic (by credential scope)* or assign a credential explicitly

**Bulk import via CSV:**
- Click **Bulk Import** and upload a CSV file with the header `hostname,mgmt_ip,ssh_port,vlan,tags,firewall_backend,enabled` (`vlan` = VLAN name or tag number, `tags` = comma-separated tag names; only `hostname` is required)
- `firewall_backend` accepts `auto`, `nftables`, `iptables`, `firewalld`, and `ufw`.

### Step 4: Add Network Interfaces

For hosts with multiple NICs, add interfaces through the API (there is no UI for this yet): `POST /api/hosts/:id/interfaces` with
- **name:** e.g., `eth0`, `ens192`, `bond0`
- **role:** e.g., `management`, `data`, `backup`, `storage`, `dmz`
- **ip address:** (optional)

Interface roles are used when policies target specific interface roles instead of all interfaces.

### Step 5: Verify Host Readiness

Click **Check Readiness** on a host row to verify:
- The selected backend is installed and accessible; native-manager prerequisites and active state are verified
- sudo works with the credential's privilege escalation setting (`sudo -n` or `sudo -S` with the sudo password) and runs `sh` as root; a wrong sudo password, a missing password, `requiretty` or an account not allowed to run `sh` as root are reported as specific errors
- The `nf_tables` kernel module is loaded (for nftables; a warning only)
- Firewall backend is auto-detected if set to `auto`, preferring active firewalld/UFW; conflicting active managers or failed detection stop deployment

### Step 6: (Optional) Discover Hosts Automatically

Instead of adding hosts by hand, use **Inventory → Discovery**:

1. Click **+ New Discovery Profile** (admin).
2. Add one or more **target sets**: an SSH credential (existing, or a new one added inline), the networks to scan (IPv4 CIDRs and/or VLAN subnets) and the SSH port.
3. Choose a schedule (manual only, or every N minutes/hours) and the tag for new hosts (default `new-server`).
4. Click **Run Now** (operator/admin) or wait for the schedule.

A run TCP-probes the SSH port on every address, logs in read-only with the target set's credential, and imports hosts that are not in inventory yet; existing hosts are left untouched. Each imported host is assigned the credential that logged in. Credentials added inline are stored as *Not assigned* unless you make them global, so they never change the credential of other hosts. The run history shows per-address results (imported, already present, login failed and why).

Limits: IPv4 only, at most a /20 (4096 addresses) per network and 8192 addresses per run; one run per profile at a time. Runs left running when the API restarts are marked FAILED.

---

## 4. Auto-Tagging with Rules

Instead of manually tagging every host, create rules that automatically assign tags based on host attributes.

### Step 1: Create a Tag Rule

Go to the **Inventory → Auto-Tagging** tab:

1. Click **+ Create Tag Rule**
2. **Name:** e.g., "Tag web servers by hostname"
3. **Target Tag:** Select the tag to assign (e.g., `web-server`)
4. **Criteria:**
   - Field: `hostname`
   - Operator: `matches` (regex)
   - Value: `^web-.*`
   - Logic: `AND` or `OR` for multiple conditions

Use **Preview Matches** to see which hosts the criteria match before saving. When you save, the rule is applied right away.

### Step 2: Evaluate the Rule

Click **Evaluate** on a rule to run it against all hosts again. The result shows how many hosts matched.

### Step 3: Review Matches

Click the rule to see which hosts matched and received the tag. Tags assigned by rules are stored with `source: rule`; manually assigned tags are never overwritten or removed by rules.

### Automatic Evaluation

A background job evaluates all enabled rules every 5 minutes. **Run All Rules Now** runs all rules immediately.

### Example Rules

| Rule Name | Condition | Tag |
|-----------|-----------|-----|
| Web servers | hostname matches `^web-.*` | `web-server` |
| Production hosts | environment equals `production` | `production` |
| VLAN 100 hosts | vlan_tag equals `100` | `prod-data` |
| Red Hat family | os_family matches `^(rhel\|centos\|rocky)$` | `rhel-family` |
| Monitoring subnet | mgmt_ip in_cidr `10.0.50.0/24` | `monitoring` |

---

## 5. Creating Firewall Policies

### Step 1: Create a Policy Set

Go to **Policy Sets** in the sidebar and click **+ Create Policy Set**:

- **Name:** e.g., "Web Server Firewall"
- **Scope Type:**
  - `TAG` — applies to all hosts with a specific tag
  - `VLAN` — applies to all hosts in a VLAN
  - `HOST_LIST` — applies to explicitly selected hosts
- **Scope Target:** Select the tag, VLAN, or hosts

### Step 2: Create a Policy Version

Inside the policy set, click **+ New Version**. The new version starts as DRAFT. On the version page, set the **Interface Scope (Policy Level)** and click **Update Interface Scope**:
  - `INTERFACE_ROLE` (recommended) — e.g., apply only to `data` interfaces
  - `ALL_INTERFACES` — apply to every interface on the host
  - `INTERFACE_NAME` — apply to specific named interfaces (e.g., `eth0`)

Individual rules can override the interface scope.

### Step 3: Add Rules

Add firewall rules to the version. Each rule specifies:

| Field | Options | Example |
|-------|---------|---------|
| **Direction** | IN, OUT, BOTH, FORWARD (through a gateway) | `IN` |
| **Action** | ALLOW, DENY | `ALLOW` |
| **Protocol** | tcp, udp, icmp, any | `tcp` |
| **Ports** | Single, comma-separated, or range | `80,443` or `8000-9000` |
| **Source Type** | CIDR, TAG, VLAN, HOST | `TAG` |
| **Source Value** | IP/CIDR or entity ID | Select "app-server" tag |
| **Destination Type / Value** | FORWARD rules only: IoT device, CIDR, VLAN, TAG, HOST | an IoT device |
| **Log Mode** | NONE, LOG, LOG_RATE_LIMITED | `NONE` |
| **Comment** | Free text | "Allow HTTPS from app tier" |

FORWARD rules filter traffic routed *through* a host, such as an IoT/OT gateway; see [iot.md](iot.md).

### Step 4: Preview Compiled Output

There is no render button in the UI. Operators and admins can call `GET /api/policy-versions/:versionId/render/host/:hostId` to see the nftables/iptables rules or native firewalld/UFW artifact generated for one host. It returns:
- The compiled ruleset text
- SHA-256 hash of the output
- Which firewall backend will be used

In **Inventory → Hosts**, **View Visualization** shows a diagram of the policies that apply to a host.

### Rule Evaluation Order

Rules are evaluated in `order_index` order. The compiled output follows:
1. Baseline rules (loopback, established/related, management SSH)
2. User-defined rules (in order_index order)
3. Default deny for **inbound** traffic. Outbound traffic is allowed unless an OUT rule denies it, and forwarded traffic is only filtered for devices protected by a gateway.

Segmentra only manages its own rules: on nftables the table `inet segmentra`, on iptables the chains `SEGMENTRA-IN`, `SEGMENTRA-OUT` (and `SEGMENTRA-FWD` for forwarding), reached by jumps from `INPUT` / `OUTPUT` / `FORWARD`. In those chains an ALLOW returns to the built-in chain (`RETURN`) instead of accepting, so other tools' rules (Docker, fail2ban, Kubernetes) are left alone and still apply.

Firewalld uses reserved native policy objects; UFW uses marked blocks in its before-rules files. Native allows can be terminal within the manager, and existing administrator rules can still affect other traffic. Firewalld non-forward rules require `ALL_INTERFACES`; native learning/log-only mode is rejected. See [native semantics and limits](firewall-managers.md#rule-semantics-and-limits).

---

## 6. Using Policy Templates

Templates let you create reusable policy blueprints for common server roles.

### Step 1: Create a Template

Go to **Templates** in the sidebar:

1. Click **+ New Template**
2. **Name:** e.g., "Web Server Standard"
3. **Category:** e.g., "Application Servers"
4. **Target Tag:** (optional) Select `web-server` — enables auto-apply
5. **Auto-Apply:** Enable if you want DRAFT policies created automatically when hosts gain this tag

### Step 2: Add Template Rules

Click the template and add rules (same fields as policy rules, including FORWARD rules with a destination):
- Allow TCP 80,443 IN from 0.0.0.0/0
- Allow TCP 53 OUT to DNS servers
- Allow TCP 443 OUT for package updates

### Step 3: Instantiate

Click **Instantiate** to create a real policy set + version + rules from the template. The created version starts in DRAFT status and goes through the normal approval workflow.

### Auto-Apply

If auto-apply is enabled and a host gains the template's target tag (manual tagging, CSV import, auto-tagging rules or discovery), Segmentra automatically creates a policy set scoped to that tag with a DRAFT version from the template (once per template and tag). This connects the auto-tagging pipeline to policy creation; the version still needs approval before it can be deployed.

---

## 7. Visual Topology Design

Design policies visually by drawing network flows between groups.

### Step 1: Create a Topology View

Go to **Topology** in the sidebar:
1. Click **+ New View** and give it a name

### Step 2: Auto-Discover (Optional)

Click **Auto-Discover from Inventory** to automatically populate:
- Nodes from tags with hosts and VLANs with hosts
- Edges from currently deployed policy rules

### Step 3: Add Flows

Define connections between groups:
- **Source:** TAG:web-server
- **Target:** TAG:db-server
- **Protocol:** TCP
- **Ports:** 5432
- **Action:** ALLOW

This represents "web servers are allowed to connect to database servers on port 5432".

### Step 4: Generate Policies

Click **Generate Policies** to create a policy set from the visual design. Flows drawn in the UI are bidirectional, so each becomes:
- An OUT rule enforced on the source side (web-server → db-server:5432)
- An IN rule enforced on the target side (db-server ← web-server:5432)

All rules go into one `HOST_LIST` policy set with a DRAFT version, and every host that takes part receives every rule. Split the design into several views if you need per-group isolation.

---

## 8. Approval Workflow

### Step 1: Submit for Approval

On the policy set page, click **Submit for Approval** next to the DRAFT version (or **Resubmit for Approval** for a REJECTED one). The system automatically:
- Evaluates high-risk patterns (broad source ranges, ALL_INTERFACES scope, sensitive ports)
- Flags the version as high-risk if applicable
- Changes status from DRAFT to PENDING_APPROVAL

### Step 2: Review and Approve

Go to **Approvals** in the sidebar. The page displays a table of all pending approval versions automatically — no need to look up or paste version UUIDs.

**Table columns:**

| Column | Description |
|--------|-------------|
| **Policy Set** | Name of the parent policy set |
| **Version** | Version number |
| **Rules** | Number of rules in the version |
| **Submitted By** | User who created and submitted the version |
| **Submitted** | Submission date with relative time (e.g., "3 hours ago") |
| **Change Summary** | Brief description of what changed |

Versions flagged by the high-risk evaluator display a **HIGH RISK** badge.

**Actions per row:**

- **Approve** (green button) — approve the version
- **Reject** — expands to reveal a textarea for entering a rejection reason
- **View Rules** — links to the full version detail page

**Expanded row detail:**

Expanding a row shows two panels:
- **Left:** Rejection reason form (required when rejecting)
- **Right:** Optional impact analysis — compare the pending version against a previous approved or deployed version on sample hosts, showing a semantic diff of new allows, removed allows, new denies, and removed denies per host

### Approval Constraints

- Nobody can approve their own changes: the approver must not be the creator, the submitter or anyone who edited the version (separation of duties). This applies to admins too.
- Only users with `approver` or `admin` roles can approve or reject
- Only DRAFT and REJECTED versions can be edited; APPROVED, DEPLOYED and PENDING_APPROVAL versions can be archived

---

## 9. Deploying Policies

### Step 1: Create a Deployment

Go to **Deployments** and click **+ Create Deployment**:

1. **Policy Version:** pick an APPROVED or DEPLOYED version from the list (shown as `<policy set> v<n> (<status>)`)
2. **Deployment Mode:**
   - `FULL` — all target hosts
   - `CANARY` — the first hosts by hostname (**Canary Size**, default 1) are deployed first; if one of them fails, the remaining hosts are not deployed
   - `PROGRESSIVE` — hosts are deployed in batches (**Batch Size**, default 5); if a host fails, the rollout stops at the end of that batch

   `FULL` deploys every host even if some fail. Canary and progressive gates apply to the SSH Direct executor only; the Ansible executor deploys all hosts in one run. Hosts that were not deployed because the rollout halted are marked SKIPPED and can be deployed later with **Retry Failed Hosts**.
3. **Target Type:** Tag, VLAN or specific hosts (only enabled hosts are included)
4. **Schedule Deployment:** (optional) start at a future time (e.g., maintenance window); a background job starts it automatically when it is due
5. **Policy Expires At / On Expiry:** (optional) see [Policy Expiry](#20-policy-expiry-time-limited-deployments)

If the policy version is high-risk (for example broad sources or many targets), the deployment needs a second person: an approver or admin clicks **Approve** on the deployment before it can be started.

On the policy set page, each version shows where it is in use: **Active on N hosts**, or *Not active (superseded or removed)*.

### Step 2: Safety Check

When the deployment is created, Segmentra automatically:
- Compiles the policy for each target host
- Checks that SSH access from the management VLAN is preserved in the compiled ruleset
- In **FULL mode**: refuses to create the deployment if SSH access would be lost
- In **CANARY/PROGRESSIVE**: warns but allows it

### Step 3: Start the Deployment

Click **Start**. Depending on your configured executor, one of two paths executes (see below). Running deployments can be paused, resumed and stopped. If hosts failed, open the deployment and click **Retry Failed Hosts**: only failed hosts (and hosts skipped by a halted canary/progressive rollout) are redeployed; hosts that succeeded are left alone.

---

## 10. How SSH Direct Deployment Works

When the executor is set to **SSH Direct**, Segmentra connects to each host individually using SSH/SCP from the API server.

### What Happens on Each Host (Step by Step)

Every root step runs as one `sudo sh -c '…'` with the credential's privilege escalation setting.

```
Segmentra API Server                              Target Host
─────────────────────                             ───────────

1. mkdir -p /var/backups/segmentra (0700)  ─────► Backup directory

2. command -v nft  (or iptables-restore)   ─────► Check that the tool for the
                                                  policy's backend is installed

3. Back up Segmentra's own state only:     ─────► /var/backups/segmentra/
   nftables: table inet segmentra                   nft.ruleset.<timestamp>
   iptables: SEGMENTRA-IN/OUT(/FWD) chains          iptables.<timestamp> (+ ip6tables.<timestamp>)
             and their jumps                        (full iptables-save kept as <file>.full)
   (deployment aborts if the backup fails)

4. scp compiled policy → ~/.segmentra-*.policy ─► Upload to the SSH user's home

5. install -m 600 → /etc/segmentra.policy  ─────► Root-owned policy file
                                                  (/etc/segmentra.policy6 for IPv6 iptables)

6. Schedule an automatic revert            ─────► systemd-run timer (or nohup sleep)
   (default 120 s)                                 restores the step-3 backup

7. Apply:                                  ─────► nft -f /etc/segmentra.policy
                                                  (replaces only table inet segmentra)
                                                  or iptables-restore --noflush of the
                                                  SEGMENTRA chains + INPUT/OUTPUT jumps
   If apply FAILS: restore the backup immediately

8. Open a NEW SSH connection               ─────► Reachability check
   If the host is unreachable, the scheduled revert restores the backup (lockout protection)

9. Cancel the scheduled revert             ─────► Deployment confirmed
```

### Key Details

- **Sequential execution**: Hosts are processed one at a time, in hostname order (this is what makes the canary/progressive gates possible)
- **Scoped**: only Segmentra's own table/chains are backed up, replaced and restored; other tools' rules (Docker, Kubernetes, fail2ban) are never flushed or replaced
- **SSH host keys**: trust-on-first-use — `StrictHostKeyChecking=accept-new` with the known_hosts file from `SEGMENTRA_KNOWN_HOSTS` (default `~/.ssh/known_hosts`); a changed host key fails the connection
- **All commands use `sudo`**: The SSH user doesn't need to be root, but needs full sudo rights. Each root step is one `sudo sh -c '…'` (`sudo -n` without a password, `sudo -k -S -p ''` with the password on stdin)
- **Missing tool**: If the tool for the policy's backend (`nft` or `iptables-restore`) is missing on the host, the deployment fails for that host before anything is changed
- **Automatic rollback**: If `nft -f` or `iptables-restore` fails, the backup is restored at once; if the host stops answering after the apply, the scheduled revert restores it
- **Timeout**: Hosts that don't finish within 10 minutes are marked as FAILED by a background job

### SSH Direct Pros and Cons

| Pros | Cons |
|------|------|
| No Ansible dependency | Sequential (one host at a time) |
| Lightweight | No built-in parallelism |
| Works anywhere with SSH | Simpler error handling |
| No Docker socket needed | |

---

## 11. How Ansible Deployment Works

When the executor is set to **Ansible**, Segmentra generates a deployment bundle and executes an Ansible playbook inside the `segmentra-ansible-runner` Docker container.

### Architecture

```
┌──────────────────────────────────┐
│  Segmentra API Container         │
│                                  │
│  1. Compile policy per host      │
│  2. Write bundle to /bundles/    │
│     - inventory.ini              │
│     - host_rules/<host>.nft|     │
│       .iptables (+ .ip6tables)   │
│     - .secrets/ keys, host_vars/ │
│       (deleted after the run)    │
│  3. Execute:                     │
│     docker exec                  │
│       segmentra-ansible-runner   │
│       ansible-playbook           │
│       -i /bundles/.../inventory.ini
│       /runner/playbooks/         │
│         apply-firewall.yml       │
│                                  │
│  (via Docker socket)             │
└──────────┬───────────────────────┘
           │ /var/run/docker.sock
           ▼
┌──────────────────────────────────┐
│  Docker Daemon                   │
└──────────┬───────────────────────┘
           │
           ▼
┌──────────────────────────────────┐
│  segmentra-ansible-runner        │
│                                  │
│  - Reads inventory.ini           │
│  - Reads host_rules/*            │
│  - Runs the playbook on all      │
│    hosts in one run (Ansible     │
│    runs hosts in parallel)       │
│                                  │
│  For each host:                  │
│    1. Create backup dir          │
│    2. Detect nft / iptables      │
│    3. Back up Segmentra's state  │
│    4. Copy policy file           │
│    5. Apply rules                │
│    6. Rollback on failure        │
└──────────────────────────────────┘
           │ SSH
           ▼
┌──────────────────────────────────┐
│  Target Hosts (Linux fleet)      │
└──────────────────────────────────┘
```

### Deployment Bundle Structure

```
/bundles/<deploymentId>/
├── inventory.ini          # Ansible inventory with per-host variables (no secrets)
├── manifest.json          # Deployment metadata
├── ansible.stdout.log     # Ansible stdout (written during execution)
├── ansible.stderr.log     # Ansible stderr
├── .secrets/              # Private key files (0600), only during the run
├── host_vars/<host>.yml   # ansible_password / ansible_become_password (0600), only during the run
└── host_rules/
    ├── webserver01.nft       # Compiled nftables policy for webserver01
    ├── webserver02.nft       # Compiled nftables policy for webserver02
    ├── dbserver01.iptables   # Compiled iptables policy for dbserver01
    └── dbserver01.ip6tables  # IPv6 rules for dbserver01 (when present)
```

Key files and `host_vars` are deleted as soon as the playbook finishes. Passphrase-protected keys are loaded into an `ssh-agent` inside the runner; the passphrase is never written to disk (see [security.md](security.md#how-secrets-are-used-when-connecting-to-hosts)).

### Generated Inventory File

```ini
[all]
webserver01 ansible_host=10.0.1.10 ansible_user=segmentra ansible_port=22 ansible_ssh_private_key_file=/bundles/abc123/.secrets/<key file> ansible_become=yes ansible_become_method=sudo segmentra_policy_file=/bundles/abc123/host_rules/webserver01.nft
dbserver01 ansible_host=10.0.2.10 ansible_user=segmentra ansible_port=2222 ansible_connection=ssh ansible_become=yes ansible_become_method=sudo segmentra_policy_file=/bundles/abc123/host_rules/dbserver01.iptables segmentra_ip6_policy_file=/bundles/abc123/host_rules/dbserver01.ip6tables
```

(`dbserver01` uses a password credential; its password is in `host_vars/dbserver01.yml`, not in the inventory.)

### What the Playbook Does

The playbook (`infra/ansible-runner/playbooks/apply-firewall.yml`) runs these tasks on each host:

For `firewalld`/`ufw`, it delegates to `apply-manager.yml`: install the one-shot Python helper, take a scoped backup, schedule a systemd rollback, apply permanent native configuration, reconnect, verify persistence, and cancel the rollback only on success. The steps below describe the raw nftables/iptables path.

1. **Generate timestamp** for backup filenames
2. **Validate policy file** (fail early if not provided)
3. **Create backup directory** (`/var/backups/segmentra`, mode 0700)
4. **Detect firewall backend** (`nft` / `iptables-restore`) and fail on a backend mismatch
5. **Back up Segmentra's own state** (`table inet segmentra`, or the `SEGMENTRA-IN/OUT(/FWD)` chains for iptables and ip6tables)
6. **Copy policy file** to `/etc/segmentra.policy` (mode 0600; `/etc/segmentra.policy6` for IPv6)
7. **Apply rules** (`nft -f`, replacing only `table inet segmentra`, or the iptables chains and their `INPUT`/`OUTPUT`(/`FORWARD`) jumps)
8. **On failure: rollback** from this run's backup and fail with an error message

The raw Ansible path has no post-apply reachability check with automatic revert. The native-manager path has both. All Ansible backends ignore canary/progressive gates.

### Ansible Pros and Cons

| Pros | Cons |
|------|------|
| Parallel execution across hosts | Requires Docker container |
| Built-in rollback block/rescue | Requires Docker socket access (not available with the hardened override) |
| Industry-standard tooling | No raw-backend lockout auto-revert; no canary/progressive gates |
| | More complex setup, slightly slower startup |

---

## 12. Firewall Learning (Traffic Discovery)

This workflow supports raw nftables/iptables only. Firewalld/UFW learning and log-only policy-test sessions are not yet supported; attempts are rejected without changing the enforced permanent ACL. Ordinary policy simulation and drift/compliance still work with native managers.

Firewall Learning discovers what traffic actually flows to/from a server, so you can write accurate policies without guessing.

### How It Works (Agentless)

The key insight: **the Linux kernel is the sensor**. Every Linux server has netfilter built in. Segmentra SSHes in and temporarily reconfigures it to log-everything/block-nothing mode.

### Step-by-Step

1. Go to **Troubleshoot** in the sidebar (operator or admin)
2. Scroll to **Firewall Learning**
3. Select one or more hosts
4. Set the duration (e.g., 60 minutes)
5. Click **Start Audit**

### What Happens on the Host

```
Time 0:00  ─── Segmentra SSHes into the host
               1. Back up Segmentra's own state (scoped, like a deployment):
                  /var/backups/segmentra/nft.audit-backup.<ts>
                  (or iptables.audit-backup.<ts>)

               2. Configure rsyslog:
                  Create /etc/rsyslog.d/99-segmentra-audit.conf
                  Route "FW-AUDIT" kernel messages to /var/log/segmentra-audit-<host>-<ts>.log
                  Restart rsyslog

               3. Deploy a log-only policy into Segmentra's own table/chains
                  (table inet segmentra, or SEGMENTRA-IN/OUT/FWD):
                    every packet is logged with prefix "FW-AUDIT: ..." and accepted

               Result: ALL traffic is logged, NOTHING is blocked; other tools' rules are untouched

Time 0:01-0:59 ─── Normal traffic flows, the kernel logs it:

               FW-AUDIT: ALLOW: catch-all: IN=eth0 SRC=10.0.1.50 DST=10.0.2.10 PROTO=TCP SPT=44312 DPT=443
               ...

Time 1:00  ─── Background job detects the session expired
               1. SSH in and restore Segmentra's previous state from the backup
                  (if the restore fails, the session stays RUNNING and is retried)

               2. Retrieve the log file

               3. Clean up the rsyslog config and restart rsyslog

               4. Parse logs into structured flows:
                  10.0.1.50 → 10.0.2.10 : TCP/443   (1,247 packets, IN)
                  10.0.2.10 → 10.0.1.100 : TCP/5432  (892 packets, OUT)
```

A running session can also be cancelled from **Active Audit Sessions**, which restores the rules right away.

### Viewing Results

After the session completes:
1. Go to **Troubleshoot → Firewall Learning**
2. Select the completed session
3. View communication flows grouped by source/destination/port with packet counts

---

## 13. Policy Auto-Recommendations

After a firewall learning session, generate policy rule recommendations automatically.

### Step 1: Complete a Learning Session

Run a Firewall Learning session as described above and wait for it to complete.

### Step 2: Generate Recommendations

Recommendations are API-only for now (there is no Recommendations page in the UI): `POST /api/recommendations/generate` (operator/admin) with `auditSessionId` and `hostId` of a completed learning session, then list them with `GET /api/recommendations`.

The engine:
1. Takes each observed traffic flow
2. Resolves source IPs to Segmentra entities (TAG > VLAN > HOST > CIDR fallback)
3. Groups flows by destination port
4. Calculates confidence scores (higher for known ports like 80/443/22, frequent flows, both endpoints in inventory)
5. Deduplicates against already-deployed rules

### Step 3: Review Recommendations

Each recommendation shows:
- The proposed rule (direction, protocol, port, source)
- Confidence score (0-100%)
- Number of observed flows supporting the recommendation
- The entity it resolved to (e.g., `TAG:web-server` instead of raw IP)

### Step 4: Accept or Reject

Accept or reject each recommendation (`POST /api/recommendations/:id/accept` or `/reject`). Accepted recommendations can then be applied (`/apply`) as rules in a DRAFT policy version that goes through the normal approval workflow.

---

## 14. On-Device Policy Testing

Test a specific policy against real traffic before enforcing it.

### Step 1: Start a Policy Test

Go to **Policy Impact Analysis** in the sidebar (operator, approver or admin):
1. Click **+ Start Policy Test**
2. Select a **Policy Version**. Operators can test APPROVED or DEPLOYED versions; approvers and admins can also test DRAFT or PENDING_APPROVAL versions (e.g. while reviewing)
3. Select a **Target Host** (one running test per host)
4. Set **Duration (minutes)** (1 to 1440, default 30)

### Step 2: What Happens

The system deploys the policy in log-only mode (same mechanism as firewall learning: nothing is blocked), collects the traffic log and restores the original rules when the timer expires. **Peek Logs** shows the traffic collected so far; **Stop & Collect** ends the test early.

### Step 3: Analyze Results

Click **Analyze** after the test has been collected. The analysis shows:

| Category | Meaning | Color |
|----------|---------|-------|
| **Matched Flows** | Traffic that matches an ALLOW rule — expected | Green |
| **DENY Rule Hits** | Active traffic that matches a DENY rule — would be blocked | Red |
| **Unmatched Flows** | Traffic with no matching rule — default-deny would block it | Yellow |

**Coverage percentage** = matched flows / total flows

### When to Use

- Before deploying a new policy to production
- When modifying existing policies and want to verify nothing breaks
- To identify missing ALLOW rules before enforcement

### Difference from Firewall Learning

| | Firewall Learning | Policy Testing |
|---|---|---|
| **Goal** | Discover what traffic exists | Validate a specific policy |
| **Input** | No policy (observe everything) | A policy version |
| **Output** | List of traffic flows | Gap analysis report |
| **Question** | "What communicates?" | "Does my policy cover everything?" |

---

## 15. Troubleshooting & Simulation

### Communication Simulation

Go to **Troubleshoot → Simulate Communication**:

1. Enter **Source IP** and **Destination IP**
2. Optionally set **Source Port**, **Destination Port**, and **Protocol**
3. Click **Simulate**

The system analyzes all deployed policies on both the source and destination hosts and reports:
- Whether communication would be **blocked** or **allowed**
- Which specific rules match
- The blocking/allowing rule details

### Policy Lookup (Search Tools)

- **Search by IP**: Find all policy rules that reference a specific IP address
- **Host Policies**: View all policies deployed to a specific host
- **Policy Version Hosts**: See which hosts have a specific policy version deployed

---

## 16. Compliance & Drift Detection

Detect when hosts have been manually modified after a deployment.

### How It Works

1. Right after a successful deployment, Segmentra reads Segmentra's own live state from the host and stores its hash (`v2:` fingerprint)
2. The compliance check SSHes into the host and reads the same state again: `table inet segmentra` (nftables) or the `SEGMENTRA-IN/OUT` chains and their jumps (iptables). Rules of other tools (Docker, Kubernetes, fail2ban) are not part of the hash
3. It hashes the current state and compares it to the stored hash
4. Status: **compliant** (match), **drifted** (mismatch), **unknown** (never deployed, or last deployed by an older version that hashed the whole ruleset — redeploy once), or **error** (SSH failure)

### Using Compliance Checks

- **Per-host**: In Inventory → Hosts, click **Check Compliance** on a host
- **Bulk**: Select multiple hosts and click **Check Compliance (N)**
- **API**: `GET /api/compliance/hosts/:hostId` or `POST /api/compliance/hosts/bulk`

---

## 17. Integrations

Go to **Integrations** in the sidebar (admin only) and click **+ New Integration**. Two types are functional:

| Type | What it does |
|------|-------------|
| **SIEM (Syslog Forwarder)** | Forwards audit events to a syslog receiver (UDP or TCP). Config: `{"host": "siem.company.com", "port": 514, "protocol": "udp", "facility": 13, "severity": 6}`. Every Audit Log entry (deployments, SSH credentials, users and roles, approvals, inventory, LDAP, integrations, ...) is forwarded once to every enabled SIEM integration; see [security.md](security.md) for how it works. |
| **Threat Intelligence (AbuseIPDB)** | **Sync** downloads the AbuseIPDB blacklist into Segmentra's threat-intel entries. Config: `{"apiKey": "...", "confidenceMinimum": 90, "maxResults": 100, "expiryDays": 7, "autoBlock": false}`. The entries are shown under **Threat Intelligence**. With `autoBlock: true` and `autoBlockPolicySetId`, new malicious IPs are added as DENY rules to a DRAFT version of that policy set (an open auto-block draft is reused; IPs already blocked are skipped), which still needs approval and deployment. |

**SOAR** and **Vulnerability DB** are listed as *planned* and cannot be selected. **Test** checks the connection (for SIEM it sends a test message), **Sync** runs the threat-intel download, and the event log shows each test and sync. API keys and tokens are masked in API responses.

---

## Compliance reports

**Compliance Report** in the sidebar produces a point-in-time evidence report for an assessor, mapped to PCI DSS v4.0, ISO/IEC 27001:2022, SOC 2 and the HIPAA Security Rule. It is evidence from Segmentra's data, not an audit opinion; see [compliance-reports.md](compliance-reports.md) for what is measured and the limitations.

1. Choose the frameworks and the period (default 90 days). Under *Thresholds and live check* you can change what counts as stale, overdue or inactive, and (operator or admin) also read every managed host over SSH to compare its live rules with the last deployment (slow).
2. Press **Generate report**. The report opens with its hash and integrity status, summary cards (red where something needs attention), a table per framework (control, status **Evidence** / **Attention** / **Not covered**, and the evidence behind it), and the hosts without a deployed policy and IoT assets without a gateway.
3. **Open printable report** and the browser's print dialog give a PDF; **JSON** and the **CSV dataset** list (controls, hosts, changes, deployment failures, inactive users, SSH credentials, IoT assets, full audit events) are for spreadsheets and archives.
4. Earlier reports stay under **Stored reports** and cannot be changed or deleted; opening one re-checks its integrity.

## Policy as code

A policy set can be exported to, and imported from, a YAML or JSON document (tags, VLANs, hosts and IoT assets by name), for Git, CI and copying policies between instances. An import only ever creates a **DRAFT** version: nothing is approved or deployed by it. The format, the rules of the comparison and the limitations are in [policy-as-code.md](policy-as-code.md).

**Import a policy (operator or admin)**
1. Open **Policy Sets** and press **Import YAML/JSON**.
2. Paste the document or pick a `.yaml`, `.yml` or `.json` file.
3. Press **Check (dry run)**. Green: what would happen and the rules that would be added (`+`) or removed (`-`). Red: every problem with its path; fix the document and check again. Nothing is written yet.
4. Press **Import as DRAFT**. The policy set is created, or gets a new DRAFT version if the rules differ; if they are the same you are told that nothing changed.
5. Open the policy set, press **Submit for Approval**, and ask a different user to approve it under **Approvals**. You cannot approve a version you imported.

**Export.** Open a policy set and press **Export YAML** or **JSON** on a version.

**Command line, for CI.** `node scripts/segmentra-policy.mjs export | plan | apply` (see the docs for the connection settings and exit codes). `plan --detailed-exitcode` exits 2 when something would change.

## 18. Kubernetes Microsegmentation

Generate Kubernetes NetworkPolicy manifests from Segmentra policies and apply them to the cluster from Segmentra (with stored credentials), or apply them yourself with `kubectl` or a CI/CD pipeline.

### Step 1: Register a Cluster

Go to **Kubernetes** in the sidebar:
1. Click **+ Add Cluster** (admin)
2. Enter the **API Server URL** (e.g., `https://k8s-api.example.com:6443`)
3. Select **Auth Type**: Kubeconfig, Service Account, Bearer Token, or a cloud login (**Amazon EKS**, **Google GKE**, **Azure AKS**; implemented but not yet tested against real cloud accounts), and the cluster's **CNI Plugin**
4. For EKS/GKE/AKS also enter the cluster's API server URL and CA certificate, and fill the cloud fields (AWS access key and region, Google service-account key, or Azure tenant/client/secret); Segmentra mints short-lived tokens itself, no cloud CLI needed. For the other types, to apply from Segmentra, paste the **kubeconfig** (with inline token or client certificate; it carries the API server URL and CA) or the **bearer token** (plus the API server CA certificate). They are stored encrypted and never shown again; an admin can replace or remove them later, here or in **Admin → Kubernetes Credentials** (next to the SSH credentials). **Test connection** verifies them. See [kubernetes.md](kubernetes.md) for the minimal RBAC the account needs

Workload discovery is not implemented. On the **Workloads** tab, **+ Add workload** registers a workload with its pod labels, and the **+ tag** selector maps it to a Segmentra tag. A rule whose source is that tag then selects those pods by label.

### Step 2: Generate NetworkPolicy

1. Select the cluster and click **Generate NetworkPolicy**
2. Pick an APPROVED or DEPLOYED policy version, the namespace and a policy name
3. Segmentra builds an **Ingress-only** NetworkPolicy from the version's inbound ALLOW rules (IN/BOTH; sources are resolved to `ipBlock` CIDRs, ports are kept; outbound rules are not emitted because egress is not restricted). DENY, ICMP, FORWARD and other rules that NetworkPolicy cannot express exactly are skipped with a warning instead of being widened
4. On the **Network Policies** tab use **Apply** (create or update on the cluster; **Dry run** validates first), **Check** (detects drift against the live policy) and **Remove**. Or use **Copy kubectl apply** / **Download JSON** and apply it yourself. Segmentra refuses to overwrite or delete a same-named policy it did not create

---

## 19. OT/IoT Microsegmentation

Protect devices that can't run agents — PLCs, HMIs, sensors, cameras, medical devices — by enforcing rules on a Linux **gateway** host that routes their traffic. The full walkthrough is in [iot.md](iot.md); the gateway itself is set up as described in [gateway-setup-guide.md](gateway-setup-guide.md).

### Step 1: Add the Gateway to Inventory

Add the Linux host that routes traffic to the devices, and give it the system tag `iot-gateway`.

### Step 2: Register IoT Devices

Go to **OT/IoT** in the sidebar, **Assets** tab:
1. Click **+ Add IoT Asset**
2. Enter name, type, criticality, IP address, MAC, vendor, model and VLAN / zone
3. Assign the device to its gateway(s) (**+ Assign gateway...**). The **Gateways** tab lists the gateways and the devices they protect.

Once a device is assigned to a gateway, forwarded traffic **to** that device is dropped on the gateway unless a FORWARD rule allows it; other routed traffic is not affected.

### Step 3: Create FORWARD Rules and Deploy

Create a policy set scoped to the gateway (for example the `iot-gateway` tag) and add rules with direction **FORWARD (through gateway)** and a destination (IoT device, CIDR, VLAN, tag or host). Approve and deploy it like any other policy. On nftables the rules go into the `forward` chain of `table inet segmentra`; on iptables into `SEGMENTRA-FWD`.

Flow collectors, enforcement points (switch ACLs) and traffic baselines exist only as API endpoints (`/api/flow-collectors`, `/api/enforcement-points`, `POST /api/iot-assets/:id/baseline`); they have no UI.

---

## 20. Policy Expiry (Time-Limited Deployments)

### When to Use

- Temporary vendor access (e.g., "allow vendor SSH for 30 days")
- Maintenance window policies (e.g., "open port 8080 during maintenance, auto-remove after")
- Compliance-driven review cycles (e.g., "expire every 90 days to force re-review")

### How to Set It

1. Go to **Deployments** → **+ Create Deployment**
2. Fill in policy version, targets, mode as usual
3. Set **Policy Expires At** to the desired expiry date/time
4. Choose **On Expiry**:
   - **Notify Only** — sends an alert; the rules stay active (default)
   - **Remove** — automatically removes Segmentra's rules (`table inet segmentra`, or the `SEGMENTRA-*` chains and their jumps) from every host that still runs this deployment's policy
   - **Revert** — automatically redeploys the previous successfully deployed version of the same policy set to the hosts that ran it, as a new system-created deployment (no new approval, but that version must still be APPROVED or DEPLOYED)

### What Happens Automatically

- **24 hours before expiry**: A `POLICY_EXPIRING_SOON` notification is sent to subscribed channels
- **At expiry** (checked every minute): the deployment is marked expired, the expiry action runs, and a `POLICY_EXPIRED` notification is sent. The per-host result of REMOVE is shown in the **On Expiry** column of the deployment's hosts table
- **Audit trail**: the warning, the expiry and the action are logged as audit events (actor *system*)

### Limitations

- If a REMOVE or REVERT action fails on a host, the error is recorded and a notification is sent, but it is **not retried** automatically.
- REVERT only redeploys to hosts that actually ran the previous version; other hosts keep the expired policy and are listed in the notification.

### Manually Restoring the Previous Ruleset

Before every deployment, Segmentra's own state on each host is backed up to `/var/backups/segmentra/`. To roll back by hand (for example after a NOTIFY_ONLY expiry), prefer deploying the previous policy version through Segmentra (below). To restore a backup directly, use `scripts/restore-previous-policy.sh` from the repository:

```bash
# Restore the most recent backup on each host
./scripts/restore-previous-policy.sh --hosts hosts.txt --user segmentra --latest

# Restore a specific backup timestamp (e.g. nft.ruleset.2026-03-18T11-46-05)
./scripts/restore-previous-policy.sh --hosts hosts.txt --user segmentra --timestamp 2026-03-18T11-46-05

# Show what would be done
./scripts/restore-previous-policy.sh --hosts hosts.txt --user segmentra --latest --dry-run
```

Options: `--hosts` (one IP or hostname per line), `--user` (SSH user with sudo), `--timestamp` or `--latest`, `--key` (private key), `--port` (default 22), `--dry-run`.

The script restores only Segmentra's own state (`table inet segmentra`, or the `SEGMENTRA-IN/OUT(/FWD)` chains and their jumps) with the same host scripts the executor uses. It never flushes the ruleset, so rules of Docker, Kubernetes or fail2ban are not touched. Backup files look like this:

```
-rw------- 1 root root 2048 Mar 18 11:46 nft.ruleset.2026-03-18T11-46-05
-rw------- 1 root root 1892 Mar 15 09:00 iptables.2026-03-15T09-00-12
```

Do not restore these files with `nft flush ruleset` / `nft -f` or a plain `iptables-restore`: that would replace other tools' rules too.

### Alternative: Deploy the Previous Policy Version via Segmentra

Instead of restoring backups, create a new deployment in Segmentra using the previous policy version:

1. Go to **Deployments** → **+ Create Deployment**
2. Select the **previous policy version** (the one that was active before the expired deployment)
3. Target the same hosts

This is the recommended approach for production environments as it keeps the full audit trail.

---

## 21. Notifications

### Setting Up

1. Go to **Notifications** in the sidebar (admin only)
2. Click **+ New Channel** and choose:
   - **Slack** — provide an incoming webhook URL
   - **HTTP Webhook** — provide an endpoint URL and optional auth header (Segmentra POSTs JSON)
   - **Email** is listed as *planned* and cannot be selected yet
3. Click **Send Test** to verify connectivity
4. Under **Event Subscriptions**, click **+ Add Event** to choose which events trigger notifications on this channel

Available events: `POLICY_SUBMITTED`, `POLICY_APPROVED`, `POLICY_REJECTED`, `DEPLOYMENT_STARTED`, `DEPLOYMENT_COMPLETED`, `DEPLOYMENT_FAILED`, `COMPLIANCE_DRIFT`, `POLICY_EXPIRING_SOON`, `POLICY_EXPIRED`, `EXCESSIVE_RULES_DETECTED`. `COMPLIANCE_DRIFT` can be selected but is currently never sent. A subscription's optional filter is stored but not applied yet: every event of the subscribed type is sent. The API also accepts `AUDIT_RESTORE_FAILED` (a firewall-learning restore failed).

Webhook URLs pointing to loopback, link-local or cloud-metadata addresses are refused unless `SEGMENTRA_ALLOW_PRIVATE_WEBHOOKS=true` (RFC1918 addresses are allowed). Webhook URLs and auth headers are masked in API responses.

### Example Configuration

**Slack channel for operations:**
- Subscribe to: DEPLOYMENT_STARTED, DEPLOYMENT_COMPLETED, DEPLOYMENT_FAILED

**Webhook to SIEM:**
- Subscribe to: POLICY_APPROVED, POLICY_EXPIRED, EXCESSIVE_RULES_DETECTED

---

## 22. Security Posture Audit

### Running a Scan

1. Go to **Security Audit** in the sidebar
2. Click **Run Security Scan**
3. Review findings grouped by severity (critical → high → medium → low)
4. Click severity cards to filter
5. Each finding shows the affected policy, rule details, and remediation guidance

### What It Checks

| Finding | Severity | Example |
|---------|----------|---------|
| Sensitive port open to any source | Critical | Port 22 (or RDP, databases, ...) ALLOW from any source |
| All ports open to any | Critical | Protocol=any, ports=* from 0.0.0.0/0 |
| Broad CIDR source | High | ALLOW from 10.0.0.0/8 (16M IPs) |
| Any-protocol rule | High | Protocol=any with no port restriction |
| ALL_INTERFACES + broad | High | Every interface exposed with wide-open rules |
| Unmanaged hosts | Medium | Hosts with no policy ever deployed |
| Stale policies | Medium | Last deployment > 90 days ago |
| Duplicate rules | Low | Same rule in multiple policy sets |

---

## 23. Background Jobs

Segmentra runs several background jobs automatically:

| Job | Interval | Purpose |
|-----|----------|---------|
| **Stale deployment timeout** | 2 min | Marks hosts as FAILED if stuck in RUNNING > 10 minutes |
| **Scheduled deployments** | 1 min | Starts deployments scheduled for the current time |
| **Expired audit sessions** | 1 min | Restores firewall rules and collects logs when learning sessions expire |
| **Tag rule evaluation** | 5 min | Re-evaluates all enabled auto-tagging rules against hosts |
| **Deployment expiry** | 1 min | Runs the expiry action (notify / remove / revert) for expired deployments, sends 24h expiry warnings |
| **Discovery scheduler** | 1 min | Starts discovery runs whose schedule is due (at startup, runs left RUNNING by a previous process are marked FAILED) |
| **Policy test expiry** | 1 min | Restores the original rules and collects logs for test sessions past their end time (retried if the restore fails) |

These jobs run as `setInterval` callbacks in the API process — no external scheduler needed.

---

## Quick Reference: Deployment Executor Comparison

| Feature | SSH Direct | Ansible |
|---------|-----------|---------|
| **Execution** | Sequential (one host at a time) | Parallel (all hosts in one playbook run) |
| **Connection** | Direct SSH from API server | Docker exec → Ansible → SSH to hosts |
| **Dependencies** | `ssh` + `scp` (+ `sshpass` for passwords) | Docker container + Docker socket |
| **Rollback on apply failure** | Automatic (restore this run's backup) | Automatic (block/rescue) |
| **Lockout protection** | Scheduled auto-revert, cancelled after a reachability check | None |
| **Canary / progressive gates** | Yes | No (all hosts at once) |
| **Logging** | Combined stdout/stderr files | Ansible-format logs |
| **Setup** | Minimal (works with the hardened compose override) | Requires `segmentra-ansible-runner` container |

---

## Quick Reference: Policy Lifecycle

```
                    ┌─────────┐
                    │  DRAFT  │ ← Create / Clone / Template Instantiate
                    └────┬────┘
                         │ Submit for Approval
                         ▼
                ┌──────────────────┐
                │ PENDING_APPROVAL │
                └───────┬──┬──────┘
                        │  │
              Approve   │  │  Reject
                        │  │
                        ▼  ▼
               ┌──────────┐ ┌──────────┐
               │ APPROVED │ │ REJECTED │──► Edit → Resubmit
               └────┬─────┘ └──────────┘
                    │ Deploy
                    ▼
               ┌──────────┐
               │ DEPLOYED │
               └──────────┘

APPROVED, DEPLOYED and PENDING_APPROVAL versions can be moved to ARCHIVED (read-only).
```

---

## Quick Reference: What Happens on a Target Host

```
Before Segmentra:                After Segmentra:
─────────────────                ────────────────

Existing rules (Docker, etc.)  →  unchanged; Segmentra adds table inet segmentra
                                   (or SEGMENTRA-IN/OUT/FWD chains + jumps)
                                 /etc/segmentra.policy (compiled rules)
No backups                     →  /var/backups/segmentra/
                                   nft.ruleset.2026-03-16T14-30-25
                                   nft.ruleset.2026-03-15T09-00-00
                                   ... (timestamped backups)
```

**Files created on target hosts:**
- `/etc/segmentra.policy` — Current active policy (0600); `/etc/segmentra.policy6` — IPv6 rules on iptables hosts
- `/var/backups/segmentra/` — Backup directory (0700)
- `/var/backups/segmentra/nft.ruleset.<timestamp>` — nftables backups (`table inet segmentra` only)
- `/var/backups/segmentra/iptables.<timestamp>` / `ip6tables.<timestamp>` — iptables backups (Segmentra chains; the full `iptables-save` is kept as `<file>.full`)
- `/var/backups/segmentra/segmentra-nft.sh`, `segmentra-iptables.sh` — helper scripts used for unattended restores (they are never run at boot)
- Reboot persistence, written into the distribution's own files (see [Persistence across reboots](../README.md#persistence-across-reboots)):
  - nftables: `/etc/nftables.d/segmentra.nft` (Debian/Ubuntu) or `/etc/nftables/segmentra.nft` (RHEL family), plus one `include` line (with a `# managed by Segmentra` marker) at the end of `/etc/nftables.conf` or `/etc/sysconfig/nftables.conf`
  - iptables: Segmentra's chains and jumps merged into `/etc/iptables/rules.v4` / `rules.v6` (Debian/Ubuntu) or `/etc/sysconfig/iptables` / `ip6tables` (RHEL family); all other lines are left unchanged
  - `/var/backups/segmentra/persist/` — previous version of each of those files before Segmentra changed it
- `/var/log/segmentra-audit-<host>-<ts>.log` — Firewall learning logs (temporary, during audit sessions only)
- `/etc/rsyslog.d/99-segmentra-audit.conf` — Rsyslog config (temporary, during audit sessions only)
