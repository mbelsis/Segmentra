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

- **SSH access** with a sudo-capable user (not root — most distros disable root SSH)
- **Passwordless sudo** for firewall commands:
  ```bash
  # /etc/sudoers.d/segmentra
  segmentra_user ALL=(ALL) NOPASSWD: /usr/sbin/nft, /usr/sbin/iptables, /usr/sbin/iptables-save, /usr/sbin/iptables-restore, /bin/mkdir, /bin/cp, /bin/mv, /bin/chmod, /bin/touch, /bin/rm, /usr/bin/tee, /usr/bin/systemctl
  ```
- **nftables** (preferred) or **iptables** installed
- **rsyslog** installed (required for firewall learning/audit features)

---

## 2. Initial Setup

### Step 1: Start Segmentra

**Windows:**
```batch
start.bat dev
```

**macOS/Linux:**
```bash
./start.sh dev
```

This starts PostgreSQL (port 15432), runs migrations, seeds roles, creates the default admin user, and starts the API (port 8080) and UI (port 5173).

### Step 2: Login

Open `http://localhost:5173` and login with:
- **Username:** `admin`
- **Password:** `admin`

Change the password immediately after first login.

### Step 3: Configure the Deployment Executor

Go to **Admin** in the sidebar.

Under **Deployment Executor**, choose:
- **Ansible** (recommended) — requires the `segmentra-ansible-runner` Docker container
- **SSH Direct** — lightweight, no Ansible dependency

### Step 4: Add SSH Credentials

In **Admin → SSH Credentials**, create a credential:
- **Name:** e.g., "Global SSH Key"
- **Username:** The sudo-capable user on target hosts (e.g., `segmentra`)
- **Private Key:** Paste the PEM-encoded private key
- **Scope:** `GLOBAL` (applies to all hosts)

The private key is encrypted at rest using AES-256-GCM.

### Step 5: (Optional) Configure Management VLAN

In **Admin → Management VLAN Setting**, select the VLAN used for SSH management access. This enables:
- Automatic SSH baseline rules in compiled policies (management SSH is always allowed)
- Safety guardrails that prevent deployments from locking out administrators

---

## 3. Building Your Inventory

### Step 1: Create Tags

Go to **Inventory → Tags** tab and create tags that describe your server roles:
- `web-server`, `db-server`, `app-server`, `monitoring`, `dmz`, etc.

Tags are the primary way to group hosts for policy targeting.

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
- Select firewall backend (`auto` for automatic detection, or `nftables`/`iptables`)
- Assign VLAN and tags

**Bulk import via CSV:**
- Click **Import CSV** with format: `hostname,mgmt_ip,ssh_port,environment,os_family,firewall_backend,vlan_tag`

### Step 4: Add Network Interfaces

For each host that has multiple NICs, go to the host detail and add interfaces:
- **Name:** e.g., `eth0`, `ens192`, `bond0`
- **Role:** e.g., `management`, `data`, `backup`, `storage`, `dmz`
- **IP Address:** (optional)

Interface roles are used when policies target specific interface roles instead of all interfaces.

### Step 5: Verify Host Readiness

Select hosts and click **Check Readiness** to verify:
- nftables/iptables is installed and accessible
- Passwordless sudo works for firewall commands
- Kernel modules are loaded (for nftables)
- Firewall backend is auto-detected if set to `auto`

---

## 4. Auto-Tagging with Rules

Instead of manually tagging every host, create rules that automatically assign tags based on host attributes.

### Step 1: Create a Tag Rule

Go to **Inventory → Tag Rules** tab (or the Tag Rules section):

1. Click **+ New Rule**
2. **Name:** e.g., "Tag web servers by hostname"
3. **Target Tag:** Select the tag to assign (e.g., `web-server`)
4. **Criteria:**
   - Field: `hostname`
   - Operator: `matches` (regex)
   - Value: `^web-.*`
   - Logic: `AND` or `OR` for multiple conditions

### Step 2: Evaluate the Rule

Click **Evaluate** to run the rule against all hosts immediately. The result shows how many hosts matched.

### Step 3: Review Matches

Click the rule to see which hosts matched and received the tag. Tags assigned by rules are marked with `source: rule` and won't conflict with manually assigned tags.

### Automatic Evaluation

A background job evaluates all enabled rules every 5 minutes. You can also trigger **Evaluate All** to run all rules immediately.

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

Go to **Policy Sets** in the sidebar and click **+ New Policy Set**:

- **Name:** e.g., "Web Server Firewall"
- **Scope Type:**
  - `TAG` — applies to all hosts with a specific tag
  - `VLAN` — applies to all hosts in a VLAN
  - `HOST_LIST` — applies to explicitly selected hosts
- **Scope Target:** Select the tag, VLAN, or hosts

### Step 2: Create a Policy Version

Inside the policy set, click **+ New Version**:
- **Interface Scope:** Choose which interfaces the rules apply to:
  - `INTERFACE_ROLE` (recommended) — e.g., apply only to `data` interfaces
  - `ALL_INTERFACES` — apply to every interface on the host
  - `INTERFACE_NAME` — apply to specific named interfaces (e.g., `eth0`)

### Step 3: Add Rules

Add firewall rules to the version. Each rule specifies:

| Field | Options | Example |
|-------|---------|---------|
| **Direction** | IN, OUT, BOTH | `IN` |
| **Action** | ALLOW, DENY | `ALLOW` |
| **Protocol** | tcp, udp, icmp, any | `tcp` |
| **Ports** | Single, comma-separated, or range | `80,443` or `8000-9000` |
| **Source Type** | CIDR, TAG, VLAN, HOST | `TAG` |
| **Source Value** | IP/CIDR or entity ID | Select "app-server" tag |
| **Log Mode** | NONE, LOG, LOG_RATE_LIMITED | `NONE` |
| **Comment** | Free text | "Allow HTTPS from app tier" |

### Step 4: Preview Compiled Output

Click **Render** on a specific host to see the actual nftables/iptables rules that would be generated. This shows:
- The compiled ruleset text
- SHA-256 hash of the output
- Which firewall backend will be used

### Rule Evaluation Order

Rules are evaluated in `order_index` order. The compiled output follows:
1. Baseline rules (loopback, established/related, management SSH)
2. User-defined rules (in order_index order)
3. Default deny (drop all unmatched traffic)

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

Click the template and add rules (same interface as policy rules):
- Allow TCP 80,443 IN from 0.0.0.0/0
- Allow TCP 53 OUT to DNS servers
- Allow TCP 443 OUT for package updates

### Step 3: Instantiate

Click **Instantiate** to create a real policy set + version + rules from the template. The created version starts in DRAFT status and goes through the normal approval workflow.

### Auto-Apply

If auto-apply is enabled and a host gains the template's target tag (via manual assignment or auto-tagging rules), Segmentra automatically creates a DRAFT policy set from the template. This connects the auto-tagging pipeline to policy creation.

---

## 7. Visual Topology Design

Design policies visually by drawing network flows between groups.

### Step 1: Create a Topology View

Go to **Topology** in the sidebar:
1. Click **+ New View** and give it a name

### Step 2: Auto-Discover (Optional)

Click **Auto-Discover Topology** to automatically populate:
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

Click **Generate Policies** to create policy sets from the visual design. Each flow is decomposed bidirectionally:
- An OUT rule on the source side (web-server → db-server:5432)
- An IN rule on the target side (db-server ← web-server:5432)

All generated policy versions start in DRAFT status.

---

## 8. Approval Workflow

### Step 1: Submit for Approval

In the policy version editor, click **Submit for Approval**. The system automatically:
- Evaluates high-risk patterns (broad source ranges, ALL_INTERFACES scope, sensitive ports)
- Flags the version as high-risk if applicable
- Changes status from DRAFT to PENDING_APPROVAL

### Step 2: Review and Approve

Go to **Approvals** in the sidebar. Reviewers can:
- View the full rule list
- See the **Impact Analysis** (semantic diff showing new allows, removed allows, new denies, removed denies per host)
- **Approve** or **Reject** with a reason

### Approval Constraints

- The approver must be a different user than the creator (separation of duties)
- High-risk policies require a different approver even if the creator is an admin
- Only users with `approver` or `admin` roles can approve

---

## 9. Deploying Policies

### Step 1: Create a Deployment

Go to **Deployments** and click **+ New Deployment**:

1. **Policy Version:** Select an APPROVED version
2. **Deployment Mode:**
   - `FULL` — all target hosts at once
   - `CANARY` — small subset first (mode stored; currently processes all hosts)
   - `PROGRESSIVE` — deploy in batches (mode stored; currently processes all hosts)
3. **Target Selection:** The hosts are determined by the policy set's scope (tag/VLAN/host list)
4. **Scheduled At:** (optional) Schedule for a future time (e.g., maintenance window)

### Step 2: Safety Check

Before deployment starts, Segmentra automatically:
- Compiles the policy for each target host
- Checks that SSH access from the management VLAN is preserved in the compiled ruleset
- In **FULL mode**: blocks deployment if SSH access would be lost
- In **CANARY/PROGRESSIVE**: warns but allows deployment

### Step 3: Start the Deployment

Click **Start**. Depending on your configured executor, one of two paths executes:

---

## 10. How SSH Direct Deployment Works

When the executor is set to **SSH Direct**, Segmentra connects to each host individually using SSH/SCP from the API server.

### What Happens on Each Host (Step by Step)

```
Segmentra API Server                         Target Host
─────────────────────                         ───────────

1. ssh → sudo mkdir -p /var/backups/segmentra ────────► Create backup dir (mode 0700)

2. ssh → command -v nft                       ────────► Detect firewall backend
   ◄──── "nft" or "iptables"

3. ssh → sudo nft list ruleset >              ────────► Backup current rules
         /var/backups/segmentra/                         to timestamped file
         nft.ruleset.20260316143025

4. scp → compiled.nft ──────────────────────► ────────► Copy policy file
         /tmp/segmentra.policy                           to /tmp/

5. ssh → sudo mv /tmp/segmentra.policy        ────────► Move to /etc/segmentra.policy
         /etc/segmentra.policy                           (mode 0600)
         sudo chmod 600 /etc/segmentra.policy

6. ssh → sudo nft -f /etc/segmentra.policy    ────────► Apply nftables rules
   (or)  sudo iptables-restore <                        (or iptables-restore)
         /etc/segmentra.policy

   If step 6 FAILS:
7. ssh → sudo nft -f <latest backup>          ────────► Automatic rollback
         (or iptables-restore < backup)                  to previous rules
```

### Key Details

- **Sequential execution**: Hosts are processed one at a time
- **SSH options**: `StrictHostKeyChecking=no`, `UserKnownHostsFile=/dev/null` (to avoid interactive prompts)
- **All commands use `sudo`**: The SSH user doesn't need to be root
- **Backend mismatch detection**: If the host has nftables but the policy was compiled for iptables (or vice versa), the deployment fails for that host before applying
- **Automatic rollback**: If `nft -f` or `iptables-restore` fails, the latest backup is automatically restored
- **Timeout**: Hosts that don't respond within 10 minutes are marked as FAILED by a background job

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
│     - ssh_key (0600)             │
│     - host_rules/*.nft           │
│  3. Execute:                     │
│     docker exec                  │
│       segmentra-ansible-runner   │
│       ansible-playbook           │
│       -i /bundles/.../inv.ini    │
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
│  - Reads host_rules/*.nft        │
│  - Uses SSH key from bundle      │
│  - Runs playbook on all hosts    │
│    (parallel by default)         │
│                                  │
│  For each host:                  │
│    1. Create backup dir          │
│    2. Detect nft vs iptables     │
│    3. Backup current rules       │
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
├── inventory.ini          # Ansible inventory with per-host variables
├── ssh_key                # SSH private key (0600 permissions)
├── manifest.json          # Deployment metadata
├── ansible.stdout.log     # Ansible stdout (written during execution)
├── ansible.stderr.log     # Ansible stderr
└── host_rules/
    ├── webserver01.nft    # Compiled nftables policy for webserver01
    ├── webserver02.nft    # Compiled nftables policy for webserver02
    └── dbserver01.iptables # Compiled iptables policy for dbserver01
```

### Generated Inventory File

```ini
[all]
webserver01 ansible_host=10.0.1.10 ansible_port=22 ansible_user=segmentra ansible_ssh_private_key_file=/bundles/abc123/ssh_key ansible_become=yes ansible_become_method=sudo segmentra_policy_file=/bundles/abc123/host_rules/webserver01.nft
webserver02 ansible_host=10.0.1.11 ansible_port=22 ansible_user=segmentra ansible_ssh_private_key_file=/bundles/abc123/ssh_key ansible_become=yes ansible_become_method=sudo segmentra_policy_file=/bundles/abc123/host_rules/webserver02.nft
dbserver01 ansible_host=10.0.2.10 ansible_port=2222 ansible_user=segmentra ansible_ssh_private_key_file=/bundles/abc123/ssh_key ansible_become=yes ansible_become_method=sudo segmentra_policy_file=/bundles/abc123/host_rules/dbserver01.iptables
```

### What the Playbook Does

The playbook (`infra/ansible-runner/playbooks/apply-firewall.yml`) runs these tasks on each host:

1. **Generate timestamp** for backup filenames
2. **Create backup directory** (`/var/backups/segmentra`, mode 0700)
3. **Detect firewall backend** (`command -v nft`)
4. **Backup current rules** (nft list ruleset or iptables-save to timestamped file)
5. **Validate policy file** (fail early if not provided)
6. **Copy policy file** to `/etc/segmentra.policy` (mode 0600)
7. **Detect backend mismatch** (fail if .nft file on iptables host or vice versa)
8. **Apply rules** (`nft -f` or `iptables-restore`)
9. **On failure: rollback** from latest backup and fail with error message

### Ansible Pros and Cons

| Pros | Cons |
|------|------|
| Parallel execution across hosts | Requires Docker container |
| Better error handling | Requires Docker socket access |
| Built-in rollback block/rescue | More complex setup |
| Industry-standard tooling | Slightly slower startup |
| Detailed per-host reporting | |

---

## 12. Firewall Learning (Traffic Discovery)

Firewall Learning discovers what traffic actually flows to/from a server, so you can write accurate policies without guessing.

### How It Works (Agentless)

The key insight: **the Linux kernel is the sensor**. Every Linux server has netfilter built in. Segmentra SSHes in and temporarily reconfigures it to log-everything/block-nothing mode.

### Step-by-Step

1. Go to **Troubleshoot** in the sidebar
2. Scroll to **Firewall Learning**
3. Select one or more hosts
4. Set the duration (e.g., 60 minutes)
5. Click **Start Audit**

### What Happens on the Host

```
Time 0:00  ─── Segmentra SSHes into the host
               1. Backup current rules:
                  sudo nft list ruleset > /var/backups/segmentra/nft.audit-backup.<ts>

               2. Configure rsyslog:
                  Create /etc/rsyslog.d/99-segmentra-audit.conf
                  Route "FW-AUDIT" kernel messages to /var/log/segmentra-audit-<host>-<ts>.log
                  Reload rsyslog

               3. Deploy log-only rules:
                  table inet segmentra_audit {
                    chain input {
                      type filter hook input priority 0; policy accept;
                      log prefix "FW-AUDIT: IN "
                    }
                    chain output {
                      type filter hook output priority 0; policy accept;
                      log prefix "FW-AUDIT: OUT "
                    }
                  }

               Result: ALL traffic is logged, NOTHING is blocked

Time 0:01-0:59 ─── Normal traffic flows, kernel logs every packet:

               FW-AUDIT: IN SRC=10.0.1.50 DST=10.0.2.10 PROTO=TCP SPT=44312 DPT=443
               FW-AUDIT: OUT SRC=10.0.2.10 DST=10.0.1.100 PROTO=TCP SPT=38221 DPT=5432
               FW-AUDIT: IN SRC=10.0.3.5 DST=10.0.2.10 PROTO=UDP SPT=12345 DPT=53
               ...

Time 1:00  ─── Background job detects session expired
               1. SSH in and restore original rules:
                  sudo nft -f /var/backups/segmentra/nft.audit-backup.<ts>

               2. Retrieve log file via SCP

               3. Clean up rsyslog config:
                  sudo rm /etc/rsyslog.d/99-segmentra-audit.conf
                  sudo systemctl reload rsyslog

               4. Parse logs into structured flows:
                  10.0.1.50 → 10.0.2.10 : TCP/443   (1,247 packets, IN)
                  10.0.2.10 → 10.0.1.100 : TCP/5432  (892 packets, OUT)
                  10.0.3.5  → 10.0.2.10 : UDP/53     (156 packets, IN)
```

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

In the Troubleshoot page, after viewing audit results, click **Generate Recommendations** (or use the Recommendations page).

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

Review each recommendation individually. Accepted recommendations can then be applied as a DRAFT policy version that goes through normal approval workflow.

---

## 14. On-Device Policy Testing

Test a specific policy against real traffic before enforcing it.

### Step 1: Start a Policy Test

Go to **Policy Testing** in the sidebar:
1. Click **+ Start Policy Test**
2. Select a **Policy Version** (any status — doesn't need to be APPROVED)
3. Select a **Target Host**
4. Set **Duration** (e.g., 30 minutes)

### Step 2: What Happens

The system deploys the policy in log-only mode (same mechanism as firewall learning), then compares observed traffic against the policy rules.

### Step 3: Analyze Results

Click **Analyze** after the test completes. The analysis shows:

| Category | Meaning | Color |
|----------|---------|-------|
| **Matched Flows** | Traffic that matches an ALLOW rule — expected | Green |
| **Unexpected Blocks** | Traffic that matches a DENY rule but was actively flowing — would break things | Red |
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

### Policy Lookup

- **Search by IP**: Find all policy rules that reference a specific IP address
- **Host Policies**: View all policies deployed to a specific host
- **Policy Version Hosts**: See which hosts have a specific policy version deployed

---

## 16. Compliance & Drift Detection

Detect when hosts have been manually modified after a deployment.

### How It Works

1. When Segmentra deploys a policy, it stores the SHA-256 hash of the compiled ruleset
2. The compliance check SSHes into the host and reads current rules (`nft list ruleset` or `iptables-save`)
3. It hashes the current rules and compares to the stored hash
4. Status: **Compliant** (match), **Drifted** (mismatch), **Unknown** (never deployed), or **Error** (SSH failure)

### Using Compliance Checks

- **Per-host**: In Inventory, click the compliance check button on a host
- **Bulk**: Select multiple hosts and click **Bulk Compliance Check**
- **API**: `GET /api/compliance/hosts/:hostId` or `POST /api/compliance/hosts/bulk`

---

## 17. Integrations

Connect Segmentra to external security tools.

### Setting Up an Integration

Go to **Integrations** in the sidebar:

1. Click **+ New Integration**
2. Select **Type**: SIEM, SOAR, Vulnerability DB, or Threat Intelligence
3. Enter **Provider** (e.g., Splunk, QRadar, Tenable, MISP)
4. Configure connection details in the **Config JSON**
5. Optionally link to encrypted **Credentials** from the secret store

### Integration Types

| Type | What It Does |
|------|-------------|
| **SIEM** | Forwards audit events to your SIEM via syslog/webhook |
| **SOAR** | Exposes actions (isolate host, apply emergency policy) via inbound webhooks |
| **Vulnerability DB** | Polls vulnerability scanner API, tracks CVEs per host |
| **Threat Intelligence** | Polls threat feeds, maintains IP/CIDR blocklists with confidence scores |

### Testing & Syncing

- **Test**: Verify connectivity to the integration endpoint
- **Sync**: Trigger a manual data sync
- **Events**: View the event log showing all sync and webhook operations

---

## 18. Kubernetes Microsegmentation

Manage Kubernetes NetworkPolicy resources agentlessly via the K8s API.

### Step 1: Add a Cluster

Go to **Kubernetes** in the sidebar:
1. Click **+ Add Cluster**
2. Enter the **API Server URL** (e.g., `https://k8s-api.example.com:6443`)
3. Select **Auth Type**: Kubeconfig, Service Account, or Bearer Token
4. Store credentials in the secret store

### Step 2: Sync Workloads

Click **Sync** to discover namespaces, pods, deployments, services, and their labels.

### Step 3: Map Labels to Tags

Map Kubernetes labels to Segmentra tags for unified policy management. For example, `app=nginx` K8s label → `web-server` Segmentra tag.

### Step 4: Deploy NetworkPolicy

Create a Segmentra policy set, get it approved, then deploy it as a Kubernetes NetworkPolicy:
1. Select the cluster and namespace
2. The system translates Segmentra rules into K8s NetworkPolicy manifest JSON
3. The policy is applied via the K8s API (not via Ansible/SSH)

---

## 19. OT/IoT Microsegmentation

Manage devices that can't run agents — PLCs, HMIs, sensors, cameras, medical devices, etc.

### Step 1: Add IoT Assets

Go to **OT/IoT** in the sidebar:
1. Click **+ Add Asset**
2. Enter device details: name, type (PLC/HMI/sensor/camera/etc.), vendor, model, IP, MAC, VLAN, Purdue zone, criticality level

### Step 2: (Optional) Configure Flow Collectors

Switch to the **Flow Collectors** tab to set up passive traffic collection:
- Configure NetFlow v5/v9, sFlow, or IPFIX collectors
- Set listen address and port
- Observed flows are stored and visible per asset

### Step 3: Configure Enforcement Points

Switch to the **Enforcement Points** tab:
1. Add managed switches or gateway firewalls
2. Specify vendor (Cisco, Juniper, Arista, etc.), management IP, and SSH credentials
3. Deploy ACLs to enforce policies on behalf of unmanaged IoT devices

### Step 4: Baseline Traffic

Select an asset and click **Baseline** to snapshot its current traffic pattern. This captures all observed flows as the "known good" state for future comparison.

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
   - **Notify Only** — sends alert, rules stay active (default)
   - **Remove** — auto-rollback firewall rules on all hosts
   - **Revert** — re-deploy the previous policy version

### What Happens Automatically

- **24 hours before expiry**: A `POLICY_EXPIRING_SOON` notification is sent to subscribed channels
- **At expiry**: The deployment is marked expired, `POLICY_EXPIRED` notification sent, and the chosen action is executed
- **Audit trail**: Both the warning and expiry are logged in audit events

---

## 21. Notifications

### Setting Up

1. Go to **Notifications** in the sidebar
2. Click **+ New Channel** and choose:
   - **Slack** — provide a webhook URL
   - **Webhook** — provide an endpoint URL and optional auth header
   - **Email** — provide SMTP settings and recipient
3. Click **Send Test** to verify connectivity
4. Add **Event Subscriptions** — choose which events trigger notifications on this channel

### Example Configuration

**Slack channel for operations:**
- Subscribe to: DEPLOYMENT_STARTED, DEPLOYMENT_COMPLETED, DEPLOYMENT_FAILED

**Webhook to SIEM:**
- Subscribe to: POLICY_APPROVED, POLICY_EXPIRED, EXCESSIVE_RULES_DETECTED

**Email to security team:**
- Subscribe to: POLICY_EXPIRING_SOON, COMPLIANCE_DRIFT, EXCESSIVE_RULES_DETECTED

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
| SSH open to 0.0.0.0/0 | Critical | Port 22 ALLOW from any source |
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
| **Expired audit sessions** | 1 min | Auto-restores firewall rules when learning sessions expire |
| **Tag rule evaluation** | 5 min | Re-evaluates all enabled auto-tagging rules against hosts |
| **Policy test expiry** | 1 min | Auto-stops test sessions past their scheduled end time |
| **Deployment expiry** | 1 min | Processes expired deployments, sends 24h expiry warnings |

These jobs run as `setInterval` callbacks in the API process — no external scheduler needed.

---

## Quick Reference: Deployment Executor Comparison

| Feature | SSH Direct | Ansible |
|---------|-----------|---------|
| **Execution** | Sequential (one host at a time) | Parallel (all hosts simultaneously) |
| **Connection** | Direct SSH from API server | Docker exec → Ansible → SSH to hosts |
| **Dependencies** | `ssh` + `scp` commands | Docker container + Docker socket |
| **Rollback** | Manual (restore from backup) | Block/rescue (automatic) |
| **Logging** | Combined stdout/stderr files | Ansible-format logs |
| **Setup** | Minimal | Requires `segmentra-ansible-runner` container |
| **Best for** | Small fleets, simple environments | Large fleets, production environments |

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
```

---

## Quick Reference: What Happens on a Target Host

```
Before Segmentra:                After Segmentra:
─────────────────                ────────────────

No rules / unknown rules    →    /etc/segmentra.policy (compiled rules)
No backups                  →    /var/backups/segmentra/
                                   nft.ruleset.20260316143025
                                   nft.ruleset.20260315090000
                                   ... (timestamped backups)
```

**Files created on target hosts:**
- `/etc/segmentra.policy` — Current active policy (0600)
- `/var/backups/segmentra/` — Backup directory (0700)
- `/var/backups/segmentra/nft.ruleset.<timestamp>` — nftables backups
- `/var/backups/segmentra/iptables.<timestamp>` — iptables backups
- `/var/log/segmentra-audit-<host>-<ts>.log` — Firewall learning logs (temporary, during audit sessions only)
- `/etc/rsyslog.d/99-segmentra-audit.conf` — Rsyslog config (temporary, during audit sessions only)
