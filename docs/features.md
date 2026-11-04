# Features and capabilities

What Segmentra can do, by area. For the order you use them in, see [How Segmentra works](how-it-works.md); for pictures, see the [Screenshots](screenshots.md). What has and has not been tested is in [Status and limitations](testing-status.md).

## Contents

- [Authentication & Authorization](#authentication--authorization)
- [Inventory Management](#inventory-management)
- [Policy Management](#policy-management)
- [Approvals and Separation of Duties](#approvals-and-separation-of-duties)
- [Deployment Management](#deployment-management)
- [Traffic Learning, Policy Testing and Firewall Logs](#traffic-learning-policy-testing-and-firewall-logs)
- [Troubleshooting & Analysis](#troubleshooting--analysis)
- [OT/IoT Microsegmentation](#otiot-microsegmentation)
- [Kubernetes Microsegmentation](#kubernetes-microsegmentation)
- [Policy as Code](#policy-as-code)
- [Compliance Evidence Reports](#compliance-evidence-reports)
- [Docker Swarm and Docker-published ports](#docker-swarm-and-docker-published-ports)
- [Audit Trail](#audit-trail)
- [Security & Compliance](#security--compliance)
- [Backup & Restore](#backup--restore)
- [Dashboard](#dashboard)
- [Topology](#topology)
- [Integrations](#integrations)

## Authentication & Authorization
- **LDAP/Active Directory Integration** with AD group-to-role mapping (group DNs are matched case- and whitespace-insensitively; LDAP users' passwords can't be reset in Segmentra)
- **Local User Management** — create, edit, disable, and reset passwords for local users directly in the Admin UI (no LDAP required for small teams)
- **Role-Based Access Control (RBAC)** enforced at both API and UI level:
  - **Viewer** — read-only access to all dashboards, inventory, policies, and deployments
  - **Operator** — manage inventory, create policies/rules, run deployments, troubleshoot, manage IoT assets
  - **Approver** — approve/reject policy versions (separation of duties — cannot create policies)
  - **Admin** — full access including users, LDAP, SSH credentials, integrations, notifications, and system settings
- **JWT Authentication** — stateless tokens in browser localStorage, sent as `Authorization: Bearer <token>`
- **Separation of Duties** — a policy version cannot be approved by the user who created, edited or submitted it; high-risk policies require a different approver even for admins

## Inventory Management
- **Host Management** — add Linux servers with management IPs, SSH ports, firewall backend selection (nftables/iptables/firewalld/ufw/auto)
- **Tags & VLANs** — organize hosts by custom tags and VLAN membership; VLANs also serve as OT/IoT zones. A tag or VLAN that policy or template rules still reference can't be deleted
- **Auto-Tagging Rule Engine** — define criteria (hostname regex, CIDR ranges, OS family, VLAN, existing tags) with AND/OR logic to automatically classify hosts; evaluates every 5 minutes and on-demand
- **Automated Discovery** — discovery profiles scan IPv4 networks (CIDRs and/or VLAN subnets, max /20 per network and 8192 addresses per run) for SSH, log in with existing or new SSH credentials (read-only fact collection: hostname, OS, nft/iptables, sudo) and import new hosts with a default tag (`new-server`); manual **Run Now** or on a schedule, with per-address run history
- **System Tags** — `iot-gateway` and `bastion` are protected tags that cannot be deleted
- **Interface Configuration** — define network interfaces with roles (data, management, backup, etc.)
- **Bulk Operations** — CSV import, bulk tag/VLAN assignment, bulk enable/disable
- **Host Readiness Check** — detect active firewall managers and verify firewall tools, sudo access, and reboot persistence before deployment
- **Native Firewall Managers** — persistent firewalld policy objects and UFW custom-rule blocks, loaded by the native boot service without a Segmentra agent. Persistence failure fails native-manager deployment. See [requirements and limits](firewall-managers.md).
- **Compliance & Drift Detection** (agentless) — SSH-based comparison of current firewall rules vs. last deployed policy hash
- **Policy Visualization** — interactive SVG diagrams showing connections per host (color-coded allow/deny)
- **Active Rules per host** — one click on a host shows the policy set and version enforced on it, its access-control rules in plain language (tags, VLANs, hosts and IoT assets resolved to names), the drift status, and for operators the live nftables/iptables ruleset read from the host side by side with the ruleset Segmentra expects; older deployments are listed as history

Supported Linux backends are **nftables, iptables, firewalld, and UFW**. Select one in Inventory or use `auto`, which prefers an active native manager. Firewalld/UFW support enforced ACL deployment, removal, rollback, IPv4/IPv6, and drift/compliance. Native learning/log-only sessions are not yet supported.

## Policy Management
- **Policy Sets** — organize rules by scope (TAG, VLAN, or HOST_LIST)
- **Version Control** — every change creates a new version with the lifecycle DRAFT → PENDING_APPROVAL → APPROVED / REJECTED → DEPLOYED; approved, deployed and pending versions can be ARCHIVED
- **Immutable versions** — a version's rules can only be edited while it is DRAFT or REJECTED. From the moment it is submitted for approval it is read-only, so what was approved is exactly what gets deployed. To change an approved or deployed policy, create a new version (**+ New Version** or **Clone**), which needs its own approval
- **Policy Templates** — reusable blueprints (e.g., "Web Server") with one-click instantiation; optional auto-apply creates a DRAFT policy when a matching tag is first assigned to hosts
- **Visual Topology Design** — draw network flows between groups, auto-discover from existing infrastructure, and generate policies automatically
- **Policy as Code** — policy sets as YAML/JSON documents (tags, VLANs, hosts by name) that can be exported, reviewed in Git and imported again; imports only ever create DRAFT versions. See [Policy as Code](#policy-as-code) below
- **Policy Impact Analysis** — semantic diff showing new/removed allows and denies per host before approval
- **High-Risk Detection** — audit policies to flag broad rules, wide scopes, and sensitive port exposure
- **Policy Expiry** — optional time-limited deployments with 24-hour warnings. On expiry the deployment is marked `EXPIRED`, a notification is sent and the expiry action runs: `NOTIFY_ONLY` does nothing else, `REMOVE` removes Segmentra's rules (`table inet segmentra` or the `SEGMENTRA-*` chains) from the hosts, and `REVERT` redeploys the previous successfully deployed version of the same policy set (tested end to end with `npm run test:integration:expiry`; see [what is not covered](testing-status.md#not-tested-yet))
- **Policy Archive & Delete** — archive deployed/approved versions (read-only), delete DRAFT/REJECTED versions

## Approvals and Separation of Duties
- **Approval before deployment** — only `APPROVED` versions (or `DEPLOYED` ones, already approved) can be deployed; a DRAFT, pending or rejected version is refused
- **A different person must approve** — the approver needs the `approver` or `admin` role and must not have created, edited or submitted the version. This applies to admins too, so an installation needs at least two people who can approve
- **Reason and decision on record** — the author can give a reason when submitting, and the reviewer sees it next to the rules, with an optional impact analysis against an earlier version. A rejection needs a reason; the author can then fix and resubmit the version
- **Second approval for high-risk deployments** — a deployment flagged as high-risk also needs approval from an `approver` or `admin` other than the person who created it
- **Imports cannot bypass it** — policy-as-code imports only create DRAFT versions, and versions restored from a backup need re-approval

## Deployment Management
- **Deployment Modes** — Full, Canary, and Progressive. With the SSH Direct executor hosts are deployed one at a time in hostname order: Canary stops if one of the first *N* canary hosts (default 1) fails, Progressive stops at the end of a batch (default 5 hosts) that had a failure; halted hosts are marked skipped and can be resumed with **Retry Failed Hosts**. The Ansible executor deploys all target hosts in one playbook run
- **Scheduled Deployments** — schedule for future execution (e.g., maintenance windows); auto-starts via background job
- **Two Executors** — Ansible (parallel, recommended) or SSH Direct (lightweight, no Ansible dependency)
- **Compulsory readiness check** — before a host's first policy, Segmentra checks that it can take one: SSH login, sudo, the firewall tools and whether rules would survive a reboot. A host that fails stops the start, with nothing deployed. If rules would be lost on reboot, someone has to accept that first, and it is recorded in the audit log. Scheduled deployments cannot ask, so they fail on a host that is not ready, and record the reboot note and continue. **Check Readiness** in the Inventory still runs the same check at any time
- **Safety Guardrails** — pre-deployment validation ensures SSH access from management VLAN is preserved
- **Automatic Rollback** — failed deployments restore previous state from host-local backups
- **Real-time Tracking** — per-host deployment status with 10-minute timeout for unresponsive hosts; **Retry Failed Hosts**, pause/resume/stop, and a deployment-level approval for high-risk deployments
- **Lockout protection** — after applying rules Segmentra checks that it can still reach the host over SSH; if not, the previous rules are restored automatically after 120 seconds

## Traffic Learning, Policy Testing and Firewall Logs
- **Firewall Learning** (agentless) — find out what a server actually communicates with before writing its policy. Over SSH, Segmentra temporarily puts the host in log-only mode: every packet is logged and accepted, so nothing is blocked. When the chosen time is up (or you cancel), the original rules are restored automatically and the log is turned into communication flows with packet counts
- **Policy Recommendations** — after firewall learning, generate rules from observed traffic with confidence scoring and IP-to-tag resolution; accepted ones become a DRAFT version. API only for now, there is no page in the UI
- **Policy Testing** (*Policy Impact Analysis* page) — try a specific policy version on a real host against real traffic before enforcing it. It also runs in log-only mode for 1 to 1440 minutes (default 30), then restores the original rules. The analysis shows which flows match an ALLOW rule, which hit a DENY rule and which match nothing and would be dropped by the default deny, with a coverage percentage
- **Peek at Logs** (*Inventory → Actions*, operator or admin) — read a host's newest firewall log lines over SSH for troubleshooting, up to 1000 at a time, with filters for direction, protocol, source and destination. Read-only: nothing changes on the host. Lines come from rules with logging on, the default deny and log-only sessions
- **Limits** — learning and policy tests run one at a time per host, on the raw nftables and iptables backends only (firewalld and UFW sessions are refused without changing the rules), and do not cover Docker-published ports. On firewalld and UFW, default-deny logging follows the manager's own settings

## Troubleshooting & Analysis
- **Communication Simulation** — test if traffic between two IPs would be blocked by deployed policies
- **Policy Search** — find which policies apply to a specific IP, host, or policy version

## OT/IoT Microsegmentation
- **Separate Asset Inventory** — register PLCs, HMIs, sensors, cameras, HVAC, medical devices with vendor/model/firmware/criticality metadata
- **Gateway Model** — IoT devices are assigned to gateway firewalls (regular Linux hosts tagged `iot-gateway` in the inventory); policies deploy to gateways via the normal SSH/Ansible pipeline
- **VLANs as Zones** — OT network zones (Purdue levels) are defined as VLANs in the inventory
- **Traffic Discovery** — run Firewall Learning on the gateway host to observe IoT traffic passively
- **Deployment Warning** — deploying to IoT gateways triggers a warning about impact on protected devices
- **Protocol Catalog** — 30 OT/IoT services (Modbus/TCP, DNP3, EtherNet/IP, S7, OPC UA, BACnet, MQTT, ...) with default ports and a cleartext/encrypted flag; pick one in the rule form or write `service: modbus-tcp` in a policy document. Port matching only, no deep inspection
- **Protection Coverage** — shows which assets are protected, by which gateway and which services are allowed to reach them (zones, cleartext warnings); it is derived from recorded deployments, not a live check
- **Discovery** — lists devices from a gateway's ARP/NDP table over SSH (passive: nothing is sent to the devices) and, as an explicit opt-in with a warning, probes a subnet of up to a /24 from the gateway with one ICMP echo per address to find quiet devices, with vendors from an IEEE OUI list you import, and imports them as assets
- **Compliance integration** — IoT coverage appears in the compliance reports

**Not tested yet:** the full IEEE OUI file, real PLCs and cameras, IPv6-only neighbours. **Not supported yet:** deep protocol inspection, flow ingestion, port scanning or fingerprinting of devices. The active probe was only tested on a Docker bridge. See the [OT/IoT guide](iot.md#8-industrial-protocols-coverage-and-discovery).

## Kubernetes Microsegmentation

Segmentra turns approved policy versions into Kubernetes **NetworkPolicy** manifests (Ingress only) and, with stored cluster credentials, applies, checks and removes them. It only touches policies it created, supports kubeconfig, token and EKS/GKE/AKS logins, and can use tags mapped to pod labels as sources. Capabilities, limitations and what has not been tested are in the [Kubernetes Guide](kubernetes.md).

## Policy as Code

Policy sets can be written, reviewed and applied as **YAML or JSON documents** that refer to tags, VLANs, hosts and IoT assets by name, so they can live in Git and move between instances. An import is a plan/apply operation that only ever creates a **DRAFT**: approval and deployment stay in Segmentra. There is a CLI for CI (`scripts/segmentra-policy.mjs`). See the [Policy as Code Guide](policy-as-code.md).

## Compliance Evidence Reports

A **point-in-time evidence report** for an assessor, mapped to controls of **PCI DSS v4.0, ISO/IEC 27001:2022, SOC 2 and the HIPAA Security Rule**, stored with a SHA-256 and available as JSON, printable HTML or CSV. It is evidence from the data Segmentra holds, not an audit opinion or a certification. See the [Compliance Reports Guide](compliance-reports.md).

## Docker Swarm and Docker-published ports

A Swarm node is an ordinary Linux server, so Segmentra manages its **host firewall over SSH**. It adds two things: the cluster ports are always allowed between the registered nodes of a swarm, and inbound rules can optionally apply to Docker-published ports and the routing mesh, which otherwise bypass the host firewall. It does not talk to the Docker daemon and does not manage overlay or container-to-container traffic. See the [Docker Swarm Guide](docker-swarm.md).

## Audit Trail
- **Who did what, where and when** — every change is recorded with the actor, time, IP address and details. Deployments record who created, approved, started or cancelled them, the policy set and version, the target hosts, tags and VLANs, the mode and the result
- **Approval history** — each submission, approval and rejection records who created the version, who requested approval and why, who decided and when, and the reason for a rejection
- **Search it** (*Audit Log* page, every role) — filter by user, action, entity type and date range
- **Send it elsewhere** — forward every entry to a SIEM over syslog (see [Integrations](#integrations)), and use it as evidence in [compliance reports](compliance-reports.md)
- **No edit or delete function** — Segmentra offers no way to change or remove entries. Someone with direct database access still could, so forward the log to a SIEM if it must resist that

## Security & Compliance
- **Security Posture Audit** — on-demand scan of all deployed policies for excessive permissions (8 categories: sensitive port open to any, all ports open to any, very broad source CIDRs, any-protocol / any-port rules, `ALL_INTERFACES` with a broad source, duplicate rules, unmanaged hosts, stale policies)
- **Notification System** (*Notifications* page, admin to configure) — create a channel (Slack incoming webhook or generic HTTP webhook), choose which events it receives, and use **Send Test** to send a sample. Approval events carry the approval trail (who requested, the author's reason, when, who decided, the rejection reason), so a reviewer or author can be alerted without opening the app. Webhook targets on loopback or link-local/cloud-metadata addresses are refused unless `SEGMENTRA_ALLOW_PRIVATE_WEBHOOKS=true`. Supported: Slack webhooks and generic HTTP webhooks (email channels are not implemented: there is no SMTP support and sends are logged as failed); subscribe channels to 11 event types (policy submitted/approved/rejected, deployment started/completed/failed, policy expiring soon/expired, excessive rules detected, firewall-learning restore failed, compliance drift). The compliance-drift event can be selected but is not emitted yet, and the optional per-rule `filter` is stored but not applied
- **Encrypted Secret Storage** — SSH keys, key passphrases, SSH and sudo passwords and LDAP passwords encrypted with AES-256-GCM (key: `SEGMENTRA_KEK_B64`); see [docs/security.md](security.md)
- **Integrations** — registry for SIEM, SOAR, vulnerability databases and threat intelligence feeds. Working adapters: **SIEM** (syslog over UDP/TCP; every Audit Log entry is forwarded once, see [docs/security.md](security.md)) and **AbuseIPDB** threat intelligence (sync, optional auto-block into a DRAFT version of a policy set; repeated syncs reuse the open auto-block draft and skip IPs already blocked). SOAR and vulnerability-database entries only store configuration and sync status.

## Backup & Restore

The **configuration backup** (Admin → Backup & Restore) is a JSON file that restores into any installation, including a fresh one. The **full database dump** (`scripts/segmentra-backup.sh`) is for routine backups of a production install. See [Backup and restore](backup-restore.md).

## Dashboard
- **Real-time Overview** — deployment status, success rates, activity charts
- **Current Deployments** — live progress tracking with per-host status
- **Top Deployers** — most active users

## Topology

Draw the allowed and denied flows between tags, VLANs and hosts on a canvas and generate policy sets from the drawing. Still work in progress.

## Integrations

Webhooks, SIEM forwarding of the audit log, threat-intelligence feeds and LDAP. See the Integrations and Admin pages.
