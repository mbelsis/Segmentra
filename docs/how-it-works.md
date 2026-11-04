# How Segmentra works

An overview of the path from an empty installation to enforced firewall rules. For every screen and option in detail, see the [User Guide](guide.md); for what each feature can do, see [Features](features.md).

## The whole flow

Segmentra never changes a firewall on its own. Every change goes through the same path, and **nothing is deployed automatically after an approval**: a person has to create and start the deployment (or schedule it).

```
1 Build the inventory  ->  2 Policy set + scope  ->  3 Version + rules  ->  4 Approval  ->  5 Deployment  ->  6 Verify & operate
```

**1. Build your inventory** (*Inventory*, *OT/IoT*, *Kubernetes*)
- **Linux servers:** add hosts by hand, **Bulk Import** a CSV, or let **Discovery** scan your networks for SSH and import what it finds. Group them with **tags** (also automatic, with **Auto-Tagging** rules) and **VLANs**. **Check Readiness** confirms Segmentra can log in, use sudo and find the firewall tool.
- **OT/IoT devices:** pick a Linux host that sits in front of the devices, tag it `iot-gateway`, then open **OT/IoT**: register the devices by hand, or use the **Discovery** tab to list what the gateway sees (its ARP table, optionally an active ping probe of a subnet) and import the devices. Assign each device to its gateway. The devices themselves are never touched; the gateway firewall protects them. See [docs/iot.md](iot.md).
- **Docker Swarm:** give every node of the swarm the same **Swarm name** in the Docker section of its host form; the **Docker Swarm** page (with a how-to) shows the nodes and warns about gaps. See [docs/docker-swarm.md](docker-swarm.md).
- **Kubernetes:** register each cluster under **Kubernetes** with its CNI and credentials, and optionally map workloads (pod labels) to tags. See [docs/kubernetes.md](kubernetes.md).

**2. Create a policy set and choose its scope** (*Policy Sets*)
A policy set decides **where** its rules apply: all hosts with certain **tags**, hosts in a **VLAN**, or a **specific list of hosts**. You can start from scratch, from a **Template** (a reusable rule set such as "Web Server"; a template with auto-apply creates a DRAFT policy when its tag is first assigned), from the **Topology** page (draw flows between groups and generate a draft policy from them), from recommendations after **Firewall Learning**, or from a YAML file ([Policy as Code](policy-as-code.md)). All of these only ever produce a `DRAFT`.

**3. Add rules to a version** (*Policy Sets → New Version*)
Each change is a new version. Add allow/deny rules (direction, protocol, ports, source; on gateways also FORWARD rules with a destination or IoT device). Before asking for approval you can check the effect with **Policy Impact Analysis**, **Troubleshoot** (would this traffic be allowed?) and the **Security Audit** for risky rules.

**4. Request approval** (*Submit for Approval*, then *Approvals*)
The author submits the version with an optional reason; it becomes `PENDING_APPROVAL` and read-only. A second person with the `approver` or `admin` role (never the author) reviews the rules and either approves or rejects with a reason. A rejected version is fixed and resubmitted; the author sees the outcome on the Dashboard and next to the policy set. Everything is written to the audit log, and the **notification channels** (Slack or webhook) can alert reviewers and authors.

**5. Deploy it: a separate, manual step** (*Deployments*)
After approval the version is only `APPROVED`; no rule is on any host yet. An operator or admin then:
1. opens **Deployments → + Create Deployment** and selects the approved version, the target hosts and a mode (**Full**, **Canary** to try a few hosts first, or **Progressive** in batches);
2. optionally **schedules** it for a maintenance window (it then starts by itself at that time) and sets an **expiry** (notify only, remove the rules, or revert to the previous version);
3. clicks **Start** (high-risk deployments first need a second person's deployment approval).

Segmentra backs up each host, applies the rules over SSH or Ansible, checks it can still reach the host (and rolls back if not), and records the result per host. The version then becomes `DEPLOYED`. For **IoT gateways** this is the same flow: their policy set is deployed to the gateway. For **Kubernetes**, open the approved version and **Generate NetworkPolicy**, then **Apply** it to a cluster (also a manual step); Segmentra can check and remove what it applied.

**6. Verify and operate**
**Active Rules** shows, per host, the policy version and rules enforced right now, its drift status and the live ruleset next to the expected one; **Check Compliance** finds rules changed by hand on a host (drift), **View Visualization** draws what a host allows, **Firewall Learning** and **Policy Impact Analysis** observe real traffic, and the **Audit Log**, **Compliance Report**, **Notifications** and **Integrations** (SIEM) give you the trail and the alerts. Details of every step, with roles, are in the [User Journey](#user-journey).

---

## User journey

This is the typical path from an empty installation to enforced firewall rules. Each step names the page in the left-hand menu and the role needed.

### 1. One-time setup (Admin, `admin` role)

- **Deployment executor:** choose **SSH Direct** (lightweight) or **Ansible** (needs the runner container).
- **SSH credentials:** add the account Segmentra uses to reach your hosts, with a private key (optionally passphrase-protected) or a password, and choose how it becomes root: **sudo without password**, **sudo with the login password**, or **sudo with a separate password**. The account needs full sudo rights (it runs `sh` as root); nothing is installed on the hosts. Credentials are stored encrypted. Each credential **applies to** all hosts (global), hosts with a tag, hosts in a VLAN, one host, or no host automatically (*not assigned*, for discovery or explicit assignment). Each host uses its explicitly assigned credential, else a host-, tag-, VLAN- and finally the global credential; the Inventory host list shows which one each host uses.
- **Management VLAN:** pick the VLAN whose subnet may always reach SSH on every host. Without one, SSH is allowed from any source so hosts can't be locked out.
- **Users and roles:** create accounts and give them roles (`viewer`, `operator`, `approver`, `admin`). You need at least two people who can approve, because nobody can approve their own changes (see step 5).

### 2. Inventory: tell Segmentra what you have (`operator` or `admin`)

- **Hosts:** add hosts one by one or with **Bulk Import** (CSV). Each host has a management IP, SSH port and firewall backend (`nftables`, `iptables`, `firewalld`, `ufw` or auto).
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
- On IoT/OT gateways (hosts tagged `iot-gateway`), use direction **FORWARD (through gateway)** for traffic routed *through* the gateway. A FORWARD rule has a source and a **destination** (CIDR, tag, VLAN, host or IoT device). Traffic to the IoT devices assigned to that gateway is denied unless a FORWARD rule allows it. Other forwarded traffic is not affected. See [docs/iot.md](iot.md).
- When the version is ready, go back to the policy set and click **Submit for Approval**. The version becomes `PENDING_APPROVAL` and can no longer be edited.

### 5. Approvals: a second person reviews (`approver` or `admin`, but not the author)

- New versions must be approved by a user with the **`approver` or `admin` role who did not create, edit or submit that version**. The app blocks self-approval ("You cannot approve a policy version that you created, edited or submitted").
- When sending a version for approval the author can type a **reason**; the reviewer sees it on the **Approvals** page. **View Rules** opens a dialog with the rules (and an optional **Impact analysis** against an earlier version); **Reject** opens its own dialog and asks for a reason. The author sees the outcome on the Dashboard (**Your approval requests**), in a counter next to Policy Sets, and on the policy set page. Every submission, approval and rejection is written to the audit log with who asked, when, why, who decided and when.
- A rejected version can be fixed and resubmitted. An approved version becomes `APPROVED` and can be deployed.
- **High-risk deployments** (rules that open sensitive or management ports to very broad sources, "any/any"-style rules, or a wide interface scope across many hosts) also need a deployment-level approval by an `approver`/`admin` other than the person who created the deployment.

### 6. Deployments: push the rules to hosts (`operator` or `admin`)

- **Deployments → + Create Deployment:** pick an approved version, the targets and a mode (`FULL`, `CANARY` or `PROGRESSIVE`). You can also schedule it for later and set an expiry date with an action (notify only, remove the rules, or revert to the previous version).
- Click **Start**. Each host is backed up first, the rules are applied, and Segmentra checks that it can still reach the host over SSH. If not, the change is reverted automatically after about two minutes.
- Follow progress on the deployment page. If some hosts fail, use **Retry Failed Hosts** once the problem is fixed. A successful deployment marks the version `DEPLOYED`, and the policy set page shows which version is **active** on how many hosts.
- Only Segmentra's own firewall rules are replaced. Rules from Docker, Kubernetes or fail2ban are left alone.

### 7. Operate: verify, troubleshoot and audit

- **Inventory → Active Rules:** answers "what exactly is enforced on this host right now?" (policy version, rules, drift status, live versus expected ruleset).
- **Inventory → Check Compliance:** detects drift when someone changes Segmentra's rules on a host by hand.
- **Troubleshoot:** simulate whether traffic between two IPs would be allowed, search which policies affect an IP or host, or run **Firewall Learning** (log-only mode) to discover real traffic.
- **Policy Impact Analysis:** run a version in log-only mode on a host before enforcing it, then analyze which observed traffic it would allow or block.
- **Security Audit, Audit Log, Notifications and Integrations:** scan for risky rules, review who did what, get alerts (Slack or webhook), and forward the audit log to a SIEM.

Typical lifecycle of a version: `DRAFT` → `PENDING_APPROVAL` → `APPROVED` (or `REJECTED` → fix → resubmit) → `DEPLOYED`; old versions can be `ARCHIVED`.
