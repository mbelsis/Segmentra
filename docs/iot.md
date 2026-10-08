# OT/IoT Microsegmentation with Segmentra

This guide explains how to protect OT/IoT devices with Segmentra: PLCs, HMIs, sensors, cameras, printers, HVAC controllers, medical devices and similar equipment.

---

## 1. The problem

Most OT/IoT devices can't run a host firewall or an agent. You can't SSH into a PLC and install nftables, and many devices have a fixed firmware network stack. They still need segmentation: an engineering workstation may talk Modbus to a PLC, but nothing else on the corporate network should reach it.

Segmentra enforces these policies **upstream**, on a Linux **gateway** that routes traffic between the IT network and the OT/IoT network. The gateway filters traffic that passes *through* it on behalf of the devices behind it.

---

## 2. Concepts

| Concept | What it is in Segmentra |
|---|---|
| **Gateway host** | A normal Linux host in **Inventory**, tagged with the system tag `iot-gateway`. It has IP forwarding enabled and routes between IT and OT networks (usually 2+ interfaces). Policies reach it through the normal SSH/Ansible deployment pipeline. |
| **IoT asset** | A device registered on the **OT/IoT → Assets** page: name, type, IP address, MAC, vendor/model, VLAN/zone, criticality. Assets are not deployment targets; nothing is installed on them. |
| **Assignment** | Each asset can be assigned to one or more gateways (OT/IoT page, asset detail panel or create form). This is stored in `iot_asset_gateways`. |
| **Protected device** | An asset that is **assigned to a gateway, enabled, and has an IP address**. Forwarded traffic to a protected device is denied by the gateway unless a FORWARD rule allows it. |
| **Zones = VLANs** | OT zones (for example Purdue levels) are modelled as **VLANs** in Inventory. Assets can be placed in a VLAN, and a VLAN can be a rule source or destination. |
| **FORWARD rule** | A policy rule with direction **FORWARD (through gateway)**. Unlike IN/OUT rules, it has a **source** *and* a **destination**. |

There is no separate IoT deployment mechanism. The gateway is a host, the policy is a regular policy set/version, and the deployment is a regular deployment.

```
 IT network                  Gateway host (iot-gateway)               OT network
 172.30.0.0/24               eth0 172.30.0.50 | eth1 172.31.0.2        172.31.0.0/24
 ┌──────────────┐            ┌──────────────────────────────┐        ┌──────────────┐
 │ HMI client   │──────────► │ input/output: the gateway's  │ ─────► │ PLC          │
 │ 172.30.0.40  │            │   own IN/OUT rules           │        │ 172.31.0.150 │
 │ web server   │            │ forward: FORWARD rules +     │        │ (protected)  │
 │ 172.30.0.31  │            │   default deny to protected  │        └──────────────┘
 └──────────────┘            └──────────────────────────────┘
```

---

## 3. How enforcement works

### Rule types on a gateway

- **IN / OUT / BOTH rules** protect the **gateway itself**, for example SSH or monitoring to the gateway. Inbound traffic to the gateway that no rule allows is dropped. Management SSH, loopback and established connections are always allowed (baseline). These rules never match traffic that is routed *through* the gateway.
- **FORWARD rules** match traffic **routed through** the gateway, by source *and* destination, plus protocol and ports. They are evaluated **in rule order; the first match wins**.
  - **Source:** CIDR, TAG, VLAN or HOST (same as other rules: TAG/VLAN/HOST resolve to the management IPs of enabled hosts).
  - **Destination:** `IoT device` (an asset: its IP address), `CIDR`, `HOST` (the host's management IP), `TAG` (enabled hosts *and* enabled IoT assets with the tag) or `VLAN` (the VLAN subnet if set; otherwise the enabled hosts and IoT assets in the VLAN).
  - **Interface scopes do not apply** to FORWARD rules.

### Default behaviour of forwarded traffic

When a policy is deployed to a host, Segmentra filters forwarding **only if** the host has FORWARD rules or protects at least one device. Then:

1. Replies to allowed connections (established/related) always pass.
2. FORWARD rules are evaluated in order: `ALLOW` lets the packet pass, `DENY` drops it.
3. Traffic **to a protected device** of this gateway that no rule allowed is **dropped** (default deny).
4. **All other forwarded traffic passes unchanged.** For example: Docker networks on the gateway, routing to other subnets, or traffic to devices that are not assigned to this gateway.

Hosts without FORWARD rules and without protected devices get exactly the same ruleset as before this feature. Their forwarding is not touched.

### nftables implementation

Everything stays inside `table inet segmentra`, which is replaced atomically on every deploy. A forward chain is added only when it is needed:

```
table inet segmentra {
  set dst_iot_736ad4b111564f09a1dae89f820fd068 { type ipv4_addr; flags interval; elements = { 172.31.0.150 } }
  set protected_v4 { type ipv4_addr; flags interval; elements = { 172.31.0.150 } }
  chain input  { ... the gateway's own IN rules, policy drop ... }
  chain output { ... policy accept ... }
  chain forward {
    type filter hook forward priority 0; policy accept;
    ct state established,related accept
    ip saddr 172.30.0.40/32 ip daddr @dst_iot_736ad4b1... tcp dport { 502 } accept comment "HMI to PLC Modbus"
    ip daddr @protected_v4 drop comment "protected_default_deny"
  }
}
```

The chain policy is `accept`, so only traffic to protected devices is default-denied. IPv6 device addresses go into `protected_v6` (`ip6 daddr @protected_v6 drop`).

### iptables / ip6tables implementation

Segmentra adds a chain `SEGMENTRA-FWD` to the same `iptables-restore --noflush` fragment as `SEGMENTRA-IN` / `SEGMENTRA-OUT`. It inserts one jump at the top of `FORWARD` in the same transaction:

```
-A FORWARD -j SEGMENTRA-FWD
-A SEGMENTRA-FWD -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "segmentra:established" -j RETURN
-A SEGMENTRA-FWD -s 172.30.0.40/32 -d 172.31.0.150/32 -p tcp -m tcp --dport 502 -m comment --comment "segmentra:fwd1 HMI to PLC Modbus" -j RETURN
-A SEGMENTRA-FWD -d 172.31.0.150/32 -m comment --comment "segmentra:protected_default_deny" -j DROP
-A SEGMENTRA-FWD -m comment --comment "segmentra:default" -j RETURN
```

- An allow is `RETURN`: the packet goes back to `FORWARD`, so rules after the jump still apply (for example Docker's `DOCKER-USER`). A deny is `DROP`.
- The `FORWARD` policy and other chains are never changed.
- If a later deployment no longer needs forwarding (no FORWARD rules, no protected devices), the jump and `SEGMENTRA-FWD` are removed. Policy removal (expiry REMOVE) removes them too.
- Scoped backups record `SEGMENTRA-FWD` and whether the `FORWARD` jump existed (`chain-fwd=` / `jump-fwd=` in the backup header). Restores (lockout auto-revert, failure rollback, firewall-learning restore) bring back exactly that state.
- Drift detection (compliance) includes `SEGMENTRA-FWD` and its jump.

### Important consequences

- **Default deny is per gateway and per device.** A device is protected only on the gateways it is assigned to, and only after those gateways are redeployed. **Assigning or unassigning a device takes effect on the gateway's next deployment.**
- **Deploying a version with no FORWARD rules to a gateway that protects devices denies all forwarded traffic to those devices.** This is the intended safe default. To stop filtering, unassign the devices and redeploy, or remove the policy.
- A `DENY` in another nftables table, or a `FORWARD` policy `DROP` you set yourself, still drops traffic Segmentra allows. Don't combine Segmentra with a manual forward default deny for the same networks. See the [Gateway Setup Guide](gateway-setup-guide.md#step-4-leave-forwarding-to-segmentra).
- Segmentra filters only traffic that is **actually routed through the gateway**. A direct path between IT and OT that bypasses the gateway is not filtered.

---

## 4. Worked example: HMI → PLC Modbus only

Goal: the HMI client `172.30.0.40` may reach the PLC `plc-1` (`172.31.0.150`) on Modbus `tcp/502`. Everything else to the PLC is blocked. In the second step, `web-ipt` (`172.30.0.31`) also gets `tcp/80` (HTTP) to the PLC.

**Setup:** gateway `iot-gw` (nftables, `172.30.0.50` / `172.31.0.2`, `ip_forward=1`), tagged `iot-gateway`. Asset `plc-1`, IP `172.31.0.150`, assigned to `iot-gw`. Policy set `ot-gateway`, scope TAG `iot-gateway`. The existing version had one rule, `IN ALLOW tcp 502 from 172.30.0.40/32`. That rule only protects the gateway itself: before this change, all routed traffic to the PLC passed.

**Rules as entered in the UI** (Policy Version → + Add Rule):

| # | Direction | Action | Protocol | Ports | Source Type / Value | Destination Type / Value | Comment |
|---|---|---|---|---|---|---|---|
| 1 | FORWARD (through gateway) | ALLOW | TCP | 502 | CIDR `172.30.0.40/32` | IoT device `plc-1 (172.31.0.150)` | HMI to PLC Modbus |
| 10 | IN | ALLOW | TCP | 502 | CIDR `172.30.0.40/32` | – | (existing rule for the gateway itself) |

Version 3 (cloned from version 2) adds:

| # | Direction | Action | Protocol | Ports | Source Type / Value | Destination Type / Value | Comment |
|---|---|---|---|---|---|---|---|
| 2 | FORWARD (through gateway) | ALLOW | TCP | 80 | HOST `web-ipt` | IoT device `plc-1 (172.31.0.150)` | web-ipt to PLC HTTP |

**Verified live** (Docker demo stack, TCP connects with `nc -z` from the client containers, which route `172.31.0.0/24` via the gateway; `172.31.0.151` is a second, *unassigned* address on the PLC container):

| Flow | Before (v1, IN rule only) | v2 (nftables) | v3 (nftables) | v3 (iptables) | After expiry REMOVE |
|---|---|---|---|---|---|
| client `172.30.0.40` → PLC :502 | open | **open** | open | open | open |
| client → PLC :80 | open | **blocked** | blocked | blocked | open |
| web-ipt `172.30.0.31` → PLC :80 | open | **blocked** | **open** | open | open |
| web-ipt → PLC :502 | open | blocked | blocked | blocked | open |
| client → `172.31.0.151` :80 (not protected) | open | open | open | open | open |
| client → gateway :22 (gateway's own baseline) | open | open | open | open | open |

Also verified:

- The approval was done by a separate approver account (the author can't approve).
- Compliance read-back was `compliant` after each deploy (nftables and iptables). It reported `drifted` after a rule was deleted by hand from the nft forward chain, and after the `FORWARD -j SEGMENTRA-FWD` jump was deleted by hand.
- The simulator: client → PLC:502 `allowed` (FORWARD rule #1); client → PLC:80 and web-ipt → PLC:80 (v2) `blocked … protected device and no FORWARD rule allows this traffic`; client → `172.31.0.151` `allowed (no policy)`.
- iptables: a pre-existing `DOCKER-USER` chain jumped from `FORWARD` was left untouched. `SEGMENTRA-FWD` was inserted above it.
- Deploying v1 (no FORWARD rules) while `plc-1` was still assigned blocked all four PLC flows. After unassigning `plc-1` and deploying v1 again, `SEGMENTRA-FWD` and its jump were removed and all flows were open.
- Scoped restore of a backup taken before `SEGMENTRA-FWD` existed removed the chain and the jump. Restoring a backup taken with it brought both back.

---

## 5. Step by step in the UI

1. **Prepare the gateway** (Linux): IP forwarding, routing, firewall tool, SSH user with sudo. See the [Gateway Setup Guide](gateway-setup-guide.md).
2. **Store credentials:** **Admin → SSH Credentials**, a key or password for the gateway's SSH user. Credentials are encrypted at rest; see [security.md](security.md).
3. **Inventory → Hosts:** add the gateway (management IP, SSH port, firewall backend `nftables` or `iptables`) and give it the tag **`iot-gateway`**. Optionally create VLANs for your OT zones (**Inventory → VLANs**). Run **Check Readiness**.
4. **OT/IoT → Assets:** register each device with its **IP address** and assign it to the gateway(s) under "Protecting Gateway(s)". The **Gateways** tab lists, per gateway, the protected devices and the number of FORWARD rules in the currently deployed version.
5. **Policy Sets → + New Policy Set:** scope it to TAG `iot-gateway` (all gateways) or to a host list (one gateway).
6. **New version → + Add Rule:** choose direction **FORWARD (through gateway)**, then a source and a **Destination Type** (`IoT device`, `CIDR`, `VLAN`, `TAG`, `HOST`) and **Destination Value**. Add one rule per allowed flow; anything else to the protected devices is denied. Add IN rules only for services on the gateway itself. To preview the compiled ruleset for a gateway, including the forward chain, call `GET /api/policy-versions/:versionId/render/host/:hostId` (API only; there is no UI button for this).
7. **Submit for Approval.** A different user with the `approver` or `admin` role approves it. **Analyze Impact** counts the added and removed allows and denies (the API response `POST /api/policy-versions/:id/impact-diff` lists each rule with its destination). A FORWARD allow from a very broad source (for example `0.0.0.0/0`) marks the version and its deployments high-risk, so the deployment then needs a second approval.
8. **Deployments → + Create Deployment:** target the gateway(s) and start. The usual protections apply: scoped backup, automatic revert if SSH to the gateway is lost, and rollback on failure.
9. **Verify:**
   - **Troubleshoot → Simulate** with source IP, device IP and port. If the destination is a protected device, the result shows the gateway, the deciding FORWARD rule or "protected-device default deny".
   - **Compliance:** the drift check covers the forward chain / `SEGMENTRA-FWD`.
   - **Firewall Learning on the gateway** (Troubleshoot) to discover device traffic. While learning, the gateway's ruleset is replaced by a log-only one: forwarded traffic to protected devices is **accepted and logged** (log prefix `FW-AUDIT: DENY: protected-default` with nftables, `FW-AUDIT: DENY: protected` with iptables, meaning "would be denied") instead of dropped. Verified live on iptables: the log rule counted the forwarded packets, traffic passed, and cancelling the session restored the previous rules. The previous ruleset is restored when the session ends. Learning results currently aggregate only inbound/outbound flows of the gateway itself. Forwarded flows are logged on the gateway (`/var/log/segmentra-audit-*.log`) but not turned into rule suggestions.

---

## 6. Changing or removing ACLs

- **Edit:** deployed versions are read-only. **Clone** the version, change the FORWARD rules, then submit, approve and deploy. Each deploy replaces the gateway's Segmentra ruleset atomically (nft) or in one restore transaction (iptables).
- **Stop protecting a device:** unassign it on the OT/IoT page and redeploy the gateway.
- **Temporary access:** set an expiry on the deployment:
  - **REMOVE** deletes Segmentra's rules from the gateway (`table inet segmentra`, or `SEGMENTRA-IN/OUT/FWD` + jumps). Forwarding is then no longer filtered. Verified live on nftables and iptables.
  - **REVERT** redeploys the previously deployed version.
  - **NOTIFY_ONLY** only notifies.

---

## 7. Gateway prerequisites

- **IP forwarding** enabled (`net.ipv4.ip_forward=1`; `net.ipv6.conf.all.forwarding=1` for IPv6).
- **Routing:** traffic between IT and OT must actually pass through the gateway. Devices use the gateway's OT address as their default route (or a route to the IT subnets), and IT clients or routers route the OT subnets via the gateway. Segmentra does not configure routes.
- `nft` (nftables backend) or `iptables-restore` / `ip6tables-restore` (iptables backend), SSH access with a key (optionally passphrase-protected) or a password, and **full `sudo` rights** for the SSH user, with or without a sudo password (Segmentra runs `sudo sh -c '…'`; set *Privilege escalation* on the credential; see [security.md](security.md#checklist)).
- No manual forward default deny for the protected networks. See [Gateway Setup Guide, step 4](gateway-setup-guide.md#step-4-leave-forwarding-to-segmentra).

---

## 8. Limitations and what is not tested

- Changes to asset assignments, asset IPs or the enabled flag take effect only on the gateway's **next deployment**. They are not pushed automatically.
- Disabled assets, and assets without an IP address, are **not** protected. An asset IP that is not a valid IP/CIDR makes the deployment to that gateway **fail** with a compile error rather than silently leaving the device unprotected.
- FORWARD rules ignore interface scopes, and there is no "ingress interface" match.
- The **simulator** assumes traffic to a protected device is routed through the gateways it is assigned to. It evaluates only that gateway's FORWARD rules. Interface scopes, routing and multiple hops are not modelled. The **search by IP** in Troubleshoot matches rule *sources* only.
- **Firewall Learning** logs forwarded traffic but does not generate FORWARD rule suggestions. The policy-test analyzer does not evaluate FORWARD rules.
- **Policy templates:** the API accepts FORWARD rules with destinations in templates, but the template editor UI does not offer FORWARD yet.
- Kubernetes NetworkPolicy export skips FORWARD rules with a warning.
- Switching a host's backend (nftables ↔ iptables) does not remove the rules of the previous backend. Remove the policy first (expiry REMOVE), as with any host.
- **Not tested live:** IPv6 protected devices and IPv6 FORWARD rules (covered by compiler output only), the Ansible executor path with FORWARD rules (it uses the same host script as SSH Direct), REVERT expiry on a gateway, multiple gateways protecting the same device, and real OT protocols beyond a TCP listener on port 502.

---

## API reference

### Rules (policy versions and templates)

`POST /api/policy-versions/:versionId/rules`, `PUT /api/policy-rules/:ruleId` (same fields for template rules):

```json
{
  "orderIndex": 1,
  "direction": "FORWARD",
  "action": "ALLOW",
  "protocol": "tcp",
  "ports": "502",
  "sourceType": "CIDR",
  "sourceValue": "172.30.0.40/32",
  "destinationType": "IOT_ASSET",
  "destinationValue": "<iot asset id>",
  "comment": "HMI to PLC Modbus"
}
```

- `direction`: `IN` | `OUT` | `BOTH` | `FORWARD`.
- `destinationType`: `CIDR` | `TAG` | `VLAN` | `HOST` | `IOT_ASSET`. `destinationValue` is a CIDR or the id of the tag, VLAN, host or IoT asset.
- Both destination fields are required for `FORWARD` and must be empty or null otherwise (send `null` to clear them when changing a rule's direction). The referenced entity must exist.
- The database enforces the same rules (migration `028_forward_rules.sql`).

### IoT assets

- `GET /api/iot-assets`: list (filters: `assetType`, `zone`, `vlanId`, `gatewayId`)
- `GET /api/iot-assets/:id`: detail with gateways, flows, tags
- `POST /api/iot-assets`: create (optional `gatewayIds`)
- `PUT /api/iot-assets/:id`, `DELETE /api/iot-assets/:id`
- `POST /api/iot-assets/bulk-import`
- `POST /api/iot-assets/:id/gateways` with `{ "gatewayIds": [] }`: assign gateways
- `DELETE /api/iot-assets/:id/gateways/:hostId`: unassign
- `POST /api/iot-assets/:id/tags`, `GET /api/iot-assets/:id/flows`, `POST /api/iot-assets/:id/baseline`

### Gateways

- `GET /api/iot-assets/gateways/list`: gateways with `protected_asset_count`, `protected_assets` and `last_deployment` (incl. `forwardRuleCount`, `removedByExpiry`)
- `GET /api/iot-assets/gateways/:hostId`: gateway detail with protected assets and history

### Database

- `iot_assets`: device inventory
- `iot_asset_gateways`: asset ↔ gateway host (many-to-many)
- `iot_asset_tags`: tag assignments
- `policy_rules.destination_type` / `destination_value` (and the same columns on `policy_template_rules`)
- `iot_observed_flows`: historical flow data (from the deprecated flow collectors)
