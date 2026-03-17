# OT/IoT Microsegmentation

## Overview

Segmentra's OT/IoT module manages devices that **cannot run agents or host-based firewalls** — PLCs, HMIs, sensors, cameras, printers, HVAC controllers, medical devices, and other OT/IoT assets.

Policies are enforced **upstream** on gateway Linux servers that sit between the IoT devices and the rest of the network. Gateways are regular hosts from the Segmentra inventory tagged `iot-gateway`, and policies are deployed to them using the normal SSH/Ansible pipeline.

---

## How It Works

### The Core Model

```
┌─────────────────────────┐
│  OT/IoT Page            │
│  Register devices       │──── assign ────┐
│  Assign to gateways     │                │
└─────────────────────────┘                │
                                           ▼
┌─────────────────────────┐     ┌─────────────────────────┐
│  Inventory Page         │     │  Gateway Host            │
│  Gateway = regular host │────►│  Tagged "iot-gateway"    │
│  tagged "iot-gateway"   │     │  2+ NICs (IT + OT)      │
└─────────────────────────┘     │  nftables / iptables    │
                                └────────┬────────────────┘
┌─────────────────────────┐              │
│  Policy Sets            │              │ SSH / Ansible
│  Scoped to TAG:         │──── deploy ──┘ (normal pipeline)
│  "iot-gateway"          │
│  Rules reference IoT    │
│  device IPs / CIDRs     │
└─────────────────────────┘
```

**Key insight:** There is no separate deployment mechanism for IoT. The gateway IS a host. The policy IS a regular policy. The deployment IS a regular deployment. The IoT page provides visibility into which devices are behind which gateways.

### What Changed From Earlier Versions

- **Enforcement points removed** — Gateways are regular hosts in the inventory, not a separate concept
- **Flow collectors tab removed** — For traffic discovery, use Firewall Learning on the gateway host instead
- **Zones replaced by VLANs** — OT zones (Purdue levels) are defined as VLANs in the Inventory page
- **Same deployment pipeline** — No new executor or protocol; SSH/Ansible to the gateway host

---

## The Two Tabs

### Tab 1: Assets

Register IoT/OT devices with manufacturer-specific metadata:

| Field | Purpose | Examples |
|-------|---------|---------|
| **Name** | Device identifier | `PLC-Assembly-Line-1` |
| **Type** | Device category | `plc`, `hmi`, `sensor`, `camera`, `printer`, `hvac`, `medical`, `other` |
| **IP Address** | Network address | `10.0.60.10` |
| **MAC Address** | Hardware address | `00:1A:2B:3C:4D:5E` |
| **Vendor / Model** | Manufacturer | Siemens S7-1500 |
| **VLAN / Zone** | Network segment (from Inventory VLANs) | VLAN 60: OT Level 1 |
| **Criticality** | Business impact | `critical`, `high`, `medium`, `low` |
| **Gateway(s)** | Which gateway(s) protect this device | `gw-ot-01.acme.corp` |

**Filtering:** By device type, VLAN/zone, or gateway.

**Gateway assignment:** Each asset can be assigned to one or more gateways. Unprotected assets (no gateway) are highlighted in red.

**Detail panel:** Shows device info, assigned gateways (add/remove), and a step-by-step guide for protecting the device.

### Tab 2: Gateways

Shows hosts from the Inventory tagged `iot-gateway`. For each gateway:

| Column | What It Shows |
|--------|--------------|
| **Hostname** | Gateway server name |
| **IP** | Management IP |
| **Backend** | nftables or iptables |
| **Protected Devices** | Count of IoT assets assigned to this gateway |
| **Last Deployed Policy** | Policy set name and version |
| **Status** | SUCCEEDED, FAILED, or "No policy deployed" |

**Detail panel:** Shows the full list of protected devices, recent deployment history, and next steps (links to Firewall Learning, Policy Sets, Deployments).

---

## Traffic Discovery

Since you can't SSH into a PLC to deploy log-only rules, use **Firewall Learning** on the gateway host instead:

1. Go to **Troubleshoot → Firewall Learning**
2. Select the gateway host
3. Set a duration (e.g., 60 minutes)
4. Start the audit — the gateway switches to log-only mode and captures all traffic passing through it
5. After completion, view the communication flows — these show what the IoT devices behind the gateway actually communicate with

This answers: "What does this PLC talk to?" without touching the PLC.

---

## Zones = VLANs

OT/IoT zones (Purdue model levels) are defined as **VLANs** in the Inventory page:

| VLAN | Zone | Description |
|------|------|-------------|
| VLAN 60 | Level 0-1 | Field devices: PLCs, sensors, actuators |
| VLAN 61 | Level 1-2 | Control: HMIs, SCADA servers |
| VLAN 62 | Level 2 | Supervision: cameras, building management |
| VLAN 63 | Level 3 | Operations: engineering workstations |

Create these in **Inventory → VLANs**, then assign IoT assets to them.

---

## Step-by-Step Setup

### 1. Create OT VLANs

Go to **Inventory → VLANs** and create VLANs for your OT zones:
- VLAN 60: "OT Level 1 - PLCs" (subnet: 10.0.60.0/24)
- VLAN 61: "OT Level 2 - HMIs" (subnet: 10.0.61.0/24)
- VLAN 62: "Building Systems" (subnet: 10.0.62.0/24)

### 2. Add a Gateway Host

Go to **Inventory → Hosts** and add the Linux server that sits between OT and IT:
- Hostname: `gw-ot-01.acme.corp`
- Management IP: `10.0.10.100`
- Tag: `iot-gateway` (this is a system tag — always available)
- Add interfaces: `eth0` (management), `eth1` (IT-facing), `eth2` (OT-facing)

See the [Gateway Setup Guide](gateway-setup-guide.md) for detailed Linux configuration.

### 3. Register IoT Assets

Go to **OT/IoT → Assets** and add devices:
- Name: `PLC-Assembly-Line-1`
- Type: PLC
- IP: `10.0.60.10`
- VLAN: "OT Level 1 - PLCs"
- Gateway: `gw-ot-01.acme.corp`

### 4. Discover Traffic (Optional)

Run **Firewall Learning** on the gateway to see what IoT devices actually communicate:
1. Go to **Troubleshoot → Firewall Learning**
2. Select `gw-ot-01.acme.corp`
3. Set 60-minute duration
4. Review discovered flows

### 5. Create Gateway Policy

Go to **Policy Sets → + New Policy Set**:
- Name: "OT Gateway Firewall"
- Scope: TAG → `iot-gateway`
- Create version with rules:

```
# Allow HMI → PLC Modbus communication
ALLOW TCP 502 IN from 10.0.61.0/24 to 10.0.60.0/24

# Allow BACnet from building management
ALLOW UDP 47808 IN from 10.0.62.0/24

# Allow monitoring from management
ALLOW TCP 9100 IN from TAG:monitoring

# Allow SSH from bastion only
ALLOW TCP 22 IN from TAG:bastion

# Block OT → App tier (air gap)
DENY any OUT to 10.0.30.0/24

# Allow DNS
ALLOW TCP/UDP 53 OUT to TAG:dns
```

### 6. Deploy

1. Submit for approval → Approve
2. Go to **Deployments → + Create Deployment**
3. Target: TAG → `iot-gateway`
4. A warning banner appears about IoT gateway impact
5. Start deployment — rules are pushed to the gateway via SSH

### 7. Verify

Go to **OT/IoT → Gateways** tab to confirm the deployment status and see which devices are protected.

---

## Deployment Warning

When deploying to hosts tagged `iot-gateway`, Segmentra shows:

> **IoT/OT Gateway Deployment**
> This deployment targets one or more IoT/OT gateways. Changes to gateway firewall rules will affect all IoT devices protected by these gateways.

---

## API Endpoints

### IoT Assets
- `GET /api/iot-assets` — List (filter: `assetType`, `zone`, `vlanId`, `gatewayId`)
- `GET /api/iot-assets/:id` — Detail with gateways, flows, tags
- `POST /api/iot-assets` — Create (with optional `gatewayIds`)
- `PUT /api/iot-assets/:id` — Update
- `DELETE /api/iot-assets/:id` — Delete
- `POST /api/iot-assets/bulk-import` — Bulk import
- `POST /api/iot-assets/:id/gateways` — Assign gateways: `{ gatewayIds: [] }`
- `DELETE /api/iot-assets/:id/gateways/:hostId` — Remove gateway
- `POST /api/iot-assets/:id/tags` — Tag
- `GET /api/iot-assets/:id/flows` — Observed traffic
- `POST /api/iot-assets/:id/baseline` — Capture baseline

### Gateways
- `GET /api/iot-assets/gateways/list` — List gateways with asset counts and deployment status
- `GET /api/iot-assets/gateways/:hostId` — Gateway detail with protected assets and history

---

## Database

- `iot_assets` — Device inventory
- `iot_asset_gateways` — Links assets to gateway hosts (many-to-many)
- `iot_asset_tags` — Tag assignments
- `iot_observed_flows` — Historical traffic data (from flow collectors, now deprecated)
