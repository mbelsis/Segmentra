# OT/IoT Microsegmentation

## Overview

Segmentra's OT/IoT module manages devices that **cannot run agents or host-based firewalls** — PLCs, HMIs, sensors, cameras, printers, HVAC controllers, medical devices, and other operational technology (OT) or Internet of Things (IoT) assets.

These devices typically run proprietary firmware, have no SSH access, and cannot execute nftables/iptables rules. Segmentra addresses this by enforcing policies **upstream** — on gateway Linux servers and managed switches that sit between the IoT devices and the rest of the network.

---

## How Enforcement Works

### The Problem

A PLC at `10.0.50.10` needs to be restricted to only communicate with the HMI at `10.0.50.20` on Modbus (TCP 502). But you cannot SSH into the PLC and install firewall rules — it's a closed embedded device.

### The Solution: Upstream Enforcement

You enforce the policy on a device you **do** control — a gateway Linux server or managed switch that sits between the IoT device and the rest of the network:

```
                       You control this
                            ↓
[PLC 10.0.50.10] ←──→ [Gateway Firewall / Switch] ←──→ [Rest of Network]
                            ↓
                       Deploy ACL here via SSH
                       "Only allow 10.0.50.10 → 10.0.50.20:502"
```

Segmentra does **not** deploy firewall rules directly to IoT/OT devices. Instead:

1. **IoT assets** are tracked in a separate inventory (distinct from the `hosts` table used for Linux servers)
2. **Traffic is observed passively** via NetFlow/sFlow/SPAN collectors — no agent on the device
3. **Policies are enforced on enforcement points** — gateway Linux servers running nftables/iptables, or managed switches that accept ACLs via SSH

This is the same SSH-based deployment mechanism used for regular host deployments, but targeting the gateway/switch instead of the IoT device itself.

---

## Architecture

```
┌─────────────────────┐     NetFlow/sFlow      ┌──────────────────────┐
│ Network Switches     │ ───────────────────►  │ Flow Collectors       │
│ (SPAN/Mirror ports)  │                        │ (Segmentra)           │
└─────────────────────┘                        └──────────┬───────────┘
                                                           │ Observed Flows
                                                           ▼
                                               ┌──────────────────────┐
                                               │ IoT Asset Inventory   │
                                               │ + Protocol            │
                                               │   Fingerprinting      │
                                               └──────────┬───────────┘
                                                           │ Policy Rules
                                                           ▼
┌─────────────────────┐     SSH (ACLs)         ┌──────────────────────┐
│ IoT/OT Devices       │ ◄──────────────────── │ Enforcement Points    │
│ (PLC, HMI, Camera,  │   (via gateway/switch) │ (Gateway Linux FW,   │
│  Sensor, Medical)    │                        │  Managed Switches)    │
└─────────────────────┘                        └──────────────────────┘
```

---

## Three Components

### 1. IoT Assets (Inventory)

The asset inventory tracks devices with OT-specific fields:

| Field | Purpose | Examples |
|-------|---------|---------|
| **Name** | Device identifier | `PLC-Line-3`, `Camera-Lobby-01` |
| **Asset Type** | Device category | `plc`, `hmi`, `sensor`, `camera`, `printer`, `hvac`, `medical`, `other` |
| **Vendor / Model** | Manufacturer details | Siemens S7-1200, Axis P1448-LE |
| **Firmware Version** | Software version | v4.2.1 |
| **MAC Address** | Hardware address | `00:1A:2B:3C:4D:5E` |
| **IP Address** | Network address | `10.0.50.10` |
| **VLAN** | Network segment | Production OT (VLAN 50) |
| **Zone** | Purdue model level | `Level 0`, `Level 1`, `Level 2`, `DMZ` |
| **Criticality** | Business impact | `critical`, `high`, `medium`, `low` |
| **Fingerprint** | Protocol metadata (JSONB) | Detected protocols, baseline traffic |

IoT assets are stored in a **separate table** (`iot_assets`) from Linux hosts (`hosts`) because they are fundamentally different — no SSH, no agent, no direct management.

### 2. Flow Collectors (Passive Discovery)

Flow collectors observe traffic passively without touching the devices:

| Collector Type | Protocol | Typical Port |
|---------------|----------|-------------|
| NetFlow v5 | UDP | 2055 |
| NetFlow v9 | UDP | 2055 |
| sFlow | UDP | 6343 |
| IPFIX | UDP | 4739 |
| SPAN Analyzer | Mirror port | N/A |

Observed flows are stored in `iot_observed_flows` with source/destination IPs, ports, protocols, byte/packet counts, and first/last seen timestamps.

### 3. Enforcement Points (Upstream Policy Deployment)

Enforcement points are the devices where policies are actually applied:

| Type | Description | Deployment Method |
|------|------------|-------------------|
| **Gateway Firewall** | Linux server running nftables/iptables at network boundary | SSH (same as host deployments) |
| **Managed Switch** | Network switch accepting ACLs (Cisco, Juniper, Arista) | SSH with vendor-specific ACL syntax |

Enforcement points use the same SSH credential infrastructure as regular Segmentra host deployments. ACLs are deployed via `POST /enforcement-points/:id/deploy-acl`.

---

## Usage Workflow

### Step 1: Add IoT Assets

Go to **OT/IoT → Assets** and add devices manually or via bulk import:
- Enter device name, type, vendor, model, IP, MAC, VLAN, and Purdue zone
- Assign criticality level (critical/high/medium/low)
- Optionally assign Segmentra tags for policy grouping

### Step 2: Observe Traffic (Optional)

Configure flow collectors to passively capture traffic:
- Go to **OT/IoT → Flow Collectors**
- Add a collector (NetFlow/sFlow/IPFIX) with listen address and port
- Observed flows appear per asset showing source, destination, protocol, ports, and packet counts

### Step 3: Capture Baseline

Select an asset and click **Baseline** to snapshot its current traffic pattern:
- Records all observed flows as the "known good" state
- Stored in the asset's fingerprint data
- Use for anomaly detection — compare future traffic against the baseline

### Step 4: Configure Enforcement Points

Go to **OT/IoT → Enforcement Points** and add the gateways/switches:
- Name and type (gateway firewall or managed switch)
- Vendor (for ACL syntax selection)
- Management IP
- SSH credential (from Admin → SSH Credentials)

### Step 5: Deploy ACLs

Create ACL configurations and deploy them to enforcement points:
- Define which traffic is allowed/denied between IoT assets and the network
- Deploy the ACL to the gateway/switch via SSH
- Track deployment status with hash verification

---

## Key Design Decisions

- **Separate from hosts**: `iot_assets` is a distinct table from `hosts` — IoT devices are fundamentally different (no SSH, no agent, no direct management)
- **Passive-first**: Traffic discovery via NetFlow/sFlow — no active scanning of fragile OT devices
- **Upstream enforcement**: Policies applied to gateways/switches, not to the IoT devices themselves
- **Zone model**: Text field for Purdue levels — flexible for non-standard OT network layouts
- **Same SSH infrastructure**: Enforcement points reuse the same SSH credential system as regular deployments
- **Flow collection is opt-in**: UDP listeners add complexity; not required for basic asset inventory management

---

## API Endpoints

### IoT Assets
- `GET /api/iot-assets` — List assets (filter by assetType, zone, vlanId)
- `GET /api/iot-assets/:id` — Get asset with observed flows and tags
- `POST /api/iot-assets` — Create asset
- `PUT /api/iot-assets/:id` — Update asset
- `DELETE /api/iot-assets/:id` — Delete asset
- `POST /api/iot-assets/bulk-import` — Bulk import assets
- `POST /api/iot-assets/:id/tags` — Assign tag
- `DELETE /api/iot-assets/:id/tags/:tagId` — Remove tag
- `GET /api/iot-assets/:id/flows` — Get observed traffic
- `POST /api/iot-assets/:id/baseline` — Capture traffic baseline

### Flow Collectors
- `GET /api/flow-collectors` — List collectors
- `GET /api/flow-collectors/:id` — Get collector with recent flows
- `POST /api/flow-collectors` — Create collector
- `PUT /api/flow-collectors/:id` — Update collector
- `DELETE /api/flow-collectors/:id` — Delete collector

### Enforcement Points
- `GET /api/enforcement-points` — List enforcement points
- `GET /api/enforcement-points/:id` — Get with deployed ACLs
- `POST /api/enforcement-points` — Create enforcement point
- `PUT /api/enforcement-points/:id` — Update
- `DELETE /api/enforcement-points/:id` — Delete
- `POST /api/enforcement-points/:id/deploy-acl` — Deploy ACL configuration
- `GET /api/enforcement-points/:id/acls` — List deployed ACLs

---

## Database Tables

- `iot_assets` — Device inventory with OT-specific fields
- `iot_asset_tags` — Many-to-many tag assignments
- `flow_collectors` — NetFlow/sFlow/IPFIX collector configurations
- `iot_observed_flows` — Passively observed traffic flows
- `enforcement_points` — Managed switches and gateway firewalls
- `enforcement_acls` — Deployed ACL configurations with status tracking
