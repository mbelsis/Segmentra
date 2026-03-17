# Demo Data

This folder contains a seed script that populates Segmentra with realistic demo content for evaluation and testing.

## Usage

```bash
# From the repo root (database must be running)
node demo-data/seed-demo-data.js
```

Or with a custom database URL:

```bash
DATABASE_URL=postgres://segmentra:segmentra@127.0.0.1:15432/segmentra node demo-data/seed-demo-data.js
```

The script is **idempotent** — running it multiple times will not create duplicates (uses `ON CONFLICT DO NOTHING`).

## What It Creates

### Infrastructure (27 hosts across 6 VLANs)

| VLAN | Tag | Hosts | Description |
|------|-------|---------|-----------|
| 10 - Management | bastion, monitoring, dns, mail-server | 6 | Bastion, Prometheus/Grafana, DNS resolvers, mail relay |
| 20 - Production Web | web-server | 4 | Nginx/Apache web servers (Ubuntu, nftables) |
| 30 - Production App | app-server, cache-server | 6 | Java/Node.js app servers + Redis cache (RHEL/CentOS) |
| 40 - Production DB | db-server | 3 | PostgreSQL primary + replica (RHEL, nftables) |
| 50 - DMZ | load-balancer, dmz | 3 | HAProxy load balancers + reverse proxy |
| 100 - Development | ci-cd, development | 5 | Jenkins, GitLab runner, dev web/app/db |

### Tags (15)

`web-server`, `app-server`, `db-server`, `monitoring`, `load-balancer`, `cache-server`, `ci-cd`, `bastion`, `dns`, `mail-server`, `production`, `development`, `dmz`, `linux-rhel`, `linux-ubuntu`

### Firewall Policies (4)

| Policy | Scope | Status | Rules | Description |
|--------|-------|--------|-------|-------------|
| Web Server Firewall | TAG: web-server | APPROVED | 9 | HTTP/HTTPS in, outbound to DB/cache/DNS |
| Database Server Firewall | TAG: db-server | APPROVED | 9 | PostgreSQL from app/web only, DENY from elsewhere (logged), replication |
| DMZ Firewall | TAG: dmz | APPROVED | 9 | HTTP/HTTPS from internet, block SSH from non-bastion, block DB access |
| Monitoring Infrastructure | TAG: monitoring | DRAFT | 10 | Prometheus/Grafana access, scrape all exporters, PagerDuty webhooks |

### SSH Credentials (3)

| Name | Username | Scope | Notes |
|------|----------|-------|-------|
| Production Global Key | segmentra | GLOBAL | Used for all production deployments |
| DMZ Deploy Key | deploy | TAG: dmz | Dedicated key for DMZ servers |
| Development Key | dev-deploy | TAG: development | Development environment only |

**Note:** These contain dummy private keys — they are NOT real and cannot be used for actual SSH connections.

### OT/IoT Assets (13)

| Type | Count | Examples |
|------|-------|---------|
| PLC | 2 | Siemens S7-1500 (Assembly Lines 1 & 2) |
| HMI | 2 | Siemens TP1900, Rockwell PanelView Plus 7 |
| HVAC | 2 | Honeywell Spyder LON controllers |
| Camera | 3 | Axis P1448-LE, M3106-L; Hikvision DS-2CD2143G2 |
| Sensor | 2 | Paessler PRTG probe, APC PDU power meter |
| Printer | 2 | HP LaserJet Enterprise, Zebra ZT620 label printer |

Plus 2 flow collectors (NetFlow v9, sFlow) and 2 enforcement points (Linux gateway firewall, Cisco Catalyst switch).

### Kubernetes (2 clusters, 13 workloads)

**Production EKS** cluster with 4 namespaces:
- `frontend`: nginx-ingress, react-app (3 replicas), react-app-svc
- `backend`: api-gateway (2 replicas), user-service, order-service (2 replicas), api-gateway-svc
- `data`: postgresql StatefulSet (2 replicas), redis-cluster (3 replicas), postgresql-svc
- `monitoring`: node-exporter DaemonSet, prometheus, grafana

**Staging GKE** cluster (empty — ready for sync).

### Topology Views (2)

**Production Network Architecture** — 11 flows showing three-tier web app:
```
Internet → DMZ (HTTP/HTTPS) → Web Tier → App Tier → DB Tier
                                ↓           ↓
                              Cache       Cache
Bastion → SSH to all tiers
Monitoring → Metrics from all tiers
DMZ ✗→ DB Tier (blocked)
```

**OT Network Segmentation** — 5 flows showing Purdue model:
```
HMI → PLC (Modbus/TCP 502)
HVAC → PLC (BACnet/UDP 47808)
Management → Cameras (RTSP 554)
OT ✗→ App Tier (air gap)
```
