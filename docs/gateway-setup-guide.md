# IoT/OT Gateway Setup Guide

This guide explains how to configure a Linux server as an IoT/OT gateway firewall — a host with multiple network interfaces that filters traffic between the OT/IoT network and the IT/corporate network.

---

## What Is a Gateway?

A gateway is a Linux server with **two or more network interfaces**:
- One interface connects to the IT/corporate network
- One or more interfaces connect to OT/IoT network segments
- The server runs nftables or iptables to filter traffic between the networks
- Segmentra deploys and manages the firewall rules via SSH

```
┌──────────────────┐        ┌──────────────────┐        ┌──────────────────┐
│  IT Network      │        │  Gateway Server  │        │  OT/IoT Network  │
│  10.0.10.0/24    │◄──────►│                  │◄──────►│  10.0.60.0/24    │
│                  │  eth0  │  nftables rules  │  eth1  │  PLCs, HMIs,     │
│  App servers,    │        │  managed by      │        │  Sensors,        │
│  databases, etc. │        │  Segmentra       │        │  Cameras, etc.   │
└──────────────────┘        └──────────────────┘        └──────────────────┘
```

---

## Prerequisites

- **Linux server** with 2+ NICs (Ubuntu 22.04+, RHEL 8+, or similar)
- **nftables** or **iptables** installed
- **SSH access** with a sudo-capable user
- **Two network connections**: one to IT, one to OT
- Physical or virtual network segmentation between IT and OT

---

## Step 1: Configure Network Interfaces

### Identify Interfaces

```bash
ip link show
```

Example output:
```
2: eth0: <BROADCAST,MULTICAST,UP> ...    # IT-facing
3: eth1: <BROADCAST,MULTICAST,UP> ...    # OT-facing
```

### Configure Static IPs

**Ubuntu (Netplan)** — `/etc/netplan/01-gateway.yaml`:
```yaml
network:
  version: 2
  ethernets:
    eth0:
      addresses:
        - 10.0.10.100/24
      routes:
        - to: default
          via: 10.0.10.1
      nameservers:
        addresses: [10.0.10.53]
    eth1:
      addresses:
        - 10.0.60.1/24
      # No default route — OT traffic stays local
```

Apply:
```bash
sudo netplan apply
```

**RHEL/CentOS (nmcli)**:
```bash
# IT interface
sudo nmcli con mod eth0 ipv4.addresses 10.0.10.100/24
sudo nmcli con mod eth0 ipv4.gateway 10.0.10.1
sudo nmcli con mod eth0 ipv4.dns 10.0.10.53
sudo nmcli con mod eth0 ipv4.method manual

# OT interface
sudo nmcli con mod eth1 ipv4.addresses 10.0.60.1/24
sudo nmcli con mod eth1 ipv4.method manual
# No gateway — OT traffic is local

sudo nmcli con up eth0
sudo nmcli con up eth1
```

---

## Step 2: Enable IP Forwarding

The gateway must forward packets between interfaces:

```bash
# Enable immediately
sudo sysctl -w net.ipv4.ip_forward=1

# Make persistent
echo 'net.ipv4.ip_forward = 1' | sudo tee /etc/sysctl.d/99-gateway.conf
sudo sysctl --system
```

Verify:
```bash
cat /proc/sys/net/ipv4/ip_forward
# Should output: 1
```

---

## Step 3: Install Firewall Backend

### nftables (recommended)

```bash
# Ubuntu/Debian
sudo apt-get install -y nftables
sudo systemctl enable nftables
sudo systemctl start nftables

# RHEL/CentOS
sudo dnf install -y nftables
sudo systemctl enable nftables
sudo systemctl start nftables
```

Verify:
```bash
sudo nft list ruleset
```

### iptables (legacy)

```bash
# Ubuntu/Debian
sudo apt-get install -y iptables iptables-persistent

# RHEL/CentOS
sudo dnf install -y iptables-services
sudo systemctl enable iptables
```

---

## Step 4: Leave Forwarding to Segmentra

Segmentra manages forwarded traffic for the devices this gateway protects. When a policy is deployed to the gateway:

- Forwarded traffic **to every IoT device assigned to the gateway** (OT/IoT page) is **dropped unless a FORWARD rule allows it**.
- Other forwarded traffic, such as Docker networks or routes to non-protected subnets, passes unchanged.
- Replies to allowed connections (established/related) always pass.

How it is implemented:

- **nftables:** `chain forward { type filter hook forward priority 0; policy accept; ... }` inside `table inet segmentra`, with a final `ip daddr @protected_v4 drop`. Like the rest of `table inet segmentra`, it is replaced atomically on each deploy.
- **iptables:** chain `SEGMENTRA-FWD`, reached from one jump at the top of `FORWARD`. An allow returns (`RETURN`) to `FORWARD`, a deny is `DROP`, and the protected devices get a final `-d <ip> -j DROP`.

**Do not** add a manual `policy drop` forward chain or `iptables -P FORWARD DROP` for the OT networks. Segmentra does not remove or override it: a drop in another nftables table, or in the built-in `FORWARD` policy, still drops traffic Segmentra allows. Every allowed flow would then need a second, manual accept rule. If you already have such a rule set, remove it or make sure it accepts what your Segmentra FORWARD rules allow.

> Until the first deployment, forwarding is not filtered by Segmentra. Assigning or unassigning a device on the OT/IoT page takes effect on the gateway's **next** deployment. If you need a safety net before the first deploy, deploy a version with no FORWARD rules as soon as the devices are assigned: everything forwarded to them is then denied.

---

## Step 5: Configure SSH Access for Segmentra

Create a dedicated user for Segmentra:

```bash
# Create user
sudo useradd -m -s /bin/bash segmentra

# Set up SSH key authentication
sudo mkdir -p /home/segmentra/.ssh
sudo chmod 700 /home/segmentra/.ssh
# (Paste the public key that matches the private key stored in Segmentra)
echo "ssh-ed25519 AAAA... segmentra@management" | sudo tee /home/segmentra/.ssh/authorized_keys
sudo chmod 600 /home/segmentra/.ssh/authorized_keys
sudo chown -R segmentra:segmentra /home/segmentra/.ssh
```

Store the matching private key (or a password) in **Admin → SSH Credentials**. Segmentra encrypts it at rest; see [security.md](security.md) for how credentials are stored and protected.

Configure passwordless sudo for firewall commands:

```bash
cat << 'EOF' | sudo tee /etc/sudoers.d/segmentra
segmentra ALL=(ALL) NOPASSWD: /usr/sbin/nft, /usr/sbin/nft *, /usr/sbin/iptables, /usr/sbin/iptables-save, /usr/sbin/iptables-restore, /bin/mkdir, /bin/cp, /bin/mv, /bin/chmod, /bin/touch, /bin/rm, /usr/bin/tee, /usr/bin/systemctl reload rsyslog, /usr/bin/systemctl restart rsyslog
EOF
sudo chmod 440 /etc/sudoers.d/segmentra
```

Test:
```bash
sudo -u segmentra sudo -n nft list ruleset
# Should work without password prompt
```

---

## Step 6: Configure Routing on OT Devices

OT devices behind the gateway need to know to route through it. There are two approaches:

### Option A: Gateway as Default Route (Simple)

Configure each OT device's default gateway to be the gateway server's OT interface IP:
- Gateway IP: `10.0.60.1`
- Most PLCs, HMIs, and cameras support setting a default gateway in their network configuration

### Option B: Static Routes on IT Side

If IT servers need to reach OT devices, add a route on the IT network's router:
```
# On the IT router / L3 switch:
ip route 10.0.60.0/24 via 10.0.10.100
ip route 10.0.61.0/24 via 10.0.10.100
ip route 10.0.62.0/24 via 10.0.10.100
```

---

## Step 7: Register in Segmentra

1. **Inventory → Hosts**: Add the gateway server
   - Hostname: `gw-ot-01.acme.corp`
   - Management IP: `10.0.10.100`
   - Firewall backend: `nftables`
   - Tag: `iot-gateway`

2. **Inventory → Hosts → Interfaces**: Add both NICs
   - `eth0` — role: `management`, IP: `10.0.10.100`
   - `eth1` — role: `data`, IP: `10.0.60.1`

3. **Admin → SSH Credentials**: Ensure a GLOBAL credential exists with the `segmentra` user

4. **Inventory → Check Readiness**: Verify the gateway is ready for deployments

---

## Step 8: Register IoT Assets

Go to **OT/IoT → Assets** and register the devices behind this gateway. Assign each device to the gateway.

---

## Multiple OT Zones

For multiple OT zones, the gateway needs additional interfaces or VLAN trunking:

### Option A: One Interface Per Zone

```
eth0 — IT (10.0.10.100/24)
eth1 — OT Level 1 (10.0.60.1/24) — PLCs
eth2 — OT Level 2 (10.0.61.1/24) — HMIs
eth3 — Building Systems (10.0.62.1/24) — HVAC, Cameras
```

### Option B: VLAN Trunking (Single Physical Interface)

```bash
# Create VLAN sub-interfaces on eth1
sudo ip link add link eth1 name eth1.60 type vlan id 60
sudo ip addr add 10.0.60.1/24 dev eth1.60
sudo ip link set eth1.60 up

sudo ip link add link eth1 name eth1.61 type vlan id 61
sudo ip addr add 10.0.61.1/24 dev eth1.61
sudo ip link set eth1.61 up

sudo ip link add link eth1 name eth1.62 type vlan id 62
sudo ip addr add 10.0.62.1/24 dev eth1.62
sudo ip link set eth1.62 up
```

Make persistent in Netplan:
```yaml
network:
  version: 2
  ethernets:
    eth1: {}
  vlans:
    eth1.60:
      id: 60
      link: eth1
      addresses: [10.0.60.1/24]
    eth1.61:
      id: 61
      link: eth1
      addresses: [10.0.61.1/24]
    eth1.62:
      id: 62
      link: eth1
      addresses: [10.0.62.1/24]
```

---

## Multiple Gateways

For redundancy or geographic separation, deploy multiple gateways:

```
┌───────────────┐     ┌─────────────────┐     ┌──────────────────┐
│  IT Network   │◄───►│  gw-ot-01       │◄───►│  Factory Floor   │
│               │     │  (primary)      │     │  PLCs, HMIs      │
│               │     └─────────────────┘     └──────────────────┘
│               │
│               │     ┌─────────────────┐     ┌──────────────────┐
│               │◄───►│  gw-ot-02       │◄───►│  Building Systems│
│               │     │  (secondary)    │     │  HVAC, Cameras   │
└───────────────┘     └─────────────────┘     └──────────────────┘
```

Both gateways are tagged `iot-gateway` in Segmentra. A single policy scoped to this tag deploys to both simultaneously.

---

## Security Hardening

### Disable Unnecessary Services

```bash
# Only SSH and firewall should be running
sudo systemctl disable --now apache2 nginx cups bluetooth avahi-daemon 2>/dev/null
```

### Restrict SSH Access

```bash
# /etc/ssh/sshd_config additions:
AllowUsers segmentra
PermitRootLogin no
PasswordAuthentication no
MaxAuthTries 3
```

### Enable Logging

```bash
# Log dropped packets (useful for troubleshooting blocked OT traffic)
# Segmentra's policies already include logging rules when log_mode is set
# For extra visibility, ensure rsyslog is running:
sudo systemctl enable rsyslog
```

### Monitor the Gateway

Add the gateway to your monitoring system (Prometheus node_exporter, Zabbix, etc.) to track:
- CPU/memory usage (important if handling high traffic volumes)
- Network throughput per interface
- Dropped packet counts
- Firewall rule hit counters

---

## Troubleshooting

### IoT Device Can't Communicate

1. Check if the gateway is forwarding: `cat /proc/sys/net/ipv4/ip_forward` (must be `1`)
2. Check the deployed rules: `sudo nft list ruleset` or `sudo iptables -L -n`
3. Check routing: `ip route` on the gateway, verify OT subnets are reachable
4. Run the **Troubleshoot → Simulate** check (source IP, device IP, port): it evaluates the gateway's FORWARD rules and shows the rule that decides, or the protected-device default deny
5. Run Firewall Learning on the gateway to see what traffic reaches the device (the gateway accepts and logs while learning)
6. Check the OT device's gateway setting. It should point to the gateway's OT interface IP
7. Check that the device is assigned to the gateway on the OT/IoT page and that the gateway was redeployed after the assignment

### Policy Deployment Fails

1. Verify SSH access: `ssh segmentra@10.0.10.100 "sudo nft list ruleset"`
2. Check the Segmentra deployment logs: **Deployments → (select deployment) → View Logs**
3. Verify the host is tagged `iot-gateway` and has the correct firewall backend setting

### Traffic Flows But Shouldn't

1. Check if there's a permissive rule: run **Security Audit** to find overly broad rules
2. Verify the device is protected: it must be assigned to the gateway (OT/IoT page), be enabled, have an IP address, and the gateway must have been redeployed since. Check `sudo nft list chain inet segmentra forward` (nftables) or `sudo iptables -S SEGMENTRA-FWD` and `sudo iptables -S FORWARD | head -2` (iptables) for the `protected_default_deny` rule and the jump
3. Check for bypasses: ensure no direct routes exist between IT and OT that skip the gateway. Segmentra can only filter traffic that is actually routed through the gateway
