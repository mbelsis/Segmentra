<div align="center">
  <img src="logo/segmentra-logo-dark.png" alt="Segmentra: microsegmentation for Linux" style="max-width: 560px; width: 100%; height: auto; border-radius: 10px;" />
</div>

# Segmentra

***Segmentra*** is a centralised, agentless, local **firewall and microsegmentation management** tool for Linux servers. It lets security and infrastructure teams define **host firewall policies** (allow/deny), and deploy them at scale to nftables, iptables, firewalld, and UFW, via SSH or Ansible Playbook. It extends enforcement to **Kubernetes** clusters, **Docker Swarm** nodes and Docker-published ports, and **OT/IoT devices** through gateway firewalls.

The platform enables:
- **Inventory creation and auto-tagging**
- **Policy versioning**
- **Policy impact analysis**
- **Policy troubleshooting**
- **Policy canary testing**
- **Policy templates and auto-assignment**
- **Segregation of duties**
- **Approval tracking**
- **Audit trails**
- **Backup and restore** of the whole configuration, into a fresh installation if needed
- **Compliance monitoring**
- **Topology building**
- **OT/IoT protection** through gateway firewalls, with device discovery
- **Notifications** to Slack and webhooks on approvals, deployments and expiry
- **Default access rules for each policy**

**Future plans** include more integration adapters (SOAR, vulnerability databases), Kubernetes workload discovery from the cluster, and a real email notification channel. See [Testing status and future work](docs/testing-status.md#not-implemented-yet).

To go further, see [how it works](docs/how-it-works.md), the [features](docs/features.md) and the rest of the [documentation](#documentation).

---

## Screenshots

<table>
  <tr>
    <td align="center" width="50%">
      <a href="docs/screenshots/01-dashboard.png"><img src="docs/screenshots/01-dashboard.png" alt="Dashboard" width="100%"></a><br>
      <b>Dashboard</b><br>
      <sub>Deployment statistics, managed hosts, IoT assets, pending approvals and the latest security audit</sub>
    </td>
    <td align="center" width="50%">
      <a href="docs/screenshots/05-inventory.png"><img src="docs/screenshots/05-inventory.png" alt="Inventory" width="100%"></a><br>
      <b>Inventory</b><br>
      <sub>Hosts with tags, VLAN, backend, SSH credential, compliance, and the <b>Active Rules</b> action</sub>
    </td>
  </tr>
</table>

See [all the screenshots](docs/screenshots.md).

---

## Installation

To install Segmentra, follow the instructions in the [Installation Guide](docs/installation.md).

## Running

```bash
./run.sh --start --development    # Start dev (API + UI + DB)
./run.sh --stop --development     # Stop dev
./run.sh --start --production     # Start production (all Docker containers; the API runs migrations on start)
./run.sh --stop --production      # Stop production
```

On Windows use `.\run.ps1` with the same options. For the first login, see [Default Login](docs/installation.md#default-login).

We have created real labs that you can deploy locally, so you can test Segmentra's capabilities and UI on real firewalls and real traffic without any servers of your own: see the [Test Labs](docs/lab.md). To simply look around the UI with sample records, load the [Demo Data](docs/demo-data.md).

---

## Documentation

| Document | Description |
|----------|-------------|
| [How Segmentra Works](docs/how-it-works.md) | The whole flow and the user journey, from an empty installation to enforced rules |
| [Features](docs/features.md) | Everything Segmentra can do, by area |
| [Screenshots](docs/screenshots.md) | The main pages of the application |
| [Installation Guide](docs/installation.md) | Dev and production setup, environment variables and other configuration |
| [User Guide](docs/guide.md) | Step-by-step usage for all features |
| [Test Labs](docs/lab.md) | One-command environments with real firewalls and traffic: base, IoT, Swarm and Kubernetes |
| [Demo Data](docs/demo-data.md) | A sample dataset to explore the UI without real servers |
| [Architecture](docs/Architecture.md) | Components, API endpoints, database schema, RBAC matrix |
| [Coexistence and Persistence](docs/coexistence-and-persistence.md) | Living alongside Docker, Kubernetes and fail2ban, and surviving reboots |
| [Native Firewall Managers](docs/firewall-managers.md) | Firewalld/UFW support, permanent ACLs, prerequisites, limitations, and verification |
| [Backup and Restore](docs/backup-restore.md) | Configuration export/import (Admin page, API) and full database dumps |
| [Security: Credentials, Secrets and Hardening](docs/security.md) | How credentials are encrypted, the encryption key, who can access them, and how to harden a production install |
| [OT/IoT Guide](docs/iot.md) | IoT microsegmentation with gateway model |
| [Gateway Setup](docs/gateway-setup-guide.md) | Linux gateway firewall configuration |
| [Kubernetes Guide](docs/kubernetes.md) | K8s NetworkPolicy management |
| [Docker Swarm Guide](docs/docker-swarm.md) | Swarm node profile and Docker-published ports |
| [Policy as Code](docs/policy-as-code.md) | YAML/JSON export and import, CLI and CI workflow |
| [Compliance Reports](docs/compliance-reports.md) | Evidence reports mapped to PCI DSS, ISO 27001, SOC 2 and HIPAA |
| [Status and Limitations](docs/testing-status.md) | Known limitations, what has been tested, what has not, and what is not implemented yet |
| [Tests](tests/README.md) | Integration and unit tests, what they cover and how to run them |
| [Ansible Playbook](docs/playbook-ansible.md) | Deployment playbook documentation |
| [Original Specification](docs/segmentra_fleet_microsegmentation_firewall_manager_full_specification.md) | The original product specification (historical; the implementation differs in places) |

---

## License

Segmentra is licensed under the [Apache License 2.0](LICENSE). Copyright 2026 Belsis Meletis (see [NOTICE](NOTICE)). To report a vulnerability, see [SECURITY.md](SECURITY.md).

### Disclaimer: provided "as is", no liability

**Segmentra is provided "AS IS", without warranty of any kind**, express or implied, including merchantability, fitness for a particular purpose, security, reliability and non-infringement.

**The creator and contributors accept no liability, to the maximum extent permitted by law,** for any damage, loss or claim of any kind arising from the use of, or inability to use, this software, whether in contract, tort or otherwise. This includes, without limitation:

- data loss or corruption;
- downtime, outages or loss of access to systems (including being locked out of hosts);
- security incidents, breaches or vulnerabilities, in Segmentra or in the systems it manages;
- misconfigured, missing or ineffective firewall rules, and traffic that is blocked or allowed by mistake;
- financial, business, legal or regulatory loss, including failed audits (compliance reports are supporting evidence, not an audit opinion or a certification).

Segmentra changes firewall rules on real hosts, clusters and gateways, and is a **work in progress** that has been tested mainly in lab environments (see [Testing status](docs/testing-status.md)). **You use it entirely at your own risk and responsibility.** Test it on non-critical systems first, keep out-of-band access, keep backups, and review every policy before deploying it.

Nothing in this README, the documentation or the user interface changes the terms of the [LICENSE](LICENSE), sections 7 (Disclaimer of Warranty) and 8 (Limitation of Liability).
