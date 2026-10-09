# Docker Swarm and Docker-published ports

## Overview

A Docker Swarm node is an ordinary Linux server, so Segmentra manages its host firewall over SSH like any other host. Two things about Docker make a plain host policy unsafe or ineffective on Swarm nodes, and Segmentra handles both:

| Problem | What happens without support | What Segmentra does |
|---|---|---|
| **Published ports bypass the host firewall.** Docker publishes a port (and the Swarm routing mesh does it on every node) with a NAT rule in `PREROUTING`; the traffic is then forwarded to the container and never reaches `INPUT` | An inbound rule such as "only 10.0.0.5 may reach 8080" has no effect on a published 8080. In the lab a client the policy did not allow reached the service on every node (12/12 requests) | **Apply inbound policy rules to Docker-published ports** (host setting): the same rules are applied to the forwarded, DNAT-ed traffic, matched on the published (original) port |
| **A default-deny policy breaks the cluster.** The nodes talk to each other on 2377/tcp (managers), 7946/tcp+udp and 4789/udp (VXLAN overlay) | The overlay network fails while `docker node ls` still shows every node *Ready* (existing control connections are allowed). In the lab only 4 of 12 routing-mesh requests and 3 of 9 overlay requests worked | **Swarm node profile**: those ports are always allowed from the other nodes of the same swarm, ahead of any policy rule |

Both are per-host settings (Inventory → host → **Docker**). They are independent: a plain Docker host can use only the published-port setting, and a Swarm node should normally use both.

**What is and is not integrated.** Segmentra manages the *host firewall* of the nodes over SSH. It does not talk to the Docker daemon or the Swarm API, does not know about services or stacks, and does not filter container-to-container or overlay-network traffic.

## Setting it up

1. **Register every node** of the swarm as a host (Inventory → Add Host) with an SSH credential and the firewall backend `iptables` or `nftables` (or `auto` when that resolves to one of them). The management SSH port you enter is allowed by the baseline rule, so keep it correct.
2. **Open the Docker section** of each host and set the **same Swarm name** on all nodes, each node's **role**, and the **Swarm address** (the `--advertise-addr` as the other nodes see it) if it differs from the management IP.
3. Tick **Apply inbound policy rules to Docker-published ports** on the nodes whose published services your policy should restrict.
4. **Write the policy** as for any host, for example "ALLOW tcp 8080 from 10.0.0.5". There is nothing Swarm-specific to add: the cluster ports are added automatically. Create a policy set that covers the nodes (a HOST_LIST or a tag such as `swarm-prod`), approve it and deploy it.
5. **Check the rollout** with the normal safety checks and canary mode: a wrong rule on the first node is visible before the rest follow. After adding, removing or re-addressing a node, **redeploy the other nodes** so their peer list is updated.

## Settings

| Field (UI) | API field | Meaning |
|---|---|---|
| Apply inbound policy rules to Docker-published ports | `dockerPublishedPorts` | Enforce the IN/BOTH rules on traffic Docker publishes with DNAT |
| Swarm name | `swarmCluster` | Name that groups the nodes of one swarm. Empty = not a Swarm node. The other **enabled** hosts with the same name are the peers |
| Swarm role | `swarmRole` | `manager` (also accepts 2377/tcp from its peers) or `worker` (default) |
| Swarm address | `swarmAddr` | The node's `--advertise-addr` as its peers see it. Defaults to the management IP. Set it when the swarm uses another network than the management one |
| Encrypted overlay networks | `swarmEncryptedOverlay` | Also allow IPsec ESP (IP protocol 50) between the nodes, needed for overlay networks created with `--opt encrypted` |

The **Docker Swarm** page (Infrastructure menu, `GET /api/hosts/swarms/overview`) lists the registered swarms with their nodes, repeats these steps and warns about a single-node swarm, a missing manager, disabled nodes, a mixed encrypted-overlay setting and nodes deployed before the swarm last changed (an estimate based on host edit times; any edit counts). It only reads the inventory. Register **every** node of the swarm as a host with the same Swarm name; peers are computed from the registered hosts. A node that is not registered is not allowed. When you add a node, redeploy the existing nodes so they allow it.

## What is generated

**iptables backend**

- `SEGMENTRA-IN`: after the loopback, established and management-SSH rules and before the policy rules, for each peer: `tcp 2377` (managers), `tcp 7946`, `udp 7946`, `udp 4789`, optionally `esp`.
- `SEGMENTRA-FWD` (published ports enabled): for each IN/BOTH rule that is not ICMP, a rule on `-m conntrack --ctstate DNAT` that matches the **original** destination port (`--ctorigdstport`), with the rule's source, protocol and interface scope; `ALLOW` returns, `DENY` drops. Then `RETURN` for traffic coming from Docker's own bridges (`docker0`, `docker_gwbridge`, `br-*`, so containers reaching a published port are not blocked), and finally the default: `DROP` (or `RETURN` when the host's default inbound action is accept). Replies of allowed connections pass first.
- **Two jumps** into `SEGMENTRA-FWD`: from `FORWARD` (as for gateways) and from `DOCKER-USER`. The second one matters: whenever a service publishes a port, Docker re-inserts its own `DOCKER-USER` and `DOCKER-INGRESS` jumps at the top of `FORWARD`, which pushes Segmentra's `FORWARD` jump below `DOCKER-INGRESS`'s `ACCEPT`. `DOCKER-USER` is the chain Docker documents for user rules and always keeps first, so the policy keeps applying to new published ports without a redeployment.
- Reboot persistence declares `DOCKER-USER` in the saved rules file (`iptables-restore` runs before Docker, which adopts the existing chain) and puts the jump before Docker's own rule. Remove and restore (rollback) handle the jump too.

**nftables backend**: the same rules in the `input` chain and a `forward` chain of `table inet segmentra` using `ct status dnat` and `ct original proto-dst`. The table is replaced atomically and does not depend on Docker's chains.

Drift detection treats a missing `DOCKER-USER` jump as "policy not present".

## Known limitations

- **What stays open between the nodes.** Only the Swarm ports (2377/tcp on managers, 7946 tcp and udp, 4789/udp, optionally ESP) are allowed, and only from the other registered, enabled nodes of the same swarm; everything else between nodes follows your policy. Container-to-container traffic across nodes travels inside the VXLAN tunnel on 4789/udp, which Segmentra allows but cannot inspect or restrict. The Docker Swarm page shows this note.

- **Peers come from the inventory.** The peers of a node are the other **enabled** hosts with the same Swarm name. A node that is not registered is not allowed. Disabling or deleting a node's host record makes the others stop allowing it after their next deployment, which cuts that node off from the swarm. Adding, removing or re-addressing a node requires redeploying the other nodes; Segmentra does not do it automatically, and it does not warn about a swarm node that is missing from the inventory.
- **Published ports become default-deny.** With the setting on, a published port that no IN rule allows is dropped for external clients, including ports a service starts publishing later (no redeployment is needed, or possible to forget). Add the rules before enabling it on a production node, and use the normal approval workflow.
- **Rules use published ports and client addresses.** Match the **published** port (for example `8080`), not the container's target port. A rule without ports allows all published ports from that source. Sources are the client addresses as the first node sees them: behind a load balancer or NAT that is the balancer's address, not the end client's. After the routing mesh forwards a request to a task on another node, that node sees only node-to-node overlay traffic, which the Swarm profile allows.
- **It covers all DNAT traffic from outside Docker's own bridges.** Other tools on the same host that DNAT traffic (libvirt or LXC port forwards, a Kubernetes node, manual DNAT rules) fall under the same default deny. Do not enable the setting on such hosts unless their traffic is allowed by a rule.
- **Inbound only.** OUT and ICMP rules are not applied to published ports. FORWARD rules (gateways) keep working as before. Traffic from containers on the host and the overlay is not restricted by these rules.
- **Learning and policy tests do not cover published ports.** Firewall learning (log-only) and policy test sessions still allow the Swarm ports but do not log or enforce published-port traffic.
- **Backends.** Only `iptables` and `nftables`. A host set to firewalld, or to UFW with published-port enforcement, fails to compile with a clear message instead of silently ignoring the setting. (UFW hosts can still use the Swarm profile.)
- **One address per node.** Only the single Swarm address of a node is allowed between peers. A separate data-path address (`--data-path-addr`), or peers reaching each other through NAT, is not handled.
- **No health check.** Segmentra does not verify that the swarm is healthy after a deployment. The lab showed that a broken overlay can leave `docker node ls` at *Ready*, so test service-to-service traffic after changing policies.
- **Existing rules in `DOCKER-USER` stay.** Segmentra inserts its jump at the top of `DOCKER-USER`, so its decision is made first. Your own rules in that chain still run after it for traffic Segmentra lets through. Docker's own chains and rules are never modified.
- The management SSH baseline is unchanged: the host's SSH port is always allowed from anywhere unless a management VLAN is configured.

## Testing

`tests/swarm-lab/` builds a 3-node Swarm on Docker Desktop (privileged Docker-in-Docker nodes with sshd, an overlay network, a published nginx service and two client containers):

```bash
tests/swarm-lab/lab.sh up        # about 40 s
node tests/swarm-lab/run.mjs     # npm run test:integration:swarm; creates and removes its own lab
tests/swarm-lab/lab.sh down
```

The integration test drives the real API and SSH executor and checks, among others: the allowed client reaches the published port on every node and a client the policy does not allow is blocked on every node; the overlay stays healthy without the policy mentioning any Swarm port; a port published later is blocked without a redeployment even after Docker reordered its `FORWARD` jumps; redeploying is idempotent; remove, backup and restore handle the `DOCKER-USER` jump and leave Docker's chain alone; the persistence rendering; and that each feature makes a difference (published ports reachable with enforcement off, overlay broken without the Swarm profile).

`npm run test:swarm-compile` unit-tests the generated rules for both backends.

## Not tested yet

These are implemented, but have not been verified:

- **Real Swarm clusters on separate machines or VMs, and reboots.** Only the Docker Desktop lab was used: all nodes share one kernel. Boot-time persistence and its ordering against Docker's start-up were not exercised (the saved-rules rendering is checked, an actual reboot is not).
- **Restarting or upgrading the Docker daemon.** The `DOCKER-USER` chain and the Segmentra jump in it are expected to survive, as Docker documents for that chain, but this was not tested. Service updates that publish ports (which do reorder `FORWARD`) were tested.
- **The nftables backend with Docker.** The generated nftables rules are unit-tested and were not run on a live Docker host.
- **Docker 28 and newer, Docker's experimental nftables firewall backend (`--firewall-backend=nftables`), and `iptables-legacy`.** The lab runs Docker 27.5 with `iptables-nft`.
- **Encrypted overlay networks** (the ESP rules are generated and syntax-checked, traffic was not tested), **host-mode published ports**, **IPv6 published ports**, and swarms using a dedicated data-path address.
- **Standalone Docker and Compose hosts** use the same published-port mechanism but were not tested separately.
- **The user interface** was checked by rendering the host form, not by a full create/edit/deploy session in a browser; the API path is covered by the integration test.

## Not supported yet

- Reading services, stacks and published ports from the Docker API (policies refer to port numbers, not services).
- Policies for traffic between containers or on overlay networks.
- Egress rules for published ports, and Docker published-port enforcement on the firewalld and UFW backends.
- Automatic updates of the peer list when the inventory changes (a redeployment is needed), and warnings about nodes missing from the inventory.
- Segmenting container-to-container traffic or restricting services by name.
