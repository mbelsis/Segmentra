# Native Linux firewall managers

Segmentra supports `nftables`, `iptables`, `firewalld`, and `ufw`. The `auto` setting checks the active manager over privileged SSH first: firewalld, then UFW, then installed nftables, then iptables. Two active managers are an error. Failed detection fails the host's deployment instead of guessing a backend. Discovery leaves hosts with manager tooling on `auto` until readiness can inspect their active state.

All backends use the same Segmentra policy rules and address resolution. Native-manager backends are agentless: a root-owned Python helper runs once per SSH/Ansible operation, or once for the unattended rollback. No Segmentra daemon, boot service, or background agent is installed. The operating system's firewall manager loads the permanent ACL on boot, without contacting Segmentra.

## Requirements

Both native-manager backends require Python 3, systemd, usable sudo, and an already running/enabled firewall manager. Segmentra enables the selected native boot service when applying an enforced policy and verifies enablement. It does not install packages or activate a previously disabled firewall manager.

Firewalld needs its native policy API (`firewall-cmd --get-policies`) and its nftables backend, plus the `nft` binary for live enforcement readback. Older releases without policy support fail readiness. Segmentra does not use firewalld's deprecated direct interface. UFW requires `IPV6=yes` in `/etc/default/ufw` and both IPv4/IPv6 save/restore tools; it refuses to silently skip IPv6.

Before switching a host from a raw nftables/iptables deployment, remove the old Segmentra policy through its original backend. Native readiness refuses an existing `table inet segmentra` or direct INPUT/OUTPUT/FORWARD jumps to Segmentra iptables chains, which would otherwise leave two independently filtering policies.

## Permanent ACLs and reboot behavior

| Backend | Permanent Segmentra configuration | Boot loader |
| --- | --- | --- |
| firewalld | `/etc/firewalld/policies/segmentra-in.xml`, `segmentra-out.xml`, and, when needed, `segmentra-fwd.xml` | Enabled `firewalld.service` |
| UFW | Marked Segmentra blocks inside `/etc/ufw/before.rules` and `/etc/ufw/before6.rules` | Enabled `ufw.service`, with UFW itself enabled |

Apply writes the native permanent configuration, reloads the manager, verifies the Segmentra rules are live, enables the boot service, and checks runtime versus permanent state. Persistence failure fails deployment and triggers scoped restoration. The SSH executor also verifies a new SSH connection before cancelling its unattended rollback; the native Ansible path schedules a systemd rollback and resets its SSH connection before verifying reachability and persistence.

Backups and rollback contain only Segmentra's configuration. UFW restoration replaces only the marked blocks, preserving administrator edits elsewhere in those files. Firewalld restoration replaces only the three reserved Segmentra policy files. Removal deletes those same native permanent objects/blocks and reloads the manager, so they do not return on reboot. Expiry removal uses this path too.

The manual `scripts/restore-previous-policy.sh` command also recognizes native-manager JSON backups with `--latest` or an explicit timestamp/identifier and invokes the helper installed on the host.

Firewalld activation needs a reload, which normally discards unsaved runtime changes. Segmentra checks unrelated zones, policies, ipsets, and direct configuration against their permanent counterparts and refuses deployment/removal when it finds unsaved runtime differences. Resolve those differences deliberately before retrying. Do not edit the manager concurrently with an in-progress deployment or rollback.

## Rule semantics and limits

Firewalld uses native policies with priority `-500`, ordered rich rules, IPv4/IPv6 address expansion, management SSH allows, inbound default deny, outbound rules, and gateway FORWARD rules plus protected-device default deny. Its existing connection tracking and loopback handling remain in place. More-negative administrator policy priorities can take precedence. This native backend supports `ALL_INTERFACES` rules; it rejects interface-name/role scopes rather than applying a broader rule. Keep a raw backend for policies that need those scopes.

UFW uses its supported custom-rules framework. Segmentra hooks into `ufw-before-*` for IPv4 and `ufw6-before-*` for IPv6. Its own ordered chains enforce the policy before UFW's ordinary rules. Segmentra allows are terminal `ACCEPT` within this framework, so an allow does not require a duplicate UFW user rule. Unmatched outbound and unprotected forwarded traffic continue through UFW's existing rules. IPv6 neighbor-discovery/control traffic is part of the native UFW baseline. Existing UFW user rules/configuration are retained, but Segmentra's inbound default deny can still block traffic allowed by a later UFW rule.

Learning/log-only sessions are currently rejected for both native managers before changing enforcement. This prevents a temporary permissive policy from replacing the permanent enforced ACL. Ordinary policy simulation, deployment, drift/compliance, readback, and expiry removal support the new backends.

Drift hashes include Segmentra's permanent configuration and live kernel/native-manager state. Unrelated administrator rules and counters are excluded. Compliance also reports reboot persistence separately using the existing persistence fields; no database migration is needed.

## Verification

On 2026-10-09, the Docker Desktop integration suite passed against Ubuntu 24.04 containers running actual firewalld and UFW. Both completed SSH auto-detection/readiness, deployment/readback, IPv4/IPv6 allowed/blocked TCP checks, native reload, container restart persistence, drift, scoped rollback, removal, post-removal connectivity, and administrator-rule preservation. Native learning-session rejection was verified without changing live/permanent ACLs. This establishes the tested host SSH path, not native Ansible end-to-end, routed gateway enforcement, or a full systemd VM/server reboot.

Run `npm run test:firewall-managers` for compiler, IPv6, unsafe-scope, persistence-parser, drift, and UFW merge/removal regressions. Run `npm run test:integration:firewall-managers` for disposable Linux containers using actual firewalld and UFW. The integration uses the production SSH readiness, deployment, readback, and removal code with temporary test keys. It checks native reload, container restart, allowed/blocked IPv4/IPv6 TCP traffic, live drift, rollback, removal, post-removal connectivity, and administrator-rule preservation. Unsupported learning-session attempts must leave the live and permanent enforced ACL unchanged.

Use `npm run test:integration:firewall-managers -- --keep` to retain both containers in Docker Desktop. Test results appear in each container's Logs tab and `/var/backups/segmentra/test-results.log`. The sample ACL is redeployed after removal testing, allowing SSH and TCP 5432 while blocking TCP 5433. The runner prints retained container/network names and the temporary SSH-key directory; remove these resources after inspection.

The container suite uses actual native boot loaders after restart; no Segmentra code reapplies policy at startup. It substitutes a small test-only systemctl wrapper because the containers do not run systemd as PID 1. Container restart tests verify rules recover after losing the live network namespace; they are not full VM/server reboot tests. Validate a full reboot on each target OS family before broad production rollout.

Troubleshooting already evaluates host inbound/outbound policy and managed IoT gateway forwarding decisions. Drift/compliance already compare deployed and live state. A unified simulator that also evaluates Kubernetes NetworkPolicy/CNI enforcement remains a separate extension; the current host/gateway simulator does not evaluate that layer.
