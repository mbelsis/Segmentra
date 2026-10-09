# Tests

This directory contains security regression checks and the Docker-based integration test flow for Segmentra's SSH deployment path.

## Native Firewall Manager Checks

Run `npm run test:firewall-managers` for focused compiler/helper regressions and `npm run test:integration:firewall-managers` for disposable Ubuntu Linux containers running actual firewalld and UFW. The latter needs Docker, container NET_ADMIN capability, and local OpenSSH tools. It uses temporary SSH keys and loopback-only published SSH ports to exercise the production readiness, SSH deployment, readback, and auto-detected removal paths. It also checks native reload and container-restart persistence, IPv4/IPv6 traffic enforcement, drift, rollback, post-removal traffic, and preservation of administrator rules. Learning-session and log-only compilation attempts must be rejected without changing the enforced ACL, because native-manager learning is not yet supported. Containers, their test network, temporary keys, and known-host files are removed on completion or failure.

The containers use a test-only systemctl wrapper and native boot loaders on restart. This verifies persistent ACL loading without any Segmentra startup code, but does not substitute for an actual systemd VM/server reboot on each target distribution. See [native firewall managers](../docs/firewall-managers.md).

Run `npm run test:integration:firewall-managers -- --keep` to leave both containers running for Docker Desktop inspection. This retains the test network and temporary SSH keys, writes results into each container's logs and `/var/backups/segmentra/test-results.log`, and redeploys the sample enforced ACL after testing removal. The runner prints the retained resource names and temporary directory; remove those resources when finished. Without `--keep`, resources are cleaned up automatically.

## Kubernetes NetworkPolicy Checks

Run `npm run test:integration:k8s -- <kindnet|calico|cilium> [--keep] [--recreate]` against a running Segmentra API (default `http://localhost:8080/api`, admin `admin`/`admin123`; override with `SEGMENTRA_API`, `SEGMENTRA_ADMIN_USER`, `SEGMENTRA_ADMIN_PASSWORD`). It needs Docker, `kind` and `kubectl`, plus `cilium` (cilium-cli) for the Cilium run and internet access to fetch the Calico manifest.

Segmentra only generates NetworkPolicy manifests, so the test creates a 3-node kind cluster with the chosen CNI, generates policies through the real API, applies them with `kubectl` and probes real pod-to-pod TCP/UDP traffic. It covers CIDR/HOST/TAG/VLAN/`any` sources, comma-separated CIDRs, port lists and ranges, same-node and cross-node clients, selector peers for labelled workloads mapped to a TAG, skipped rules (DENY, ICMP, OUT, unresolvable sources), policy update and removal, and the per-CNI `ipBlock` warning. Run it once per CNI, because enforcement differs: Cilium does not apply `ipBlock` to in-cluster pod traffic, so the test expects those allows to be blocked there while selector peers are allowed. The cluster is deleted afterwards unless `--keep` is given.

The test also drives the cluster-management API: it stores credentials (a kubeconfig with a client certificate, and service-account tokens with read-write and read-only RBAC), tests the connection, applies, drift-checks and removes policies through Segmentra, and verifies that unmanaged same-named policies are never overwritten or deleted and that no credential material is ever returned. Run it against a development or disposable Segmentra stack: it creates users, hosts, tags and policy sets, and because approved policy versions cannot be deleted it archives its versions but leaves those records behind.

## Compliance Report Checks

Run `npm run test:integration:compliance` against a running Segmentra API (same settings as the other integration tests; no Docker lab needed). It builds a small fixture (two hosts without a deployment, IoT assets with and without a gateway, hostile and formula-like names) and checks, through the real API, that the reports reflect it in the counts, the lists and the control statuses, and that a report generated earlier does not change. It also checks generation and validation, roles (a viewer can read but not generate, an approver cannot run the live SSH check), immutability, period scoping and thresholds, the HTML (Content-Security-Policy, escaping) and the CSV datasets (formula neutralisation, the audit-event export). The tamper check edits a stored report with `docker exec` on the Segmentra database container and is skipped when that container is not found. It leaves its users, hosts and IoT assets in the development database. The live drift check inside a report is not covered. See [Compliance Reports](../docs/compliance-reports.md).

## Policy as Code Checks

Run `npm run test:integration:policy-code` against a running Segmentra API (same settings as the other integration tests; no Docker needed). It creates its own users, tags, hosts and policy sets (approved versions cannot be deleted, so it archives its versions and leaves those records behind: run it against a development stack). It checks, through the real API and the `scripts/segmentra-policy.mjs` CLI: that a dry run writes nothing, creating a policy set from a document, idempotency for YAML text, JSON and the `{content}` form, export determinism and the export-import round trip (including FORWARD destinations, log modes and interface scopes), the diff on changes and reordering detection, that an imported version is a DRAFT that needs approval and cannot be approved by the user who imported it, that all validation problems of a document are reported together with their paths, that a different scope is not applied unless asked, permissions (viewer and approver cannot import) and ambiguous names, and the CLI's `plan` / `apply` output and exit codes. See [Policy as Code](../docs/policy-as-code.md).

## Docker Swarm Checks

Run `npm run test:integration:swarm` against a running Segmentra API (same settings as the Kubernetes test) with Docker Desktop or Docker. `tests/swarm-lab/lab.sh up` builds the lab in about 40 seconds: three privileged Docker-in-Docker nodes (one manager, two workers) that also run sshd, an overlay network, an nginx service published on 8080, and two client containers; `lab.sh down` removes it. The test creates and removes its own lab (`--reuse` uses a running one, `--keep` leaves it up).

It registers the nodes with a Swarm profile and published-port enforcement, deploys policies through the real API and SSH executor, and verifies with real traffic that the allowed client reaches the published port on every node while another client is blocked, that the overlay stays healthy without the policy mentioning any Swarm port, that a port published later is blocked without a redeployment (even after Docker re-orders its `FORWARD` jumps), that redeploying is idempotent, that remove, backup and restore handle the `DOCKER-USER` jump and leave Docker's chain alone, how the saved-rules file is rendered, and that each feature makes a difference when switched off. A deployment that fails only with a transient SSH error is retried (the lab runs on a busy VM). `tests/swarm-lab/probe.mjs` is the exploratory version that prints measurements.

`npm run test:swarm-compile` unit-tests the generated iptables and nftables rules without Docker. The lab is one Docker Desktop VM, so a real reboot, multiple machines and Docker daemon restarts are not covered. `lab.sh` removes only its own three `[127.0.0.1]:223x` entries from `~/.ssh/known_hosts` when it is created or removed (the SSH executor records host keys with accept-new). See [Docker Swarm](../docs/docker-swarm.md).

## Security Regression Checks

Run `npm run test:security` from the repository root. This builds the API and its dependencies, then uses Node's built-in test runner without Docker or a database.

The checks cover production encryption-key validation, CORS defaults and origin validation, and bootstrap password hashing and initialization guards. Bootstrap route checks use a mocked database client and verify that the table lock precedes the first-user check; they do not exercise concurrent transactions against PostgreSQL.

Bootstrap requests now require a `password` of at least 12 characters and at most 72 UTF-8 bytes alongside the bootstrap `token`. The resulting admin can log in with that password after its initial JWT expires. Existing users are unaffected; an existing bootstrap account without a password needs an admin password reset.

## What This Integration Test Does

The integration test validates the real application flow from API setup to firewall enforcement on disposable targets.

It does not mock the deployment engine. Instead, it boots a temporary environment and drives the app through its real HTTP endpoints.

The test currently verifies:

- Docker is installed and reachable
- the `alpine:3.20` base image is available
- a temporary PostgreSQL database can be started for Segmentra
- the API container can boot against that database
- the database migrations and seed step complete successfully
- Segmentra can create local users, VLAN settings, hosts, policy sets, policy versions, rules, approvals, and deployments through the real API
- the SSH direct executor can deploy firewall rules using SSH password authentication
- the SSH direct executor can deploy firewall rules using SSH key authentication
- the deployed `iptables` rules inside the targets match the expected ACL shape
- live ICMP traffic between target containers is allowed or blocked according to the deployed rules

## What It Starts

The test stack is defined in [docker-compose.yml](docker-ssh-integration/docker-compose.yml).

It starts these temporary services:

- `db`: PostgreSQL for the test run
- `api`: the Segmentra API container built from the current repo
- `target-a`
- `target-b`
- `target-c`

Each target container is Alpine-based and is configured with:

- `iptables`
- OpenSSH server
- `sudo`
- `ping`
- both password and key-based login enabled for the same test user

## How The Test Works

The starter script is [run-docker-ssh-integration.mjs](run-docker-ssh-integration.mjs).

At a high level, it performs these steps:

1. Checks that Docker and Docker Compose are available.
2. Creates an ephemeral SSH keypair under `tests/docker-ssh-integration/.runtime/keys`.
3. Pulls `alpine:3.20` or uses the local cached image if Docker Hub is temporarily unreachable.
4. Builds and starts the temporary Docker stack (the API runs with `NODE_ENV=development` so the seed creates the default `admin` / `admin123` user).
5. Runs DB migrations and seeds the default admin user plus roles.
6. Waits for the API health endpoint to become ready.
7. Logs into the API as `admin`.
8. Creates:
   - an operator user
   - an approver user
   - a management VLAN
   - three hosts mapped to the three target containers
9. Forces the deployment executor setting to `ssh`.
10. Creates three separate host-scoped policies:
    - `target-a` allows ICMP only from `target-b`
    - `target-b` allows ICMP only from `target-c`
    - `target-c` allows no ICMP sources
11. Submits each policy for approval and approves it with a different user.
12. Seeds fake Docker (`DOCKER-USER`) and fail2ban (`f2b-sshd`) chains and jumps in each target, then runs one deployment round with a global SSH password credential.
13. Reads `iptables-save` output inside each target and checks the expected management SSH baseline and ICMP allow rules in `SEGMENTRA-IN`, that the `INPUT`/`OUTPUT` jumps exist exactly once, that the built-in policies are unchanged and that the Docker/fail2ban rules are untouched.
14. Runs real `ping` commands between the containers to confirm the traffic behavior matches the ACL.
15. Runs a second deployment round with a global SSH key credential.
16. Repeats the firewall inspection and live `ping` validation, then checks drift detection: each host is `compliant`, stays `compliant` after Docker chain churn, and is `drifted` once a Segmentra jump is removed.
17. Tears the stack down, unless `--keep` is passed.

## Traffic Behavior That Is Verified

The test intentionally checks both allowed and blocked traffic.

Expected results:

- `target-b -> target-a` ping succeeds
- `target-a -> target-b` ping fails
- `target-c -> target-b` ping succeeds
- `target-b -> target-c` ping fails
- `target-a -> target-c` ping fails

This proves the deployed ACL is directional and not just "host reachable or unreachable".

## How To Run It

If someone only wants to validate a new version of the app, the normal workflow is simply to run the starter script from the repository root. The script builds the current local source tree, boots the temporary Docker environment, runs the full integration scenario, and exits with failure if the new version breaks the tested deployment path.

From the repository root:

```bash
npm run test:integration:ssh-docker
```

If you want to keep the stack alive after the run for manual inspection:

```bash
npm run test:integration:ssh-docker -- --keep
```

## Requirements

You need:

- Docker Engine running
- Docker Compose available through `docker compose`
- enough permissions to build images, create containers, and create Docker networks

The script builds the API image from the current local source tree, so your current code changes are included in the test run.

## How To Tell The Test Completed Successfully

The simplest success signal is the script output.

A successful run ends with this line:

```text
[integration] Docker SSH integration test completed successfully
```

If `--keep` is not used, the script should then tear the stack down automatically.

If `--keep` is used, you should also see:

```text
[integration] Leaving the integration stack running because --keep was passed
```

## How To Confirm Success Manually

If you run with `--keep`, you can verify the result yourself.

### 1. Confirm the containers are up

```bash
docker compose -f tests/docker-ssh-integration/docker-compose.yml -p segmentra-it ps
```

### 2. Confirm the API is reachable

```bash
curl http://127.0.0.1:18080/api/health
```

Expected result: an HTTP 200 response.

### 3. Inspect deployed firewall rules

Example:

```bash
docker compose -f tests/docker-ssh-integration/docker-compose.yml -p segmentra-it exec -T target-a iptables-save
```

You should see:

- `-A INPUT -j SEGMENTRA-IN` and `-A OUTPUT -j SEGMENTRA-OUT` (once each); built-in policies stay `ACCEPT`
- a management SSH allow rule for `172.29.0.0/24` on port `22` in `SEGMENTRA-IN`, which ends with the default `DROP` (allow rules in Segmentra's chains use `-j RETURN`, so the packet goes back to `INPUT`, whose remaining rules and policy still apply)
- host-specific ICMP allow rules (`-j RETURN`) only where expected
- the fake `DOCKER-USER` / `f2b-sshd` chains and their jumps unchanged

### 4. Re-run the live ping checks manually

Examples:

```bash
docker compose -f tests/docker-ssh-integration/docker-compose.yml -p segmentra-it exec -T target-b ping -c 1 -W 1 172.29.0.31
docker compose -f tests/docker-ssh-integration/docker-compose.yml -p segmentra-it exec -T target-a ping -c 1 -W 1 172.29.0.32
```

Expected result:

- the first command succeeds
- the second command fails

## Files Involved

- [tests/run-docker-ssh-integration.mjs](run-docker-ssh-integration.mjs): starter script and test driver
- [tests/docker-ssh-integration/docker-compose.yml](docker-ssh-integration/docker-compose.yml): temporary integration stack
- [tests/docker-ssh-integration/target/Dockerfile](docker-ssh-integration/target/Dockerfile): Alpine SSH target image
- [tests/docker-ssh-integration/target/entrypoint.sh](docker-ssh-integration/target/entrypoint.sh): target runtime configuration
- [tests/docker-ssh-integration/README.md](docker-ssh-integration/README.md): narrower README for this specific stack

## Cleanup

If you ran with `--keep`, clean up manually with:

```bash
docker compose -f tests/docker-ssh-integration/docker-compose.yml -p segmentra-it down -v --remove-orphans
```

## Current Scope

This integration test currently covers the SSH direct deployment path.

It does not currently validate:

- the Ansible executor
- frontend UI flows
- rollback behavior after a failed deployment
- compliance/audit readback flows
- policy testing sessions

Those can be added later as separate integration scenarios rather than overloading this one.
