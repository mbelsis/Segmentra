# Tests

This directory contains the Docker-based integration test flow for Segmentra's SSH deployment path.

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
