# Segmentra Ansible Playbook Documentation

## Overview

Segmentra uses an Ansible playbook to deploy firewall policies to target hosts. The playbook is located at `infra/ansible-runner/playbooks/apply-firewall.yml` and is executed inside the `segmentra-ansible-runner` Docker container.

## Playbook Location

- **File**: `infra/ansible-runner/playbooks/apply-firewall.yml`
- **Container**: `segmentra-ansible-runner`
- **Ansible Version**: Ansible Core 2.16.4 (installed in the container)

## How It's Invoked

The API invokes the playbook programmatically when a deployment is started and the deployment executor (Admin → Deployment Executor) is set to Ansible. The container name comes from `ANSIBLE_RUNNER_CONTAINER` (default `segmentra-ansible-runner`):

```typescript
runAnsiblePlaybook({
  runnerContainer: 'segmentra-ansible-runner',
  inventoryPath: `/bundles/${deploymentId}/inventory.ini`,
  playbookPath: `/runner/playbooks/apply-firewall.yml`,
  agentKeys,      // passphrase-protected keys to load into ssh-agent (may be empty)
  stdoutPath,
  stderrPath
})
```

## Playbook Execution Flow

The order below is simplified; see the playbook for the exact task list.

### 1. **Backup Directory Creation**

The playbook ensures a backup directory exists on each target host:
- **Path**: `/var/backups/segmentra`
- **Permissions**: `0700` (owner read/write/execute only)
- **Purpose**: Stores backups of current firewall rules before applying new ones

### 2. **Firewall Backend Check**

The backend comes from the compiled policy file (`.nft` or `.iptables`, set by the host's `firewall_backend`). The playbook only checks that the tool it needs is installed: `nft` for nftables, `iptables-restore` for iptables. Having both installed is fine; modern distributions ship `iptables-nft` next to `nft`.

### 3. **Backup Current Rules (Segmentra state only)**

Before applying, the playbook backs up only what Segmentra owns, using the `segmentra-nft.sh` / `segmentra-iptables.sh` scripts in `playbooks/files/`:

- **nftables:** `table inet segmentra` (or a marker that it didn't exist) to `/var/backups/segmentra/nft.ruleset.<timestamp>`. A full `nft list ruleset` is also saved as `<file>.full`, for reference only. If `/etc/nftables.conf` exists it is copied to `/var/backups/segmentra/nftables.conf.<timestamp>`.
- **iptables / ip6tables:** the `SEGMENTRA-IN` / `SEGMENTRA-OUT` chains (and `SEGMENTRA-FWD` on gateways that filter forwarded traffic) and whether their `INPUT` / `OUTPUT` / `FORWARD` jumps existed, to `/var/backups/segmentra/iptables.<timestamp>` (and `ip6tables.<timestamp>` when `ip6tables-save` / `ip6tables-restore` are installed). The full `iptables-save` is kept as `<file>.full`, for reference only.

**Timestamp format:** `YYYY-MM-DDTHH-MM-SS`

### 4. **Policy File Validation**

The playbook validates that a policy file path is provided:
- Checks for `segmentra_policy_file` variable
- Fails early if no policy file is specified
- Prevents accidental deployments without a policy

### 5. **Copy Policy File to Host**

The compiled policy file is copied from the deployment bundle to the target host:
- **Source**: Path in the deployment bundle (e.g., `/bundles/<deploymentId>/host_rules/<hostname>.nft`)
- **Destination**: `/etc/segmentra.policy` on the target host
- **Permissions**: `0600` (owner read/write only)
- **Method**: Uses Ansible's `copy` module

### 6. **Apply Firewall Rules**

- **nftables:** `nft -f /etc/segmentra.policy`. The file replaces `table inet segmentra` atomically; other tables are untouched.
- **iptables:** `iptables-restore --noflush` fills only `SEGMENTRA-IN` / `SEGMENTRA-OUT` (and `SEGMENTRA-FWD` when the policy has FORWARD rules), then a single jump is inserted at the top of `INPUT` / `OUTPUT` (and `FORWARD`). Segmentra's chains end in `RETURN`, so traffic they don't decide continues through the rest of the built-in chain. Other chains and the built-in chain policies are untouched. If the policy no longer has FORWARD rules, an existing `SEGMENTRA-FWD` chain and its jump are removed. The IPv6 file (`segmentra_ip6_policy_file`, copied to `/etc/segmentra.policy6`) is applied the same way with `ip6tables-restore`; if `ip6tables-restore` is missing, a warning is logged and only IPv4 is applied.

### 6b. **Reboot persistence (distribution's own service)**

After a successful apply, `files/segmentra-nft.sh persist` / `files/segmentra-iptables.sh persist iptables|ip6tables` copy Segmentra's live state into the files the distribution loads at boot: `/etc/nftables.d/segmentra.nft` (Debian/Ubuntu) or `/etc/nftables/segmentra.nft` (RHEL family) plus one `include` line in `/etc/nftables.conf` / `/etc/sysconfig/nftables.conf`, or Segmentra's lines merged into `/etc/iptables/rules.v4|v6` (iptables-persistent) or `/etc/sysconfig/iptables|ip6tables` (iptables-services). The matching service is enabled, never started. Nothing is installed and firewalld is never disabled; with firewalld active, a missing package or an unsupported distribution the task prints `SEGMENTRA_PERSIST_WARN …` lines and the play continues (these tasks never fail a host). The `Show reboot persistence result` task prints the result; the API records it per host with a read-only check after the run ("Survives reboot" column). See [Persistence across reboots](../README.md#persistence-across-reboots).

### 7. **Automatic Rollback on Failure**

If applying fails, the playbook restores this run's backup with the same scripts. Only Segmentra's own table or chains are put back to their previous state; Docker, Kubernetes and fail2ban rules are never replaced. The rescue then re-syncs reboot persistence to the restored state and reports whether the rollback itself succeeded.

Hosts still on the old full-table iptables design (before chain-based policies) get a full restore of the `filter` table only. The `nat` and other tables are not touched.

## Inventory File Structure

The playbook uses a dynamically generated Ansible inventory file for each deployment. The inventory is created at:
- **Path**: `/bundles/<deploymentId>/inventory.ini`

**Example inventory entry:**
```ini
[all]
server1 ansible_host=10.0.0.1 ansible_user=admin ansible_port=22 ansible_ssh_private_key_file=/bundles/<deploymentId>/.secrets/ssh_key_<credentialId>_... ansible_become=yes ansible_become_method=sudo segmentra_policy_file=/bundles/<deploymentId>/host_rules/server1.nft
server2 ansible_host=10.0.0.2 ansible_user=admin ansible_port=2222 ansible_connection=ssh ansible_become=yes ansible_become_method=sudo segmentra_policy_file=/bundles/<deploymentId>/host_rules/server2.iptables segmentra_ip6_policy_file=/bundles/<deploymentId>/host_rules/server2.ip6tables
```

**Key variables:**
- `ansible_host`: Management IP address of the host
- `ansible_port`: SSH port (from host's `ssh_port` field, default: 22)
- `ansible_user`: SSH username (from the host's effective SSH credential)
- `ansible_ssh_private_key_file`: Path to the key file in the bundle (key credentials only; one file per credential)
- `ansible_connection=ssh`: set for password credentials
- `ansible_become=yes`: Enables privilege escalation (sudo)
- `ansible_become_method=sudo`: Uses sudo for privilege escalation
- `segmentra_policy_file`: Path to the host-specific compiled policy file
- `segmentra_ip6_policy_file`: iptables hosts only, when the policy has IPv6 rules

Each host uses its effective SSH credential (explicit assignment, then host-, tag-, VLAN- and global-scoped credentials; see [security.md](security.md#how-secrets-are-used-when-connecting-to-hosts)).

**Passwords are never written into the inventory.** For password credentials, `ansible_password` and `ansible_become_password` are written to `/bundles/<deploymentId>/host_vars/<hostname>.yml` (`0600`, directory `0700`). The become password is the configured sudo password (login password or separate sudo password); with *sudo without password* the login password is still provided and only sent if sudo prompts. For key credentials with a separate sudo password, only `ansible_become_password` is written there.

**Passphrase-protected keys:** the key file stays encrypted on disk. The playbook then runs under `ssh-agent` inside the runner; each passphrase is passed to `docker exec` as an environment variable (`SEGMENTRA_KP_<n>`) and piped to `ssh-add`, so it never touches disk or a command line. A `<key>.pub` file is written next to the key so `ssh` uses the agent.

Key files, `.pub` files and `host_vars` files are deleted as soon as the playbook finishes, whether it succeeded or failed.

## Deployment Bundle Structure

Each deployment creates a bundle directory with the following structure:

```
/bundles/<deploymentId>/
├── inventory.ini              # Ansible inventory file
├── manifest.json              # Deployment metadata
├── ansible.stdout.log         # playbook output (ssh.stdout.log with the SSH executor)
├── ansible.stderr.log
├── .secrets/                  # key files (0600, dir 0700) - only while the playbook runs
├── host_vars/<hostname>.yml   # passwords (0600) - only while the playbook runs
└── host_rules/
    ├── server1.nft            # nftables policy for server1
    ├── server2.iptables       # iptables policy for server2
    ├── server2.ip6tables      # optional IPv6 rules for server2
    └── ...
```

## Error Handling

The playbook includes comprehensive error handling:

1. **Early validation**: Fails if policy file is not provided
2. **Backup before apply**: Always creates backups before making changes
3. **Automatic rollback**: Restores previous state if apply fails
4. **Clear error messages**: Provides actionable error messages for troubleshooting

## Security Considerations

- **SSH Key Permissions**: SSH private keys are written with `0600` permissions and removed after the run
- **Policy File Permissions**: Policy files on hosts are set to `0600` (owner read/write only)
- **Backup Directory**: Backup directory has `0700` permissions (owner access only)
- **Privilege Escalation**: Uses `sudo` with `become: true` for all privileged operations
- **SSH Key Storage**: Keys are written to the deployment bundle only for the duration of the run, never to target hosts
- **sudo rights**: the playbook runs every task with `become`, so the account needs full sudo rights (`ALL`); a sudoers rule limited to `nft` / `iptables` is not enough

## Execution Environment

The playbook runs inside the `segmentra-ansible-runner` Docker container:

- **Base Image**: `python:3.12-slim` (+ `openssh-client` and `sshpass`)
- **Ansible Version**: `ansible-core==2.16.4`
- **Host key checking**: enabled with trust-on-first-use — `ANSIBLE_SSH_ARGS` adds `-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/runner/ssh/known_hosts`; `/runner/ssh` is the `segmentra_ansible_ssh` volume, so learned keys survive rebuilds and a changed host key fails the run
- **Working Directory**: `/runner`
- **Volume Mounts**: 
  - Deployment bundles are mounted at `/bundles` (the same `segmentra_bundles` volume the API writes to with `BUNDLES_DIR=/bundles`)
  - Container name is fixed to `segmentra-ansible-runner` (`container_name` in docker-compose.yml) to match `ANSIBLE_RUNNER_CONTAINER`
  - Playbooks are copied to `/runner/playbooks`

## Integration with Segmentra

The playbook is integrated into Segmentra's deployment workflow:

1. **Policy Compilation**: Segmentra compiler generates host-specific policy files (`.nft` or `.iptables`)
2. **Bundle Generation**: API creates deployment bundle with inventory and policy files
3. **Playbook Execution**: API triggers Ansible playbook execution via Docker exec
4. **Status Tracking**: Deployment status is tracked per-host in the database
5. **Logging**: stdout/stderr are captured and stored for troubleshooting

## Troubleshooting

### View Playbook Logs

Deployment logs are stored in the bundle directory:
- **stdout**: `ansible.stdout.log`
- **stderr**: `ansible.stderr.log`

Access logs via the API endpoint:
```
GET /api/executions/:executionId/logs
```

### Common Issues

1. **SSH Connection Failures**
   - Verify SSH credentials are configured
   - Check network connectivity to target hosts
   - Verify SSH port is correct

2. **Permission Denied**
   - Ensure the SSH user has full sudo rights and that the credential's privilege escalation setting (sudo without password / with the login password / with a separate password) matches the host
   - Run **Check Readiness** on the host: it reports sudo problems (password required, wrong password, `requiretty`, not permitted)

3. **Policy File Not Found**
   - Check that policy compilation succeeded
   - Verify bundle directory structure is correct

4. **Rollback Failures**
   - Check backup directory exists and is writable
   - Verify backup files were created successfully

## Best Practices

1. **Test policies first** with Policy Impact Analysis, or deploy to a small set of hosts before the whole fleet
2. **Monitor deployment logs** for any warnings or errors
3. **Keep backups** - the playbook backs up only Segmentra's own table/chains; use your own backups for the rest of the host configuration
4. **Verify SSH access** before deploying (Check Readiness)
5. **Canary and progressive modes** are enforced only by the SSH Direct executor (hosts one by one, halting on failure). The Ansible executor deploys all hosts of a deployment in a single playbook run

---

## Extended Deployment Capabilities

### Policy Testing Mode

Segmentra can deploy policies in **log-only mode** for pre-enforcement testing (Policy Impact Analysis and Firewall Learning). This uses the same compiler with `logOnlyMode: true`, which:
- Accepts all traffic (nothing gets blocked)
- Logs matching traffic with an `FW-AUDIT` prefix
- Allows the policy test analyzer to compare observed flows against policy rules

Log-only policies are always applied over direct SSH (`packages/executor/src/audit-ssh.ts`), not through the Ansible playbook, regardless of the deployment executor setting.

### Kubernetes NetworkPolicy Deployment

For Kubernetes clusters, Segmentra generates a NetworkPolicy manifest (Ingress only) from an approved policy version and stores it for you to apply with `kubectl`; it does not connect to the cluster, and **the Ansible playbook is not used**. See [kubernetes.md](kubernetes.md).

### OT/IoT ACL Deployment

Linux IoT/OT gateways are regular inventory hosts: their FORWARD rules are compiled into the same nftables/iptables policy and deployed by this playbook (or the SSH executor). See [iot.md](iot.md).

Enforcement points (switches, firewalls) are not configured by Segmentra: `POST /api/enforcement-points/:id/deploy-acl` only records an ACL with status `PENDING` for manual application on the device.

