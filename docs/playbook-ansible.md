# Segmentra Ansible Playbook Documentation

## Overview

Segmentra uses an Ansible playbook to deploy firewall policies to target hosts. The playbook is located at `infra/ansible-runner/playbooks/apply-firewall.yml` and is executed inside the `segmentra-ansible-runner` Docker container.

## Playbook Location

- **File**: `infra/ansible-runner/playbooks/apply-firewall.yml`
- **Container**: `segmentra-ansible-runner`
- **Ansible Version**: Ansible Core 2.16.4 (installed in the container)

## How It's Invoked

The API invokes the playbook programmatically when a deployment is started:

```typescript
runAnsiblePlaybook({
  runnerContainer: 'segmentra-ansible-runner',
  inventoryPath: `/bundles/${deploymentId}/inventory.ini`,
  playbookPath: `/runner/playbooks/apply-firewall.yml`,
  stdoutPath,
  stderrPath
})
```

## Playbook Execution Flow

### 1. **Backup Directory Creation**

The playbook ensures a backup directory exists on each target host:
- **Path**: `/var/backups/segmentra`
- **Permissions**: `0700` (owner read/write/execute only)
- **Purpose**: Stores backups of current firewall rules before applying new ones

### 2. **Firewall Backend Detection**

The playbook automatically detects which firewall backend is available:
- Checks for `nftables` by running `command -v nft`
- Falls back to `iptables` if `nftables` is not available
- This detection determines which backup and apply methods are used

### 3. **Backup Current Rules**

Before applying new rules, the playbook creates a timestamped backup:

**For nftables hosts:**
- Backs up `/etc/nftables.conf` (if it exists)
- Exports current ruleset: `nft list ruleset > /var/backups/segmentra/nft.ruleset.<timestamp>`

**For iptables hosts:**
- Saves current rules: `iptables-save > /var/backups/segmentra/iptables.<timestamp>`

**Timestamp Format**: `YYYYMMDDHHMMSS` (e.g., `20260108143025`)

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

The playbook applies the policy file using the appropriate command:

**For nftables (`.nft` files):**
```bash
nft -f /etc/segmentra.policy
```

**For iptables (`.iptables` files):**
```bash
iptables-restore < /etc/segmentra.policy
```

### 7. **Automatic Rollback on Failure**

If applying the rules fails, the playbook automatically attempts to restore the previous backup:

**For nftables:**
- Finds the latest backup file: `nft.ruleset.<timestamp>`
- Restores it: `nft -f <backup_file>`

**For iptables:**
- Finds the latest backup file: `iptables.<timestamp>`
- Restores it: `iptables-restore < <backup_file>`

After rollback, the playbook fails with a clear error message: `"Firewall apply failed; rollback attempted"`

## Inventory File Structure

The playbook uses a dynamically generated Ansible inventory file for each deployment. The inventory is created at:
- **Path**: `/bundles/<deploymentId>/inventory.ini`

**Example inventory entry:**
```ini
[all]
server1 ansible_host=10.0.0.1 ansible_port=22 ansible_user=admin ansible_ssh_private_key_file=/bundles/<deploymentId>/ssh_key ansible_become=yes ansible_become_method=sudo segmentra_policy_file=/bundles/<deploymentId>/host_rules/server1.nft
server2 ansible_host=10.0.0.2 ansible_port=2222 ansible_user=admin ansible_ssh_private_key_file=/bundles/<deploymentId>/ssh_key ansible_become=yes ansible_become_method=sudo segmentra_policy_file=/bundles/<deploymentId>/host_rules/server2.iptables
```

**Key variables:**
- `ansible_host`: Management IP address of the host
- `ansible_port`: SSH port (from host's `ssh_port` field, default: 22)
- `ansible_user`: SSH username (from SSH credentials)
- `ansible_ssh_private_key_file`: Path to SSH private key in the bundle
- `ansible_become=yes`: Enables privilege escalation (sudo)
- `ansible_become_method=sudo`: Uses sudo for privilege escalation
- `segmentra_policy_file`: Path to the host-specific compiled policy file

## Deployment Bundle Structure

Each deployment creates a bundle directory with the following structure:

```
/bundles/<deploymentId>/
├── inventory.ini              # Ansible inventory file
├── ssh_key                    # SSH private key (0600 permissions)
├── manifest.json              # Deployment metadata
└── host_rules/
    ├── server1.nft            # nftables policy for server1
    ├── server2.iptables      # iptables policy for server2
    └── ...
```

## Error Handling

The playbook includes comprehensive error handling:

1. **Early validation**: Fails if policy file is not provided
2. **Backup before apply**: Always creates backups before making changes
3. **Automatic rollback**: Restores previous state if apply fails
4. **Clear error messages**: Provides actionable error messages for troubleshooting

## Security Considerations

- **SSH Key Permissions**: SSH private keys are stored with `0600` permissions
- **Policy File Permissions**: Policy files on hosts are set to `0600` (owner read/write only)
- **Backup Directory**: Backup directory has `0700` permissions (owner access only)
- **Privilege Escalation**: Uses `sudo` with `become: true` for all privileged operations
- **SSH Key Storage**: Keys are stored in deployment bundles, not on target hosts

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
   - Ensure SSH user has sudo privileges
   - Verify `ansible_become=yes` is set in inventory

3. **Policy File Not Found**
   - Check that policy compilation succeeded
   - Verify bundle directory structure is correct

4. **Rollback Failures**
   - Check backup directory exists and is writable
   - Verify backup files were created successfully

## Best Practices

1. **Always test policies** in a canary deployment before full rollout
2. **Monitor deployment logs** for any warnings or errors
3. **Keep backups** - the playbook creates backups, but consider additional backup strategies
4. **Verify SSH access** before deploying to ensure connectivity
5. **Use progressive deployments** for large fleets to minimize risk

---

## Extended Deployment Capabilities

### Policy Testing Mode

Segmentra can deploy policies in **log-only mode** for pre-enforcement testing. This uses the same compiler infrastructure but with `logOnlyMode: true`, which:
- Sets default policy to ACCEPT (nothing gets blocked)
- Adds logging rules that capture all traffic with `FW-AUDIT` prefix
- Allows the policy test analyzer to compare observed flows against policy rules

The Ansible playbook handles log-only policies identically to enforcement policies — the difference is entirely in the compiled ruleset content.

### Kubernetes NetworkPolicy Deployment

For Kubernetes environments, Segmentra generates and applies NetworkPolicy manifests directly via the K8s API — **the Ansible playbook is not used** for container microsegmentation. This is a separate deployment path through the `packages/k8s-executor` concept.

### OT/IoT ACL Deployment

For OT/IoT enforcement, Segmentra deploys vendor-specific ACLs to switches and gateways via SSH. This uses the same SSH credential infrastructure as host deployments but with a different compilation target (vendor ACL syntax vs. nftables/iptables).

