# Security: Credentials, Secrets and Hardening

This page explains how Segmentra stores and uses sensitive data (SSH passwords and private keys, LDAP bind passwords, integration secrets) and how to harden a production installation.

> **Why this matters:** whoever controls Segmentra can change the firewall on every managed host, and Segmentra holds SSH credentials with `sudo` rights on all of them. Treat it like a bastion host or a configuration-management server: a small number of trusted admins, reachable only from a management network, and monitored.

## Summary

- SSH passwords, SSH private keys (and passphrases) and LDAP bind passwords are **encrypted at rest**. They are never stored in plain text.
- They live in the `secret_store` table, encrypted with **AES-256-GCM**.
- The encryption key comes from the `SEGMENTRA_KEK_B64` environment variable. It is never stored in the database.
- The API never returns secret values. Only administrators can manage SSH credentials.
- When a secret is needed to reach a host, it is decrypted in memory for that operation only.

## How secrets are stored

| Secret | Where | Format |
|---|---|---|
| SSH private key (and optional passphrase) | `secret_store` (type `SSH_KEY`), referenced by `ssh_credentials.private_key_secret_id` / `passphrase_secret_id` | AES-256-GCM |
| SSH password | `secret_store` (type `SSH_PASSWORD`), referenced by `ssh_credentials.password_secret_id` | AES-256-GCM |
| LDAP bind password | `secret_store` (type `LDAP_BIND`), referenced by `ldap_settings.bind_password_secret_id` | AES-256-GCM |
| User passwords (local login) | `users.password_hash` | bcrypt hash (not reversible) |

Each encrypted value is stored as `[1-byte format version][12-byte random IV][16-byte GCM authentication tag][ciphertext]`. Every secret gets a fresh random IV. The authentication tag means that tampering with the stored bytes is detected: decryption fails instead of returning modified data. The implementation is in `apps/api/src/services/crypto.ts` and `apps/api/src/services/secrets.ts`.

A stored SSH password in the database looks like random bytes, for example `019233da90faeba82a2ac6...`. The `01` at the start is the format version, followed by the IV, tag and ciphertext.

## The encryption key (`SEGMENTRA_KEK_B64`)

- **What it is:** 32 random bytes, base64-encoded. Generate one with `openssl rand -base64 32`.
- **Where it lives:** only in the API's environment (for Docker installs, the `.env` file next to `docker-compose.yml`). It is never written to the database, so a database dump or backup on its own does not reveal any secrets.
- **Production installs:** `./install.sh --production` (and `install.ps1`) generates the key into `.env` automatically. The API container refuses to start in production (`NODE_ENV=production`) if the key is missing.
- **Development fallback:** if the key is not set, Segmentra derives one from `JWT_SECRET` (SHA-256) and logs a warning at startup. This is only acceptable for local development. With the fallback, anyone who knows `JWT_SECRET` can decrypt the secrets, and changing `JWT_SECRET` makes all stored secrets unreadable.

**Operator checklist:**

1. Set `SEGMENTRA_KEK_B64` **before** storing any credentials.
2. **Back up `.env`** somewhere safe and separate from database backups. If the key is lost, the stored SSH and LDAP secrets can't be recovered and must be entered again.
3. Keep `.env` readable only by the account that runs Segmentra (`chmod 600 .env`).
4. There is no built-in key rotation. To change the key, set the new value, restart the API, and re-enter every SSH credential and the LDAP bind password.

## Who can see or change credentials

- **SSH credentials** (Admin → SSH Credentials, `/api/ssh-credentials`) can only be listed, created, changed or deleted by users with the `admin` role. The list returns names, usernames, auth method and scope, plus the IDs of the encrypted secrets, never the secret values.
- **LDAP settings** (`/api/admin/ldap-settings`) are admin-only. The bind password is never returned. Leaving the password field empty when saving keeps the stored password.
- **Integration and notification secrets** (API keys, webhook tokens, auth headers) are masked in API responses (for example `••••abcd`). Sending the masked value back on update keeps the stored value.
- Creating or changing credentials is recorded in the **Audit Log** (`SSH_CREDENTIAL_CREATE` and so on). The audit entry contains the credential name and username, never the secret.

## How secrets are used when connecting to hosts

Secrets are decrypted only when Segmentra needs to reach a host (deployments, readiness and compliance checks, firewall learning, policy tests, discovery):

- **Passwords** are passed to `ssh`/`scp` through `sshpass -e`, which reads them from an environment variable of that one child process. They do not appear in the process list (`ps`) or on the command line.
- **Private keys** have to be given to `ssh -i` as a file. Segmentra writes the decrypted key to a temporary file with permissions `0600`, in a private temporary directory, for the duration of the operation only, and deletes it afterwards (including on errors).
- **Ansible executor:** for the run of the playbook, key files and per-host password files (`host_vars/<host>.yml`, `0600`, directories `0700`) are written into that deployment's bundle directory, which the Ansible runner container reads. They are deleted as soon as the playbook finishes, whether it succeeded or failed. Passwords are never placed in the inventory file or on the command line.
- **Host-scoped credentials:** a credential can apply to all hosts (global) or to a single host. Segmentra uses the host's own credential if one exists, otherwise the newest global credential.

## Related protections

- **SSH host keys** are checked with "trust on first use" (`StrictHostKeyChecking=accept-new`): a host's key is recorded on the first connection, and later connections are refused if the key changes. The known_hosts file is set with `SEGMENTRA_KNOWN_HOSTS` (default `~/.ssh/known_hosts`; a Docker volume in production).
- **Least privilege on hosts:** use a dedicated account with `sudo` rights for the firewall tools rather than `root`. Key-based accounts need passwordless `sudo`. For password accounts, the same password is used for `sudo`.
- **Login protection:** JWT sessions expire after 12 hours. Failed logins are rate-limited. In production the API refuses weak or placeholder `JWT_SECRET` values and requires at least 32 characters.
- **Change control:** new policy versions must be approved by an `approver` or `admin` who did not create, edit or submit them. All actions are written to the Audit Log, which can be forwarded to a SIEM.
- **Outbound calls:** notification webhooks can't be pointed at loopback, link-local or cloud-metadata addresses, and the check happens at connection time so DNS rebinding doesn't work.

## Hardening a production install

### What the shipped images already do

- The API container runs as the non-root `node` user. The images are multi-stage builds, so compilers and dev dependencies are not in the runtime image.
- `.dockerignore` keeps `.env`, keys and local data out of the build context, so no secrets are baked into images.
- In the base `docker-compose.yml`, PostgreSQL and the API are published on `127.0.0.1` only. Browsers reach the API through nginx (`segmentra-web`).
- In production (`NODE_ENV=production`) the API refuses to start without a strong `JWT_SECRET` (32+ characters, no placeholder values) and `SEGMENTRA_KEK_B64`, and the seed doesn't create a default admin password.
- Secrets are encrypted at rest, SSH host keys are verified (trust on first use), failed logins are rate-limited, and every change is audited.

### Hardened compose override (`docker-compose.hardened.yml`)

The repository includes an override file that applies the container hardening below. Use it together with the base file:

```bash
docker compose -f docker-compose.yml -f docker-compose.hardened.yml up -d --build
```

It does the following:

| Setting | Effect |
|---|---|
| No Docker socket in `segmentra-app`; `segmentra-ansible-runner` is not started | Removes the biggest risk: the socket is root-equivalent on the Docker host. **Use the SSH Direct executor** (Admin → Deployment Executor → SSH Direct) before the first deployment. |
| `read_only: true` on all containers | Root filesystems can't be modified. Only the named volumes (database, bundles, SSH known_hosts) and small `tmpfs` mounts (`/tmp`, nginx cache, Postgres socket) are writable. Temporary SSH key files live in the API's `tmpfs /tmp`. |
| `cap_drop: [ALL]` | No Linux capabilities in the API container. The database and nginx get back only the few they need to start and switch to their unprivileged users. |
| `no-new-privileges:true` | Processes can't gain privileges through setuid binaries. |
| `pids_limit`, `mem_limit` | Limits the damage of a runaway or abused process. |
| No published ports for PostgreSQL and the API | Only nginx (port 80, or `WEB_PORT`) is reachable from outside the Docker network. |

It was tested with a full deployment flow through nginx: SSH password credential, readiness check, policy, approval, deployment to a target host. Requires Docker Compose 2.24 or later.

If you need the Ansible executor, don't apply the `segmentra-app` part of this file, or start the runner with `--profile ansible` and add the socket back. In that case run Segmentra on a **dedicated VM** so that the socket only exposes that VM.

### Checklist

**1. Network access**
- Serve the UI over **TLS**. Segmentra doesn't terminate TLS itself: put a reverse proxy or load balancer with a certificate in front of `segmentra-web`, or add TLS to its nginx configuration, and set `CORS_ORIGIN` to the HTTPS URL.
- Make the UI reachable only from a management network or VPN. Never expose it to the internet. Firewall the Docker host itself.
- Leave the API and PostgreSQL unpublished (the hardened override does this). If you set `API_BIND=0.0.0.0`, review `TRUST_PROXY`.

**2. Docker host**
- Prefer a dedicated VM for Segmentra. Keep the host OS and Docker up to date.
- Remove the Docker socket mount unless you use the Ansible executor (see above).
- Rebuild regularly to pick up base-image security updates: `docker compose build --pull && docker compose up -d`. Scan images with a scanner such as Trivy or Grype. For reproducible builds, pin base images by digest in the Dockerfiles.

**3. Accounts on managed hosts**
- Use a **dedicated SSH user** (for example `segmentra`), not `root`. Prefer **SSH keys** over passwords.
- Restrict where that user can log in from: in `authorized_keys` use `from="<Segmentra host IP>"` before the key, or in `sshd_config` use `AllowUsers segmentra@<Segmentra host IP>`. Set a **management VLAN** in Segmentra so the deployed baseline only allows SSH from that subnet.
- **sudo:** Segmentra currently runs its host scripts as `sudo -n sh -c '<script>'` (backups, apply, restore, log collection), so the SSH user needs **full passwordless sudo**. Restricting sudo to individual firewall commands is not possible today. Treat the Segmentra credential as root on every managed host and protect it accordingly.

**4. Secrets**
- Keep `.env` at `chmod 600`, owned by the account that runs Docker. Back it up **separately** from database backups. Losing `SEGMENTRA_KEK_B64` makes stored secrets unrecoverable; leaking it together with a database dump exposes them.
- For stricter setups, inject the variables from your secret manager or Docker secrets instead of a plain `.env` file.
- To rotate `JWT_SECRET`, change it and restart the API; all users are logged out. There is no built-in KEK rotation (see "The encryption key" above).
- Remove `SEGMENTRA_BOOTSTRAP_TOKEN` after the first admin exists.

**5. Database**
- Use a strong `POSTGRES_PASSWORD` (the installer generates one).
- Encrypt and restrict database backups. They contain encrypted secrets, policies and the audit log.

**6. Users and roles**
- Prefer LDAP / Active Directory with multi-factor authentication at the identity provider. Segmentra has no built-in MFA.
- Keep the number of `admin` users small. Give people separate `operator` and `approver` roles. Policy approvals already require a different person than the author.
- Disable accounts of people who leave. JWT sessions stay valid until they expire (12 hours).

**7. Monitoring**
- Forward the **Audit Log** to your SIEM (Integrations → SIEM). Alert at least on: SSH credential changes, user and role changes, approvals of high-risk deployments, and Firewall Learning or policy-test starts (these put hosts into log-only mode).
- Watch the API logs for repeated failed logins and restore failures.
- Back up the database and `.env`, and test a restore.

### Remaining gaps

- No built-in TLS or MFA (use a reverse proxy and your identity provider).
- No built-in rotation of `SEGMENTRA_KEK_B64`.
- The SSH user needs full sudo on managed hosts.
- Decrypted secrets are in the API process's memory while in use, so control of the API container means control of the credentials.

## Known gaps

- No built-in rotation of `SEGMENTRA_KEK_B64` (re-enter secrets after changing it).
- Secrets are decrypted inside the API process while in use, so anyone with control of the API container or host can read them. Protect that host accordingly.
- The Ansible executor needs the Docker socket (`/var/run/docker.sock`), which is root-equivalent on the Docker host. SSH-executor-only installs can remove that mount.
