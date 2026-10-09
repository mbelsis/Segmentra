# Security: Credentials, Secrets and Hardening

This page explains how Segmentra stores and uses sensitive data (SSH passwords and private keys, LDAP bind passwords, integration secrets) and how to harden a production installation.

> **Why this matters:** whoever controls Segmentra can change the firewall on every managed host, and Segmentra holds SSH credentials with `sudo` rights on all of them. Treat it like a bastion host or a configuration-management server: a small number of trusted admins, reachable only from a management network, and monitored.

## Summary

- SSH passwords, SSH private keys, key passphrases, sudo passwords, LDAP bind passwords and the configuration of integrations and notification channels (API keys, webhook URLs, auth headers) are **encrypted at rest**. They are never stored in plain text.
- They live in the `secret_store` table, encrypted with **AES-256-GCM**.
- The encryption key comes from the `SEGMENTRA_KEK_B64` environment variable. It is never stored in the database.
- The API never returns secret values. Only administrators can manage SSH credentials.
- When a secret is needed to reach a host, it is decrypted in memory for that operation only.

## How secrets are stored

| Secret | Where | Format |
|---|---|---|
| SSH private key | `secret_store` (type `SSH_KEY`), referenced by `ssh_credentials.private_key_secret_id` | AES-256-GCM |
| SSH key passphrase (optional) | `secret_store` (type `SSH_KEY_PASSPHRASE`; older rows `SSH_KEY`), referenced by `ssh_credentials.passphrase_secret_id` | AES-256-GCM |
| SSH password | `secret_store` (type `SSH_PASSWORD`), referenced by `ssh_credentials.password_secret_id` | AES-256-GCM |
| Separate sudo password (optional) | `secret_store` (type `SUDO_PASSWORD`), referenced by `ssh_credentials.sudo_password_secret_id` | AES-256-GCM |
| LDAP bind password | `secret_store` (type `LDAP_BIND`), referenced by `ldap_settings.bind_password_secret_id` | AES-256-GCM |
| Integration config (e.g. AbuseIPDB `apiKey`, SIEM host/port) | whole config object as JSON in `secret_store` (type `INTEGRATION_CONFIG`), referenced by `integrations.config_secret_id` | AES-256-GCM |
| Notification channel config (Slack/webhook URL incl. tokens, `authHeader`, `customHeaders`) | whole config object as JSON in `secret_store` (type `NOTIFICATION_CONFIG`), referenced by `notification_channels.config_secret_id` | AES-256-GCM |
| User passwords (local login) | `users.password_hash` | bcrypt hash (not reversible) |

Each encrypted value is stored as `[1-byte format version][12-byte random IV][16-byte GCM authentication tag][ciphertext]`. Every secret gets a fresh random IV. The authentication tag means that tampering with the stored bytes is detected: decryption fails instead of returning modified data. The implementation is in `apps/api/src/services/crypto.ts` and `apps/api/src/services/secrets.ts`.

For integrations and notification channels the plain `config` column only keeps a **masked display copy** (for example `{"apiKey": "••••abcd"}`, `{"url": "https://hooks.slack.com/services/••••wxyz", "authHeader": "••••"}`); it is never used to contact anything. Masked are values under secret-like keys (`apiKey`, `token`, `secret`, `password`, `authHeader`, `authorization`, `credential`, `privateKey`), all `customHeaders` values, and inside URLs the userinfo password, token-like query parameters (`token`, `key`, `sig`, `code`, ...), Slack/Teams/Discord webhook paths and any opaque token-like path segment. Non-secret parts (SIEM host and port, the webhook host and plain path) stay readable there. Rows saved by versions before migration 031 are encrypted once by the API at startup (`[Secrets] Encrypted plaintext config of N integration(s) and M notification channel(s)` in the log); the step is idempotent and safe with several API replicas. Deleting an integration or channel deletes its encrypted config.

A stored SSH password in the database looks like random bytes, for example `019233da90faeba82a2ac6...`. The `01` at the start is the format version, followed by the IV, tag and ciphertext.

## The encryption key (`SEGMENTRA_KEK_B64`)

- **What it is:** 32 random bytes, base64-encoded. Generate one with `openssl rand -base64 32`.
- **Where it lives:** only in the API's environment (for Docker installs, the `.env` file next to `docker-compose.yml`). It is never written to the database, so a database dump or backup on its own does not reveal any secrets.
- **Production installs:** `./install.sh --production` (and `install.ps1`) generates the key into `.env` automatically. The API container refuses to start in production (`NODE_ENV=production`) if the key is missing.
- **Development fallback:** if the key is not set, Segmentra derives one from `JWT_SECRET` (SHA-256) and logs a warning at startup. This is only acceptable for local development. With the fallback, anyone who knows `JWT_SECRET` can decrypt the secrets, and changing `JWT_SECRET` makes all stored secrets unreadable.

**Operator checklist:**

1. Set `SEGMENTRA_KEK_B64` **before** storing any credentials.
2. **Back up `.env`** somewhere safe and separate from database backups. If the key is lost, the stored SSH, LDAP, integration and notification secrets can't be recovered and must be entered again.
3. Keep `.env` readable only by the account that runs Segmentra (`chmod 600 .env`).
4. There is no built-in key rotation. To change the key, set the new value, restart the API, and re-enter every SSH credential, the LDAP bind password and the configuration of every integration and notification channel.

## Who can see or change credentials

- **SSH credentials** (Admin → SSH Credentials, `/api/ssh-credentials`) can only be listed, created, changed or deleted by users with the `admin` role. The list returns names, usernames, auth method, privilege escalation mode (`sudo_mode`), scope ("Applies to") with the tag / VLAN / host name, priority, how many hosts are explicitly assigned to it, whether discovery uses it, and the flags `has_passphrase` / `has_sudo_password`; neither secret values nor the IDs of the encrypted secrets are returned. Editing a credential can change its name, scope, priority, sudo settings, key passphrase and (for password credentials) the login password; a private key cannot be replaced (add a new credential instead).
- **Assigning a credential to a host** (Inventory → edit host → *SSH credential*, `sshCredentialId` on `/api/hosts`) is admin-only as well; operators get `403`. Every role that can see inventory sees which credential a host uses (`effective_credential` in the host list and detail: name, scope, auth method, sudo mode and why it was chosen), never the secret.
- **Deleting a credential** is refused with `409` while a discovery target set uses it (`credential_in_use_by_discovery`), a host is explicitly assigned to it (`credential_assigned_to_hosts`) or an enforcement point uses it (`credential_used_by_enforcement_points`), so nothing silently switches credentials. Encrypted secrets that no other credential shares are deleted with it.
- **LDAP settings** (`/api/admin/ldap-settings`) are admin-only. The bind password is never returned. Leaving the password field empty when saving keeps the stored password.
- **Integration and notification secrets** (API keys, webhook URLs with tokens, auth headers, custom header values) are admin-only, stored encrypted (see the table above) and masked in API responses (for example `••••abcd`). On update, sending the masked value back (or omitting a secret key) keeps the stored value, sending a new value replaces it, and an empty string clears it. A webhook URL equal to the masked form of the stored URL keeps the stored URL.
- Creating, changing or deleting credentials is recorded in the **Audit Log** (`SSH_CREDENTIAL_CREATE`, `SSH_CREDENTIAL_UPDATE`, `SSH_CREDENTIAL_DELETE`). The audit entry contains the credential name, username, auth method, sudo mode, scope (old and new on a scope change) and whether a password / passphrase / sudo password was set or changed, never the secret. Host credential assignments appear in `HOST_UPDATE` entries (`sshCredentialId`).

## How secrets are used when connecting to hosts

Secrets are decrypted only when Segmentra needs to reach a host (deployments, readiness and compliance checks, firewall learning, policy tests, discovery):

- **Passwords** are passed to `ssh`/`scp` through `sshpass -e`, which reads them from an environment variable of that one child process. They do not appear in the process list (`ps`) or on the command line.
- **Private keys** have to be given to `ssh -i` as a file. Segmentra writes the key **exactly as stored** to a temporary file with permissions `0600`, in a private temporary directory, for the duration of the operation only, and deletes it afterwards (including on errors). A passphrase-protected key stays encrypted in that file.
- **Key passphrases** are handed to OpenSSH through its askpass mechanism: `SSH_ASKPASS` points to a small helper script (in a private `0700` temp directory, no secret inside) and `SSH_ASKPASS_REQUIRE=force` (OpenSSH 8.4+; for older clients the child runs without a controlling terminal and with `DISPLAY` set). The helper prints the passphrase from an environment variable of that one `ssh`/`scp` child process, and only answers passphrase prompts. So the decrypted key exists only inside the `ssh` process, and the passphrase is never on disk or on a command line. For passphrase keys, `BatchMode` is not used (it disables askpass); instead only public-key authentication is allowed and one passphrase attempt is made. When a credential is saved, the key and passphrase are checked with `ssh-keygen -y` the same way; a wrong or missing passphrase is rejected (`invalid_key_or_passphrase`).
- **Privilege escalation (sudo):** each credential has a mode: *sudo without password* (`sudo -n sh -c '…'`), *sudo with the login password* (password credentials only) or *sudo with a separate password*. With a password, root steps run as `sudo -k -S -p '' sh -c '…'` and the password is written as the **first line of the remote command's standard input**: it never appears in the remote or local process list, on a command line, in a file on the host, or in logs. `-k` makes sudo ignore cached credentials so it always consumes that line, and the root script starts with `exec </dev/null`, so the password cannot reach the script even if sudo did not ask for it. Each step that needs root is one `sudo sh -c` invocation, so the password is sent once per step. The automatic lockout revert is scheduled from that root shell (`systemd-run` / `nohup`) and needs no password when it fires.
- **Output scrubbing:** the stdout/stderr returned from hosts (deployment logs, readiness and error messages) has every secret of that credential (login password, key passphrase, sudo password) replaced by `********` before it is stored or returned. sudo refusals are reported as readable errors (wrong sudo password, sudo needs a password but the credential is set to passwordless, `requiretty`, account not allowed to run `sh` as root).
- **Ansible executor:** for the run of the playbook, key files (as stored, so passphrase-protected keys stay encrypted) and per-host password files (`host_vars/<host>.yml` with `ansible_password` and/or `ansible_become_password`, `0600`, directories `0700`) are written into that deployment's bundle directory, which the Ansible runner container reads. They are deleted as soon as the playbook finishes, whether it succeeded or failed. Passwords are never placed in the inventory file or on the command line. The become (sudo) password is the configured sudo password; with *sudo without password* the login password of a password credential is still provided (Ansible only sends it if sudo prompts).
- **Ansible with passphrase-protected keys:** the playbook runs under `ssh-agent` inside the runner (`docker exec … ssh-agent -t <timeout> sh -c '<loader>' … ansible-playbook …`). Each passphrase is passed as `docker exec -e SEGMENTRA_KP_<n>` (variable name only; Docker reads the value from the API process's environment) and piped to `ssh-add` with the shell builtin `printf`, so it is never on disk or on a command line. The public half of the key (`<key>.pub`) is written next to the key file so `ssh` uses the agent for it. The agent, and with it the decrypted key, ends with the playbook (keys also expire from the agent shortly after the run's timeout).
- **Which credential is used for a host:** every SSH connection to a managed host (readiness, deployments, drift/compliance checks, policy expiry, Firewall Learning, policy tests, troubleshooting, Ansible runs) picks the credential the same way:
  1. a credential **explicitly assigned** to the host (Inventory → edit host; discovery sets this for the hosts it imports);
  2. a credential scoped to **that host** (*A specific host*);
  3. a credential scoped to **one of the host's tags** (*Hosts with tag*);
  4. a credential scoped to **the host's VLAN** (*Hosts in VLAN*);
  5. the **global** default (*All hosts*).

  Within one level the highest **priority** wins, then the newest credential (for example a host carrying two tags that both have a credential). Credentials set to *Not assigned (manual use)* are never chosen automatically: they are only used by discovery target sets and for hosts they are explicitly assigned to. Adding a tag-, VLAN- or host-scoped credential therefore only affects the hosts it matches; adding a new global credential changes the default for every host that has nothing more specific. Note that tags can be added by tag rules, so a tag-scoped credential follows those rules too. A credential whose tag, VLAN or host is deleted matches nothing (the list shows it as *(deleted)*).

## Related protections

- **SSH host keys** are checked with "trust on first use" (`StrictHostKeyChecking=accept-new`): a host's key is recorded on the first connection, and later connections are refused if the key changes. The known_hosts file is set with `SEGMENTRA_KNOWN_HOSTS` (default `~/.ssh/known_hosts`; a Docker volume in production).
- **Dedicated account on hosts:** use a dedicated SSH account rather than `root`, with an SSH key (optionally passphrase-protected) or a password. It needs **full sudo rights** because Segmentra runs `sh` as root through sudo; sudo may require a password (set *Privilege escalation* on the credential) or be passwordless. No agent is installed on the hosts.
- **Agentless host changes:** Segmentra installs no permanent daemon, service, timer, cron job, or boot script. It writes root-owned policy artifacts and scoped backups/helpers under `/var/backups/segmentra/` (`0700`). The native firewalld/UFW helper requires Python 3 and runs only during an operation or unattended rollback. Lockout protection may use a transient one-shot systemd timer; that is not a boot agent.
- **Native firewalld/UFW boot persistence:** firewalld loads Segmentra's permanent XML policies from `/etc/firewalld/policies/`; UFW loads its marked blocks from `/etc/ufw/before.rules` and `/etc/ufw/before6.rules`. Segmentra reloads the active manager, verifies live and saved state, enables/verifies its native boot service, and rolls back on persistence failure. Firewalld operations refuse unrelated unsaved runtime changes. At boot only the native manager runs, without contacting Segmentra. Removal deletes Segmentra's permanent objects/blocks and reloads the manager while retaining other administrator configuration.
- **Raw nftables/iptables boot persistence:** only Segmentra's include/file or saved chain/jump lines are written to the distribution's boot configuration. The corresponding `nftables`, `netfilter-persistent`, or `iptables`/`ip6tables` service is enabled, never started/restarted by Segmentra. Other saved lines are retained. Segmentra never installs target packages or disables firewalld; use its native backend on firewalld-managed hosts. Raw learning/log-only policies are not persisted, and native learning attempts are rejected before changing enforcement. See [Persistence across reboots](../README.md#persistence-across-reboots) and [native firewall managers](firewall-managers.md).
- **Login protection:** JWT sessions expire after 12 hours. Failed logins are rate-limited. In production the API refuses weak or placeholder `JWT_SECRET` values and requires at least 32 characters.
- **Change control:** new policy versions must be approved by an `approver` or `admin` who did not create, edit or submit them. Changes are written to the Audit Log, and every Audit Log entry is also forwarded to the enabled SIEM integrations (see Monitoring below).
- **Outbound calls:** notification webhooks can't be pointed at loopback, link-local or cloud-metadata addresses (RFC1918 private ranges are allowed, since Segmentra is on-premise), and the check happens at connection time so DNS rebinding doesn't work. `SEGMENTRA_ALLOW_PRIVATE_WEBHOOKS=true` disables this check; leave it unset in production.

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
- **sudo:** Segmentra runs its host scripts as `sudo sh -c '<script>'` (backups, apply, restore, log collection), so the SSH user needs **full sudo rights**; restricting sudo to individual firewall commands is not possible today. Two good setups: a normal admin-style account whose sudo asks for a password (choose *sudo with the login password* or *sudo with a separate password* on the credential; a stolen key alone is then not root), or a dedicated service account with `NOPASSWD: ALL` restricted by `from=`/`AllowUsers` as above. Don't set `Defaults requiretty` for this account. Either way, treat the Segmentra credential as root on every managed host and protect it accordingly.

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
- Disable accounts of people who leave: deactivating a user blocks their sessions immediately (every request re-checks that the user is active and re-reads their roles). Changing or resetting a password does **not** end existing sessions; those tokens stay valid until they expire (up to 12 hours). If a password was compromised, deactivate the account and keep it deactivated for 12 hours, because reactivating it earlier makes the old tokens valid again.

**7. Monitoring**
- Configure a **SIEM integration** (Integrations). **Every** Audit Log entry is forwarded (RFC 5424 syslog over UDP or TCP) to each enabled SIEM integration: SSH credential, user/role, LDAP, policy, approval, inventory, integration and deployment events alike, whichever code path wrote them. Alert at least on deployments (especially high-risk ones), SSH credential and role changes, Firewall Learning starts (they put hosts into log-only mode) and restore failures.
- **How forwarding works:** a database trigger on `audit_events` sends `pg_notify('segmentra_audit', <event id>)` for every inserted row (only after the inserting transaction commits). Each API process keeps one dedicated database connection that `LISTEN`s on that channel, loads the row and the actor's username, and sends it. The row is first claimed with `UPDATE audit_events SET siem_forwarded_at = now() WHERE id = … AND siem_forwarded_at IS NULL`, so with **several API replicas** each event is still sent only once (by whichever replica claims it). If the listen connection drops it reconnects with backoff (1 s up to 30 s). A catch-up sweep (at startup, after each reconnect and every minute) sends events of the **last 60 minutes** that were not forwarded yet; older unforwarded events are not sent. Consequences: events written while no SIEM integration is enabled are sent once one is enabled if they are less than 60 minutes old; if every SIEM collector rejects an event (e.g. TCP collector down) it is retried by the sweep within that window; with several SIEM integrations, an event that reached at least one of them is not retried for the others (UDP delivery can't be confirmed at all). Secret-like metadata keys are masked in the syslog message as an extra safeguard; audit metadata never contains secret values (only flags such as `passwordChanged`).
- Watch the API logs for repeated failed logins and restore failures.
- Back up the database and `.env`, and test a restore.

### Remaining gaps

- No built-in TLS or MFA (use a reverse proxy and your identity provider).
- No built-in rotation of `SEGMENTRA_KEK_B64`.
- The SSH user needs full sudo rights on managed hosts (with or without a sudo password).
- Changing or resetting a password does not revoke existing sessions (tokens stay valid for up to 12 hours); deactivating the user blocks them only while it stays deactivated.
- Decrypted secrets are in the API process's memory while in use, so control of the API container means control of the credentials.
- The Ansible executor needs the Docker socket (`/var/run/docker.sock`), which is root-equivalent on the Docker host. SSH-executor-only installs can remove that mount (the hardened override does).
- SIEM forwarding sends unforwarded events only from the last 60 minutes and does not retry per collector (see Monitoring above).
