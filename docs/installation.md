# Segmentra Installation Guide

---

## Quick Start

### Automated Installation

**Linux/macOS:**
```bash
# Development
./install.sh --development

# Production
./install.sh --production
```

**Windows (PowerShell):**
```powershell
# Development
.\install.ps1 --development

# Production
.\install.ps1 --production
```

### Running the Application

**Linux/macOS:**
```bash
./run.sh --start --development    # Start dev environment
./run.sh --stop --development     # Stop dev environment
./run.sh --start --production     # Start production
./run.sh --stop --production      # Stop production
./run.sh --status --development   # Check service status
```

**Windows (PowerShell):**
```powershell
.\run.ps1 -start -development
.\run.ps1 -stop -development
.\run.ps1 -start -production
.\run.ps1 -stop -production
.\run.ps1 -status -development
```

### Default Login

- **Development:** `admin` / `admin123` (created by the seed when `SEGMENTRA_ADMIN_PASSWORD` is not set; change it after first login)
- **Production:** `admin` / the `SEGMENTRA_ADMIN_PASSWORD` value. `./install.sh --production` generates one into `.env` and prints it. With `NODE_ENV=production` the seed never creates the `admin123` default.

The dev scripts (`start.sh`, `run.sh`, `run.ps1`, `start.bat`) generate a random JWT secret once into the untracked file `.dev-jwt-secret` when `JWT_SECRET` is not set. They also install/refresh dependencies when `package-lock.json` or a `package.json` changed, then migrate, seed and build before starting.

---

## Development Installation (Manual Steps)

For developers who want to understand each step or customize the setup.

### Prerequisites

- **Node.js 20+** — [https://nodejs.org](https://nodejs.org)
- **Docker Desktop** — For PostgreSQL (and optionally Ansible runner)
- **npm** — Included with Node.js

### Step 1: Install Dependencies

```bash
npm install
```

### Step 2: Start PostgreSQL

```bash
docker compose up -d segmentra-db
```

This starts PostgreSQL on port **15432** with persistent storage.

### Step 3: Build Workspaces

```bash
npm run build
```

### Step 4: Run Database Migrations

**Linux/macOS:**
```bash
export DATABASE_URL="postgres://segmentra:segmentra@127.0.0.1:15432/segmentra"
npm run db:migrate
```

**Windows (PowerShell):**
```powershell
$env:DATABASE_URL = "postgres://segmentra:segmentra@127.0.0.1:15432/segmentra"
npm run db:migrate
```

### Step 5: Seed Default Data

```bash
npm run db:seed
```

This creates:
- The four RBAC roles (viewer, operator, approver, admin)
- The protected system tags (`iot-gateway`, `bastion`)
- An `admin` user (if missing) with the password from `SEGMENTRA_ADMIN_PASSWORD`, or **admin / admin123** in development when it is unset (a warning is printed). With `NODE_ENV=production` and no `SEGMENTRA_ADMIN_PASSWORD`, no admin user is created.

Migrations are plain `.sql` files in `packages/db/migrations`; `npm run db:migrate` runs `packages/db/scripts/migrate.js`, which also cleans up duplicate `pgmigrations` rows left by older releases (that shipped a `.js` wrapper next to every `.sql` file).

### Step 6: Start the API

**Linux/macOS:**
```bash
export DATABASE_URL="postgres://segmentra:segmentra@127.0.0.1:15432/segmentra"
export JWT_SECRET="$(openssl rand -hex 32)"   # or reuse the value in .dev-jwt-secret
npm run dev -w apps/api   # runs apps/api/dist — run `npm run build` first
```

**Windows (PowerShell):**
```powershell
$env:DATABASE_URL = "postgres://segmentra:segmentra@127.0.0.1:15432/segmentra"
$env:JWT_SECRET = "<at least 32 random characters>"   # or reuse the value in .dev-jwt-secret
npm run dev -w apps/api   # runs apps/api/dist — run `npm run build` first
```

API listens on **http://localhost:8080**.

### Step 7: Start the UI

```bash
cd apps/web
npm run dev
```

UI listens on **http://localhost:5173**.

### Step 8 (Optional): Import Demo Data

```bash
node demo-data/seed-demo-data.js
```

This creates 27 hosts, 6 VLANs, 15 tags, 4 firewall policies, 3 SSH credentials, 13 IoT assets, 2 K8s clusters, and 2 topology views. See `demo-data/README.md` for details.

### Step 9 (Optional): Start Ansible Runner

The default deployment executor is **Ansible**, which requires the Ansible runner container. If you plan to test deployments:

```bash
docker compose up -d segmentra-ansible-runner
```

Alternatively, switch to the **SSH Direct** executor in the UI: **Admin → Deployment Executor → SSH Direct**.

---

## Production Installation

### Prerequisites

- **Docker Engine** + **docker compose** (v2)
- Linux host recommended
- Network access from Segmentra to managed hosts (SSH, port 22)
- On managed hosts: an account with full sudo rights, `nft` or `iptables`, and, for rules that survive a reboot, the distribution's own persistence service: Debian/Ubuntu `nftables` (nftables backend) or `iptables-persistent` (iptables backend); RHEL/Rocky/Alma `nftables` or `iptables-services` **with firewalld disabled**. Segmentra never installs these packages or disables firewalld; it reports what is missing (readiness check, "Survives reboot" column). See [guide.md](guide.md#on-target-linux-hosts) and [Persistence across reboots](../README.md#persistence-across-reboots).

### Docker Architecture

Production runs 4 containers:

| Container | Purpose | Port |
|-----------|---------|------|
| `segmentra-web` | Nginx serving the React UI + API proxy | **80** |
| `segmentra-app` | Express API (Node.js, runs as non-root `node` user) | 8080 (bound to 127.0.0.1) |
| `segmentra-db` | PostgreSQL 16 | 15432 (bound to 127.0.0.1) |
| `segmentra-ansible-runner` | Ansible playbook executor | — (no port) |

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Browser     │────►│ segmentra-web│────►│ segmentra-app│
│              │ :80 │ (nginx)      │/api/│ (Express API)│
└──────────────┘     └──────────────┘     └──────┬───────┘
                                                  │
                                    ┌─────────────┼──────────────┐
                                    │             │              │
                              ┌─────▼─────┐ ┌────▼─────┐ ┌─────▼──────┐
                              │segmentra- │ │segmentra-│ │  Target    │
                              │db         │ │ansible-  │ │  Hosts     │
                              │(postgres) │ │runner    │ │  (SSH)     │
                              └───────────┘ └──────────┘ └────────────┘
```

### Step 1: Configure Environment

`./install.sh --production` (or `.\install.ps1 --production`) creates `.env` for you with random values and keeps any values already present. To do it manually, create a `.env` file in the project root (never commit it):

```env
# REQUIRED — at least 32 random characters (the API refuses shorter/default secrets in production)
# Generate: openssl rand -hex 32
JWT_SECRET=

# REQUIRED — 32 random bytes, base64. Encrypts SSH keys/passwords and LDAP bind passwords.
# Generate: openssl rand -base64 32
# Set it BEFORE storing any secrets and back it up: changing or losing it makes stored
# secrets undecryptable. (If unset, the key would be derived from JWT_SECRET — the
# Docker image refuses to start without it.)
SEGMENTRA_KEK_B64=

# Database password (used when the database volume is first created)
POSTGRES_PASSWORD=

# Initial "admin" user password (min. 12 characters). Without it no admin user is created.
SEGMENTRA_ADMIN_PASSWORD=

# Group that owns /var/run/docker.sock on the host (Linux: stat -c %g /var/run/docker.sock;
# Docker Desktop: 0). Lets the non-root API user run `docker exec` for the Ansible executor.
DOCKER_GID=

# Optional
# CORS_ORIGIN=https://segmentra.example.com
# SEGMENTRA_BOOTSTRAP_TOKEN=
# API_PORT=8080
# API_BIND=127.0.0.1
# WEB_PORT=80
# DB_PORT=15432
```

> **Security notes**
> - PostgreSQL and the API are published on `127.0.0.1` only. Browsers reach the API through the nginx container (`/api/` proxy). If you set `API_BIND=0.0.0.0`, review `TRUST_PROXY` (compose sets `1`, which trusts one proxy hop).
> - **Docker socket:** `segmentra-app` mounts `/var/run/docker.sock` because the Ansible executor runs `docker exec segmentra-ansible-runner ansible-playbook ...`. Access to the Docker socket is **equivalent to root on the Docker host**. The SSH Direct executor does not need it — if you only use SSH Direct, remove the socket mount and the `group_add` entry from `docker-compose.yml`.
> - JWT tokens are valid for 12 hours. Role changes take effect on the next request (roles are re-read from the database). Deactivating a user blocks their tokens only while the account stays deactivated: reactivating it within 12 hours makes unexpired tokens valid again. Changing or resetting a password does not end sessions that are already open.

### Step 2: Build and Start

```bash
docker compose up -d --build
```

This builds the images and starts the services. The API waits for the database healthcheck, and its entrypoint validates `JWT_SECRET` / `SEGMENTRA_KEK_B64`, runs the database migrations and the seed (roles, system tags, initial admin) on **every start**, then launches the API. Set `SEGMENTRA_SKIP_MIGRATIONS=1` on `segmentra-app` to skip this.

Check progress with:

```bash
docker compose logs -f segmentra-app
```

For production, consider the hardened override, which removes the Docker socket and makes the containers read-only (requires the SSH Direct executor):

```bash
docker compose -f docker-compose.yml -f docker-compose.hardened.yml up -d --build
```

See [security.md](security.md#hardening-a-production-install).

### Step 3: Access the UI

Open **http://localhost** (port 80) and log in as `admin` with the `SEGMENTRA_ADMIN_PASSWORD` value.

The nginx container proxies `/api/*` requests to the backend automatically.

### Step 4 (Optional): Import Demo Data

```bash
docker compose exec -T segmentra-app node demo-data/seed-demo-data.js
```

### Building the Docker Images

`docker compose up -d --build` builds all three images from this repository. You don't need Node.js on the Docker host: everything is compiled inside the images.

| Image (compose service) | Dockerfile | Build context | What it contains |
|---|---|---|---|
| `segmentra-app` | `infra/app/Dockerfile` | repository root | Multi-stage: builds the TypeScript workspaces (shared, compiler, executor, api), then a slim non-root runtime (`node` user) with production dependencies, the DB migrations and seed, `ssh`/`scp`/`sshpass` for the SSH executor and the Docker CLI for the Ansible executor. The entrypoint checks secrets, runs migrations and the seed, then starts the API. Build arg `NODE_IMAGE` (default `node:20-bookworm-slim`). |
| `segmentra-web` | `infra/web/Dockerfile` | repository root | Builds the React UI with Vite (API base URL `/api`) and serves it with nginx, which also proxies `/api/` to `segmentra-app`. |
| `segmentra-ansible-runner` | `infra/ansible-runner/Dockerfile` | `infra/ansible-runner` | Python + Ansible, `openssh-client` and `sshpass`, the `apply-firewall.yml` playbook and its helper scripts. Host keys are trusted on first use and kept on a volume. |

`.dockerignore` keeps `node_modules`, build output, `.env`, keys and local data out of the build context, so secrets are never baked into an image.

Useful commands:

```bash
# Build (or rebuild) all images without starting them
docker compose build

# Rebuild a single image after changing its code, then restart only that service
docker compose build segmentra-app
docker compose up -d segmentra-app

# Force a clean rebuild (ignore the build cache)
docker compose build --no-cache

# Build the API image on its own, e.g. to push to a registry
docker build -f infra/app/Dockerfile -t registry.example.com/segmentra-app:1.0.0 .
docker build -f infra/web/Dockerfile -t registry.example.com/segmentra-web:1.0.0 .
docker build -t registry.example.com/segmentra-ansible-runner:1.0.0 infra/ansible-runner
```

If you push images to a registry, replace the `build:` entries in `docker-compose.yml` with `image:` references on the target host, and keep the same environment variables and volumes.

### Upgrading to a New Version

```bash
git pull                       # get the new version
docker compose up -d --build   # rebuild changed images and recreate their containers
docker compose logs -f segmentra-app
```

- **Database migrations run automatically** when `segmentra-app` starts. New tables and columns are created; existing data is kept. Back up the database first (see [Database Backup](#database-backup)).
- Volumes (database, deployment bundles, SSH known_hosts) and `.env` are kept across rebuilds. **Don't regenerate `.env`**: a new `SEGMENTRA_KEK_B64` would make stored SSH and LDAP secrets unreadable.
- Managed hosts are not changed by an upgrade. New firewall behaviour (for example chain-based iptables rules) applies to a host the next time a policy is deployed to it.

---

## Managing Services

### Start/Stop

```bash
# Start all production services
docker compose up -d

# Stop all services (data persists)
docker compose stop

# Stop and remove containers (data persists in volumes)
docker compose down

# Stop and delete all data (destructive!)
docker compose down -v
```

### View Logs

```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f segmentra-app
docker compose logs -f segmentra-web
```

### Database Backup

```bash
# Backup
docker compose exec -T segmentra-db pg_dump -U segmentra segmentra > backup.sql

# Restore
docker compose exec -T segmentra-db psql -U segmentra segmentra < backup.sql
```

### Reset Database

```bash
docker compose down -v
docker compose up -d        # production: the API re-runs migrations + seed on start
# development: ./run.sh --start --development (or npm run db:migrate && npm run db:seed)
```

---

## Configuration Reference

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | Yes | — | PostgreSQL connection string |
| `JWT_SECRET` | Yes | — | JWT signing secret. Min. 32 chars when `NODE_ENV=production` (16 in dev); known placeholder values are refused in production |
| `SEGMENTRA_KEK_B64` | Prod: yes | — | 32 random bytes, base64. Key for AES-256-GCM encryption of SSH keys/passwords and LDAP passwords. **Fallback:** if unset, the key is derived from `JWT_SECRET` (SHA-256), so rotating `JWT_SECRET` breaks stored secrets. Set it explicitly in production and before storing secrets; changing it later requires re-entering all secrets |
| `NODE_ENV` | No | — | `production` enables strict checks (set by the Docker image) |
| `PORT` | No | `8080` | API server port |
| `BUNDLES_DIR` | No | `./data/bundles` | Directory for deployment bundles (`/bundles` in Docker, shared with the Ansible runner) |
| `ANSIBLE_RUNNER_CONTAINER` | No | `segmentra-ansible-runner` | Container used with `docker exec` by the Ansible executor |
| `CORS_ORIGIN` | No | Same-origin only in production; allow all in development | Comma-separated HTTP(S) browser origins without paths or wildcards; set for cross-origin UI access |
| `TRUST_PROXY` | No | — | Express `trust proxy` setting (`1`, `loopback`, CIDR, `true`) when behind a reverse proxy, so client IPs are correct for login rate limiting and audit |
| `SEGMENTRA_KNOWN_HOSTS` | No | `~/.ssh/known_hosts` | known_hosts file for SSH connections (SSH executor, readiness checks, firewall learning). New hosts are trusted on first use (`StrictHostKeyChecking=accept-new`); a changed host key is rejected |
| `SEGMENTRA_ALLOW_PRIVATE_WEBHOOKS` | No | `false` | `true` allows notification webhooks to loopback, link-local and cloud-metadata addresses (blocked by default; RFC1918 ranges are always allowed) |
| `SEGMENTRA_BOOTSTRAP_TOKEN` | No | — | Enables one-time `POST /api/admin/bootstrap` while no users exist; requires `token`, optional `username`, and `password` (12+ characters, at most 72 UTF-8 bytes) |
| `SEGMENTRA_ADMIN_PASSWORD` | Prod: yes | `admin123` (dev only) | Password for the initial `admin` user created by the seed (min. 12 chars in production) |
| `SEGMENTRA_SSH_COMMAND_TIMEOUT_MS` | No | `300000` | Per-command SSH timeout |
| `SEGMENTRA_ASKPASS_DIR` | No | OS temp dir | Directory for the short-lived `SSH_ASKPASS` helper used with passphrase-protected keys (the helper never contains a secret) |
| `SEGMENTRA_SKIP_MIGRATIONS` | No | `0` | Docker only: `1` skips migrations + seed in the API entrypoint |

docker-compose also reads `POSTGRES_PASSWORD` (or legacy `DB_PASSWORD`), `DB_USER`, `DB_NAME`, `DB_PORT`, `API_PORT`, `API_BIND`, `WEB_PORT` and `DOCKER_GID`.

The local dev scripts also read `SEGMENTRA_DATABASE_URL` (custom database URL instead of the local container; `start.sh`, `run.sh`, `run.ps1`) and `SEGMENTRA_RESET_DB=1` (`start.sh` / `start.bat`: wipe the Docker volumes before starting — data loss).

### Deployment Executors

Segmentra supports two executors for deploying firewall rules to hosts:

| Executor | Setup | Best For |
|----------|-------|----------|
| **Ansible** (default) | Requires `segmentra-ansible-runner` container | Production — parallel execution, better rollback |
| **SSH Direct** | No extra dependencies | Hardened installs (no Docker socket); lockout auto-revert and canary/progressive rollouts |

Switch in: **Admin → Deployment Executor**. With the hardened override (`docker-compose.hardened.yml`) the Ansible runner is not started, so select **SSH Direct** before the first deployment. See the [executor comparison in the user guide](guide.md#quick-reference-deployment-executor-comparison).

For development without Ansible, either:
- Switch to SSH Direct in the UI
- Or start the runner: `docker compose up -d segmentra-ansible-runner`

### SSH Credentials

Configure in: **Admin → SSH Credentials**

- Use a **sudo-capable account** (not root). Nothing is installed on the hosts (agentless).
- Authentication: a private key (optionally passphrase-protected; the passphrase is checked when you save) or a password
- **Privilege escalation:** *sudo without password*, *sudo with the login password* (password credentials) or *sudo with a separate password*. The account needs **full sudo rights** (e.g. `segmentra ALL=(ALL) ALL`, or `NOPASSWD: ALL` for passwordless): Segmentra runs its scripts as `sudo sh -c '…'`, so a sudoers entry limited to `nft`/`iptables` makes deployments fail. `Defaults requiretty` must not apply to the account.
- The SSH client in the API image must be OpenSSH 8.4 or newer for passphrase-protected keys (the bundled Debian bookworm image has 9.2)
- **Applies to:** all hosts (global), hosts with a tag, hosts in a VLAN, one host, or *not assigned* (only used by discovery or when assigned to a host explicitly). Each host uses its explicitly assigned credential, else a host-, tag-, VLAN- and finally the global credential (highest priority, then newest, within a level); **Inventory → Hosts** shows which one each host uses. See the [user guide](guide.md#step-4-add-ssh-credentials)
- Keys, passphrases and passwords are encrypted at rest with AES-256-GCM (see [security.md](security.md))

---

## Security Notes

- **Change the default admin password** immediately after first login
- **Set a strong `JWT_SECRET`** (32+ random characters) — required in production; known defaults are refused
- **Set `SEGMENTRA_KEK_B64`** before storing any secrets, and back it up — otherwise the key is derived from `JWT_SECRET`
- **Set `POSTGRES_PASSWORD`** in `.env` (the compose default `segmentra` is for local development only; it only applies when the volume is first created)
- **PostgreSQL port** — published on `127.0.0.1:15432` only; remove the `ports` mapping entirely if you never need host access
- **Docker socket mount** — `/var/run/docker.sock` is root-equivalent and only required for the Ansible executor; if using SSH Direct only, remove the mount and `group_add`. Treat the API container as high-trust when the socket is mounted.
- **SSH host key verification** — trust-on-first-use (`StrictHostKeyChecking=accept-new`) for both the SSH executor (known_hosts at `SEGMENTRA_KNOWN_HOSTS`, persisted in the `segmentra_ssh_known_hosts` volume) and the Ansible runner (`segmentra_ansible_ssh` volume). A host whose key changes is rejected; remove its old entry from known_hosts after a legitimate re-key.
- **JWT token lifetime** — tokens are valid for 12 hours. Role changes take effect on the next request. Deactivating a user blocks their tokens only while the account stays deactivated (reactivating it within 12 hours makes unexpired tokens valid again). Changing or resetting a password does not end existing sessions, so keep a compromised account deactivated for at least 12 hours. The expiry is set in `apps/api/src/services/jwt.ts`.
- **TLS** — in production, place a reverse proxy with TLS (e.g., nginx with Let's Encrypt) in front of the `segmentra-web` container
- **Back up** the PostgreSQL volume (`segmentra_pgdata`) regularly

---

## Troubleshooting

### Port Conflicts

If port 80, 8080, or 15432 is already in use, override them in `.env`:
```env
WEB_PORT=3000
API_PORT=9090
DB_PORT=25432
```

### Database Connection Errors

Verify PostgreSQL is running:
```bash
docker compose ps segmentra-db
docker compose logs segmentra-db
```

### Deployment Failures

1. Check SSH credentials are configured: **Admin → SSH Credentials**
2. Verify executor setting: **Admin → Deployment Executor**
3. If using Ansible, verify runner is running: `docker compose ps segmentra-ansible-runner`
4. Open the deployment (**Deployments →** select it): the **Message** column of the hosts table shows each host's result or error. Failed hosts can be redeployed with **Retry Failed Hosts**.
