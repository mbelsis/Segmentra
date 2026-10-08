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

Alternatively, switch to **SSH Direct** executor in the UI: **Admin → Deployment Executor → SSH**.

---

## Production Installation

### Prerequisites

- **Docker Engine** + **docker compose** (v2)
- Linux host recommended
- Network access from Segmentra to managed hosts (SSH, port 22)

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
> - JWT tokens are valid for 12 hours. Disabling a user or changing roles takes effect on next login, not immediately.

### Step 2: Build and Start

```bash
docker compose up -d --build
```

This builds the images and starts the services. The API waits for the database healthcheck, and its entrypoint validates `JWT_SECRET` / `SEGMENTRA_KEK_B64`, runs the database migrations and the seed (roles, system tags, initial admin) on **every start**, then launches the API. Set `SEGMENTRA_SKIP_MIGRATIONS=1` on `segmentra-app` to skip this.

Check progress with:

```bash
docker compose logs -f segmentra-app
```

### Step 3: Access the UI

Open **http://localhost** (port 80) and log in as `admin` with the `SEGMENTRA_ADMIN_PASSWORD` value.

The nginx container proxies `/api/*` requests to the backend automatically.

### Step 4 (Optional): Import Demo Data

```bash
docker compose exec -T segmentra-app node demo-data/seed-demo-data.js
```

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
| `CORS_ORIGIN` | No | — (allow all) | Comma-separated list of allowed browser origins; set in production |
| `TRUST_PROXY` | No | — | Express `trust proxy` setting (`1`, `loopback`, CIDR, `true`) when behind a reverse proxy, so client IPs are correct for login rate limiting and audit |
| `SEGMENTRA_KNOWN_HOSTS` | No | `~/.ssh/known_hosts` | known_hosts file for SSH connections (SSH executor, readiness checks, firewall learning). New hosts are trusted on first use (`StrictHostKeyChecking=accept-new`); a changed host key is rejected |
| `SEGMENTRA_ALLOW_PRIVATE_WEBHOOKS` | No | `false` | `true` allows notification webhooks to loopback, link-local and cloud-metadata addresses (blocked by default; RFC1918 ranges are always allowed) |
| `SEGMENTRA_BOOTSTRAP_TOKEN` | No | — | Enables one-time `POST /api/admin/bootstrap` while no users exist |
| `SEGMENTRA_ADMIN_PASSWORD` | Prod: yes | `admin123` (dev only) | Password for the initial `admin` user created by the seed (min. 12 chars in production) |
| `SEGMENTRA_SSH_COMMAND_TIMEOUT_MS` | No | `300000` | Per-command SSH timeout |
| `SEGMENTRA_SKIP_MIGRATIONS` | No | `0` | Docker only: `1` skips migrations + seed in the API entrypoint |

docker-compose also reads `POSTGRES_PASSWORD` (or legacy `DB_PASSWORD`), `DB_USER`, `DB_NAME`, `DB_PORT`, `API_PORT`, `API_BIND`, `WEB_PORT` and `DOCKER_GID`.

### Deployment Executors

Segmentra supports two executors for deploying firewall rules to hosts:

| Executor | Setup | Best For |
|----------|-------|----------|
| **Ansible** (default) | Requires `segmentra-ansible-runner` container | Production — parallel execution, better rollback |
| **SSH Direct** | No extra dependencies | Development — simpler, no Docker-in-Docker |

Switch in: **Admin → Deployment Executor**

For development without Ansible, either:
- Switch to SSH Direct in the UI
- Or start the runner: `docker compose up -d segmentra-ansible-runner`

### SSH Credentials

Configure in: **Admin → SSH Credentials**

- Use a **sudo-capable account** (not root)
- The account needs passwordless sudo for: `nft`, `iptables`, `iptables-save`, `iptables-restore`
- Private keys are encrypted at rest with AES-256-GCM

---

## Security Notes

- **Change the default admin password** immediately after first login
- **Set a strong `JWT_SECRET`** (32+ random characters) — required in production; known defaults are refused
- **Set `SEGMENTRA_KEK_B64`** before storing any secrets, and back it up — otherwise the key is derived from `JWT_SECRET`
- **Set `POSTGRES_PASSWORD`** in `.env` (the compose default `segmentra` is for local development only; it only applies when the volume is first created)
- **PostgreSQL port** — published on `127.0.0.1:15432` only; remove the `ports` mapping entirely if you never need host access
- **Docker socket mount** — `/var/run/docker.sock` is root-equivalent and only required for the Ansible executor; if using SSH Direct only, remove the mount and `group_add`. Treat the API container as high-trust when the socket is mounted.
- **SSH host key verification** — trust-on-first-use (`StrictHostKeyChecking=accept-new`) for both the SSH executor (known_hosts at `SEGMENTRA_KNOWN_HOSTS`, persisted in the `segmentra_ssh_known_hosts` volume) and the Ansible runner (`segmentra_ansible_ssh` volume). A host whose key changes is rejected; remove its old entry from known_hosts after a legitimate re-key.
- **JWT token lifetime** — tokens are valid for 12 hours. Disabling a user or changing roles takes effect on next login, not immediately. For faster revocation, consider shortening the token expiry in `apps/api/src/services/jwt.ts`.
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
4. Check execution logs in: **Deployments → (select deployment) → View Logs**
