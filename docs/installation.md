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

- **Username:** `admin`
- **Password:** `admin123`

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
- A default admin user: **admin / admin123**

### Step 6: Start the API

**Linux/macOS:**
```bash
export DATABASE_URL="postgres://segmentra:segmentra@127.0.0.1:15432/segmentra"
export JWT_SECRET="change-me-to-a-long-random-string"
npm run dev -w apps/api
```

**Windows (PowerShell):**
```powershell
$env:DATABASE_URL = "postgres://segmentra:segmentra@127.0.0.1:15432/segmentra"
$env:JWT_SECRET = "change-me-to-a-long-random-string"
npm run dev -w apps/api
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
| `segmentra-app` | Express API (Node.js) | 8080 (internal) |
| `segmentra-db` | PostgreSQL 16 | 15432 |
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

Create a `.env` file in the project root. **This is required for production** — do not deploy with default secrets.

```env
# REQUIRED — generate a unique random string (minimum 32 characters)
# Example: openssl rand -base64 48
JWT_SECRET=your-long-random-secret-here-minimum-32-characters

# REQUIRED for production — encryption key for SSH keys and LDAP passwords
# Generate: python3 -c "import os,base64; print(base64.b64encode(os.urandom(32)).decode())"
SEGMENTRA_KEK_B64=your-base64-encoded-32-byte-key

# Optional: override default ports
# API_PORT=8080
# WEB_PORT=80
# DB_PORT=15432
```

> **Security Warning:** The default `docker-compose.yml` uses hardcoded database credentials (`segmentra/segmentra`) and exposes PostgreSQL on port 15432. For production:
> - Change the database password in both `docker-compose.yml` and `DATABASE_URL`
> - Consider not exposing the PostgreSQL port externally (remove the `ports` mapping for `segmentra-db`)
> - The Docker socket mount (`/var/run/docker.sock`) is required for the Ansible executor. If you use SSH Direct executor only, remove this mount to reduce the attack surface.
> - JWT tokens are valid for 12 hours. Disabling a user or changing roles takes effect on next login, not immediately.

### Step 2: Build and Start

```bash
docker compose up -d --build
```

This builds all 4 images and starts the services.

### Step 3: Run Migrations

```bash
docker compose exec -T segmentra-app sh -c \
  "DATABASE_URL=postgres://segmentra:segmentra@segmentra-db:5432/segmentra \
   node node_modules/.bin/node-pg-migrate up -m packages/db/migrations"
```

### Step 4: Create Admin User

```bash
docker compose exec -T segmentra-app sh -c \
  "DATABASE_URL=postgres://segmentra:segmentra@segmentra-db:5432/segmentra \
   node packages/db/scripts/seed-roles.js"
```

### Step 5: Access the UI

Open **http://localhost** (port 80) and login with:
- **Username:** `admin`
- **Password:** `admin123`

The nginx container proxies `/api/*` requests to the backend automatically.

### Step 6 (Optional): Import Demo Data

```bash
docker compose exec -T segmentra-app sh -c \
  "DATABASE_URL=postgres://segmentra:segmentra@segmentra-db:5432/segmentra \
   node demo-data/seed-demo-data.js"
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
docker compose up -d segmentra-db
# Wait a few seconds, then re-run migrations and seed
```

---

## Configuration Reference

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | Yes | — | PostgreSQL connection string |
| `JWT_SECRET` | Yes | — | JWT signing secret (min 16 chars) |
| `PORT` | No | `8080` | API server port |
| `SEGMENTRA_KEK_B64` | No | — | Base64 key for AES-256-GCM encryption of secrets |
| `BUNDLES_DIR` | No | `./data/bundles` | Directory for deployment bundles |
| `ANSIBLE_RUNNER_CONTAINER` | No | `segmentra-ansible-runner` | Docker container name for Ansible executor |

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
- **Set a strong `JWT_SECRET`** (32+ random characters) — never use the default in production
- **Set `SEGMENTRA_KEK_B64`** for AES-256-GCM encryption of SSH keys and LDAP passwords
- **Change database credentials** in `docker-compose.yml` for production (default: `segmentra/segmentra`)
- **Remove PostgreSQL port exposure** — consider removing `ports: "15432:5432"` from `segmentra-db` if external DB access is not needed
- **Docker socket mount** — `/var/run/docker.sock` is required for the Ansible executor; if using SSH Direct only, remove this mount. Treat the API container as high-trust when the socket is mounted.
- **SSH host key verification** — disabled by default (`StrictHostKeyChecking=no`) for deployment automation. For high-security environments, consider configuring a known_hosts file.
- **JWT token lifetime** — tokens are valid for 12 hours. Disabling a user or changing roles takes effect on next login, not immediately. For faster revocation, consider shortening the token expiry in `apps/api/src/services/jwt.ts`.
- **TLS** — in production, place a reverse proxy with TLS (e.g., nginx with Let's Encrypt) in front of the `segmentra-web` container
- **Back up** the PostgreSQL volume (`segmentra_pgdata`) regularly

---

## Troubleshooting

### Port Conflicts

If port 80, 8080, or 15432 is already in use, modify `docker-compose.yml`:
```yaml
ports:
  - "3000:80"    # Change 80 to 3000
  - "9090:8080"  # Change 8080 to 9090
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
