# Installation & running Segmentra

This document covers:
- Running Segmentra in a **developer environment** (API + UI + Postgres)
- Installing Segmentra in a **production environment** (Docker Compose)
- How to **access the UI without LDAP** (bootstrap token flow)

---

## Dev environment (local)

### Prerequisites
- **Node.js 20+**
- **Docker Desktop**
- Shell: **PowerShell** (Windows) or any terminal (macOS/Linux)

### 1) Install dependencies
From repo root:

```bash
npm install
```

### 2) Start PostgreSQL (Docker)
From repo root:

```bash
docker compose up -d segmentra-db
```

### 3) Run DB migrations + seed roles
Set `DATABASE_URL` and run:

**PowerShell (Windows):**
```powershell
$env:DATABASE_URL="postgres://segmentra:segmentra@127.0.0.1:15432/segmentra"
npm run db:migrate
npm run db:seed
```

**bash (macOS/Linux):**
```bash
export DATABASE_URL="postgres://segmentra:segmentra@127.0.0.1:15432/segmentra"
npm run db:migrate
npm run db:seed
```

### 4) Start the API
The API listens on port **8080** by default.

**PowerShell:**
```powershell
$env:JWT_SECRET="change-me-to-a-long-random-string"
# optional, used for UI access without LDAP (see below)
$env:SEGMENTRA_BOOTSTRAP_TOKEN="dev-bootstrap-token"

npm run build -ws
npm run dev -w apps/api
```

Verify:
- `http://localhost:8080/api/health`

### 5) Start the UI
The UI is a Vite dev server (usually port **5173**).

```bash
cd apps/web

# Optional: only needed if your API is not on localhost:8080
# PowerShell: $env:VITE_API_URL="http://localhost:8080/api"
# bash: export VITE_API_URL="http://localhost:8080/api"

npm run dev
```

Open the Vite URL printed in the terminal (commonly `http://localhost:5173`).

---

## Access the UI without LDAP (dev bootstrap)

The login page is LDAP-based. For dev/bring-up, you can bypass LDAP by using the **bootstrap admin token** to mint a JWT.

### Step A — Enable bootstrap in the API
Set `SEGMENTRA_BOOTSTRAP_TOKEN` in the API environment before starting the API:

```powershell
$env:SEGMENTRA_BOOTSTRAP_TOKEN="dev-bootstrap-token"
```

### Step B — Create the first admin and get a JWT
Call the bootstrap endpoint:

**PowerShell:**
```powershell
$body = @{ token="dev-bootstrap-token"; username="bootstrap_admin" } | ConvertTo-Json
Invoke-RestMethod -Method Post `
  -Uri "http://localhost:8080/api/admin/bootstrap" `
  -ContentType "application/json" `
  -Body $body
```

Copy the returned `token`.

### Step C — Store the token in the browser
In the UI (browser), open DevTools Console and run:

```js
localStorage.setItem('segmentra_token', 'PASTE_THE_TOKEN_HERE')
location.reload()
```

You should now be authenticated in the UI.

### Important notes
- `POST /api/admin/bootstrap` is **one-time**: it refuses to run if any users already exist.
- In production, **disable** bootstrap by **removing** `SEGMENTRA_BOOTSTRAP_TOKEN` after initial setup.

---

## Production installation (Docker Compose)

### Prerequisites
- Linux host (recommended) with **Docker Engine** + **docker compose**
- Persistent storage for PostgreSQL and deployment bundles
- Network access from Segmentra to managed hosts (SSH) if you will run deployments

### 1) Create production env vars
At minimum, set these for the `segmentra-app` container:
- `DATABASE_URL` (points to `segmentra-db` if using compose DB, or an external Postgres)
- `JWT_SECRET` (long random secret)
- `SEGMENTRA_KEK_B64` (recommended: base64 of a **32-byte** key for AES-256-GCM encryption)
- `BUNDLES_DIR` (inside container; defaults to `./data/bundles` when running locally, but in container we use `/bundles`)
- `ANSIBLE_RUNNER_CONTAINER` (default `segmentra-ansible-runner`)

**Example (generate a KEK):**
```bash
# 32 random bytes -> base64
python - << 'PY'
import os, base64
print(base64.b64encode(os.urandom(32)).decode())
PY
```

### 2) Start services
From repo root on the production host:

```bash
docker compose up -d
```

This starts:
- `segmentra-db` (PostgreSQL)
- `segmentra-ansible-runner` (ansible-core + playbooks)
- `segmentra-app` (API; and UI build artifacts are present under `apps/web/dist`)

### 3) Run migrations + seed roles (required)
Run these on the host (or in a one-off container) with `DATABASE_URL` pointing at the production DB:

```bash
export DATABASE_URL="postgres://segmentra:segmentra@127.0.0.1:15432/segmentra"
npm install
npm run db:migrate
npm run db:seed
```

> Note: v1 expects migrations to be run out-of-band. If you want “auto-migrate on startup”, we can add it.

### 4) First admin / LDAP configuration
You have two options:

- **Preferred**: configure LDAP settings + AD group mappings (so admins/operators can login normally).
- **Bootstrap**: temporarily set `SEGMENTRA_BOOTSTRAP_TOKEN`, call `/api/admin/bootstrap`, then remove the token.

### 5) Accessing the UI in production
In v1, the UI is served by the Vite dev server during development. In production you typically do one of:

- **Reverse proxy** (recommended): serve the built UI via nginx and proxy `/api/*` to the API container.
- **Separate UI container**: build and serve `apps/web/dist` via nginx.

If you want, tell me your preferred approach and I’ll add a production-ready nginx config + compose service.

---

## Security / operational notes (prod)

- **Do not keep** `SEGMENTRA_BOOTSTRAP_TOKEN` enabled after initial setup.
- Set a strong `JWT_SECRET` and store it securely.
- Set a stable `SEGMENTRA_KEK_B64` (if you rotate it without re-encrypting, encrypted secrets become unreadable).
- Back up Postgres volume (`segmentra_pgdata`) regularly.
- Deployments use Docker socket mounting (`/var/run/docker.sock`) so the API can execute ansible inside the runner container. Treat the API container as **high trust** and restrict host access accordingly.


