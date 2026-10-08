#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

MODE="${1:---development}"

# Normalize flags
case "$MODE" in
  --development|--dev|-d) MODE="development" ;;
  --production|--prod|-p) MODE="production" ;;
  *)
    echo "Usage: ./install.sh --development | --production"
    echo "  --development  Install for local development (Node.js + Docker DB)"
    echo "  --production   Install for production (all Docker containers)"
    exit 1
    ;;
esac

echo "========================================"
echo " Segmentra Installer ($MODE)"
echo "========================================"
echo

# Check Docker
echo "[1/6] Checking Docker..."
if ! docker info >/dev/null 2>&1; then
  echo "ERROR: Docker is not running. Please start Docker Desktop and try again."
  exit 1
fi
echo "  Docker OK"

if [ "$MODE" = "development" ]; then
  # Check Node.js
  echo "[2/6] Checking Node.js..."
  if ! command -v node >/dev/null 2>&1; then
    echo "ERROR: Node.js is not installed. Install Node.js 20+ from https://nodejs.org"
    exit 1
  fi
  NODE_VERSION=$(node -v | sed 's/v//' | cut -d. -f1)
  if [ "$NODE_VERSION" -lt 20 ]; then
    echo "ERROR: Node.js 20+ required. Found: $(node -v)"
    exit 1
  fi
  echo "  Node.js $(node -v) OK"

  # Install npm dependencies
  echo "[3/6] Installing npm dependencies..."
  npm install

  # Start PostgreSQL container
  echo "[4/6] Starting PostgreSQL..."
  docker compose up -d segmentra-db
  echo "  Waiting for PostgreSQL to be ready..."
  sleep 3
  for i in $(seq 1 20); do
    if docker compose exec -T segmentra-db pg_isready -U segmentra >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
  echo "  PostgreSQL ready on port 15432"

  # Build workspaces
  echo "[5/6] Building workspaces..."
  npm run build

  # Run migrations and seed
  echo "[6/6] Setting up database..."
  export DATABASE_URL="postgres://segmentra:segmentra@127.0.0.1:15432/segmentra"
  npm run db:migrate
  npm run db:seed

  echo
  echo "========================================"
  echo " Development installation complete!"
  echo "========================================"
  echo
  echo " Start the application:"
  echo "   ./run.sh --start --development"
  echo
  echo " Default credentials (development only):"
  echo "   Username: admin"
  echo "   Password: admin123 (or SEGMENTRA_ADMIN_PASSWORD if it was set during seeding)"
  echo
  echo " Optional: import demo data:"
  echo "   node demo-data/seed-demo-data.js"
  echo "========================================"

elif [ "$MODE" = "production" ]; then
  # Generate secrets into .env (read automatically by docker compose; never commit it).
  # Existing values are kept, so re-running the installer is safe.
  echo "[2/6] Preparing .env secrets..."
  touch .env
  chmod 600 .env
  # make sure appended lines start on a new line
  if [ -s .env ] && [ -n "$(tail -c1 .env)" ]; then echo >> .env; fi
  rand_hex() { od -An -N"$1" -tx1 /dev/urandom | tr -d ' \n'; }
  rand_b64() { head -c "$1" /dev/urandom | base64 | tr -d '\n'; }
  env_has() { grep -q "^$1=." .env; }
  NEW_ADMIN_PASSWORD=""
  env_has JWT_SECRET || echo "JWT_SECRET=$(rand_hex 32)" >> .env
  # Must be set BEFORE any secret is stored; changing it later makes stored secrets undecryptable.
  env_has SEGMENTRA_KEK_B64 || echo "SEGMENTRA_KEK_B64=$(rand_b64 32)" >> .env
  if ! env_has POSTGRES_PASSWORD && ! env_has DB_PASSWORD; then
    PROJECT="${COMPOSE_PROJECT_NAME:-$(basename "$ROOT_DIR" | tr '[:upper:]' '[:lower:]')}"
    if docker volume inspect "${PROJECT}_segmentra_pgdata" >/dev/null 2>&1; then
      echo "  Existing database volume found - keeping its current password (set POSTGRES_PASSWORD in .env to match it)."
    else
      echo "POSTGRES_PASSWORD=$(rand_hex 16)" >> .env
    fi
  fi
  if ! env_has SEGMENTRA_ADMIN_PASSWORD; then
    NEW_ADMIN_PASSWORD="$(rand_hex 12)"
    echo "SEGMENTRA_ADMIN_PASSWORD=$NEW_ADMIN_PASSWORD" >> .env
  fi
  # Group that owns the Docker socket, so the non-root API user can run `docker exec`
  # for the Ansible executor. On Docker Desktop (macOS/Windows) the socket inside the
  # VM is owned by root's group (0).
  if ! env_has DOCKER_GID; then
    if [ "$(uname -s)" = "Linux" ] && [ -S /var/run/docker.sock ]; then
      echo "DOCKER_GID=$(stat -c %g /var/run/docker.sock)" >> .env
    else
      echo "DOCKER_GID=0" >> .env
    fi
  fi
  echo "  .env ready (JWT_SECRET, SEGMENTRA_KEK_B64, POSTGRES_PASSWORD, SEGMENTRA_ADMIN_PASSWORD, DOCKER_GID)"

  # Build all Docker images
  echo "[3/6] Building Docker images..."
  docker compose build

  # Start services (db healthcheck gates the API; the API entrypoint runs migrations + seed)
  echo "[4/6] Starting all services..."
  docker compose up -d

  echo "[5/6] Waiting for the API (migrations run on container start)..."
  API_OK=0
  for i in $(seq 1 60); do
    if curl -sf "http://127.0.0.1:${API_PORT:-8080}/api/health" >/dev/null 2>&1; then
      API_OK=1
      break
    fi
    sleep 2
  done
  if [ "$API_OK" != "1" ]; then
    echo "  WARNING: API not healthy yet. Check: docker compose logs segmentra-app"
  else
    echo "  API ready"
  fi

  echo "[6/6] Done."
  echo
  echo "========================================"
  echo " Production installation complete!"
  echo "========================================"
  echo
  echo " Services running:"
  echo "   UI:  http://localhost:${WEB_PORT:-80}"
  echo "   API: http://127.0.0.1:${API_PORT:-8080} (localhost only; browsers use the UI's /api proxy)"
  echo "   DB:  127.0.0.1:${DB_PORT:-15432}"
  echo
  echo " Admin login:"
  echo "   Username: admin"
  if [ -n "$NEW_ADMIN_PASSWORD" ]; then
    echo "   Password: $NEW_ADMIN_PASSWORD   (stored in .env as SEGMENTRA_ADMIN_PASSWORD - change it after first login)"
  else
    echo "   Password: SEGMENTRA_ADMIN_PASSWORD from .env (used only when the admin user is first created)"
  fi
  echo
  echo " SECURITY: the API container mounts /var/run/docker.sock (root-equivalent) for the"
  echo " Ansible executor. If you only use the SSH executor, remove that mount from docker-compose.yml."
  echo " Back up .env: losing SEGMENTRA_KEK_B64 makes stored SSH/LDAP secrets unrecoverable."
  echo
  echo " Manage services:"
  echo "   ./run.sh --start --production"
  echo "   ./run.sh --stop --production"
  echo "========================================"
fi
