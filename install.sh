#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

MODE=""
HARDENED=0
HARDENED_COMPOSE_FILE="docker-compose.yml:docker-compose.hardened.yml"

install_usage() {
  echo "Usage: ./install.sh --development | --production [--hardened]"
  echo "  --development  Install for local development (Node.js + Docker DB)"
  echo "  --production   Install for production (all Docker containers)"
  echo "  --hardened     With --production: use docker-compose.hardened.yml too (no Docker socket,"
  echo "                 read-only containers, only nginx published; requires the SSH Direct executor)."
  echo "                 Recorded as COMPOSE_FILE in .env, so every later 'docker compose' command,"
  echo "                 ./run.sh and scripts/segmentra-backup.sh keep using the hardened override."
  exit 1
}

# Normalize flags
for arg in "${@:---development}"; do
  case "$arg" in
    --development|--dev|-d) MODE="development" ;;
    --production|--prod|-p) MODE="production" ;;
    --hardened) HARDENED=1 ;;
    *) install_usage ;;
  esac
done
[ -n "$MODE" ] || MODE="development"
if [ "$HARDENED" = "1" ] && [ "$MODE" != "production" ]; then
  echo "ERROR: --hardened is only valid with --production."
  exit 1
fi

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
  # Hardened mode is recorded as COMPOSE_FILE in .env: docker compose reads it automatically,
  # so all later compose commands (run.sh, segmentra-backup.sh, manual ones) include the override.
  if [ "$HARDENED" = "1" ]; then
    if grep -q '^COMPOSE_FILE=' .env; then
      if ! grep -q '^COMPOSE_FILE=.*docker-compose.hardened.yml' .env; then
        echo "  ERROR: .env already sets COMPOSE_FILE without docker-compose.hardened.yml; fix it by hand:"
        echo "         COMPOSE_FILE=$HARDENED_COMPOSE_FILE"
        exit 1
      fi
    else
      echo "COMPOSE_FILE=$HARDENED_COMPOSE_FILE" >> .env
    fi
  fi
  if grep -q '^COMPOSE_FILE=.*docker-compose.hardened.yml' .env; then HARDENED=1; fi
  echo "  .env ready (JWT_SECRET, SEGMENTRA_KEK_B64, POSTGRES_PASSWORD, SEGMENTRA_ADMIN_PASSWORD, DOCKER_GID)"
  [ "$HARDENED" = "1" ] && echo "  Hardened mode: COMPOSE_FILE=$HARDENED_COMPOSE_FILE (in .env)"

  # Build all Docker images
  echo "[3/6] Building Docker images..."
  docker compose build

  # Start services (db healthcheck gates the API; the API entrypoint runs migrations + seed)
  echo "[4/6] Starting all services..."
  docker compose up -d

  echo "[5/6] Waiting for the API (migrations run on container start)..."
  API_OK=0
  # The hardened override does not publish the API; check it through nginx then.
  if [ "$HARDENED" = "1" ]; then
    HEALTH_URL="http://127.0.0.1:${WEB_PORT:-80}/api/health"
  else
    HEALTH_URL="http://127.0.0.1:${API_PORT:-8080}/api/health"
  fi
  for i in $(seq 1 60); do
    if curl -sf "$HEALTH_URL" >/dev/null 2>&1; then
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
  echo "   UI:  http://localhost:${WEB_PORT:-80}  (plain HTTP: put a TLS reverse proxy in front, see docs/installation.md)"
  if [ "$HARDENED" = "1" ]; then
    echo "   API: not published (hardened); reached through the UI's /api proxy"
    echo "   DB:  not published (hardened)"
  else
    echo "   API: http://127.0.0.1:${API_PORT:-8080} (localhost only; browsers use the UI's /api proxy)"
    echo "   DB:  127.0.0.1:${DB_PORT:-15432}"
  fi
  echo
  echo " Admin login:"
  echo "   Username: admin"
  if [ -n "$NEW_ADMIN_PASSWORD" ]; then
    echo "   Password: $NEW_ADMIN_PASSWORD   (stored in .env as SEGMENTRA_ADMIN_PASSWORD - change it after first login)"
  else
    echo "   Password: SEGMENTRA_ADMIN_PASSWORD from .env (used only when the admin user is first created)"
  fi
  echo
  if [ "$HARDENED" = "1" ]; then
    echo " HARDENED: no Docker socket and no Ansible runner. Select Admin > Deployment Executor >"
    echo " SSH Direct before the first deployment."
  else
    echo " SECURITY: the API container mounts /var/run/docker.sock (root-equivalent) for the"
    echo " Ansible executor. If you only use the SSH executor, use ./install.sh --production --hardened."
  fi
  echo " Back up .env: losing SEGMENTRA_KEK_B64 makes stored SSH/LDAP secrets unrecoverable."
  echo
  echo " Manage services:"
  echo "   ./run.sh --start --production"
  echo "   ./run.sh --stop --production"
  echo "========================================"
fi
