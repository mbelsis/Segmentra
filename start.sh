#!/usr/bin/env bash
#
# Segmentra launcher (Linux / macOS)
# Usage: ./start.sh [dev|prod]
#   dev  - Development mode (default)
#   prod - Production mode
#
# Environment variable overrides:
#   SEGMENTRA_DATABASE_URL  - Custom PostgreSQL connection URL
#   SEGMENTRA_RESET_DB=1    - Wipe docker volumes before start (DATA LOSS)
#   JWT_SECRET              - JWT signing secret (dev: generated once into .dev-jwt-secret;
#                             prod: required, >= 32 chars)
#   SEGMENTRA_KEK_B64       - Secret-encryption key (32 bytes base64; recommended, required for prod)
#   SEGMENTRA_ADMIN_PASSWORD - Password for the initial "admin" user (prod: required to create it)
#   PORT                    - API port (default: 8080)
#   BUNDLES_DIR             - Deployment bundles directory
#   ANSIBLE_RUNNER_CONTAINER - Ansible runner container name
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

MODE="${1:-dev}"
if [[ "$MODE" != "dev" && "$MODE" != "prod" ]]; then
  echo "[segmentra] ERROR: Invalid mode. Use: ./start.sh dev  or  ./start.sh prod"
  exit 1
fi

echo "[segmentra] ========================================"
echo "[segmentra] Starting Segmentra in $MODE mode"
echo "[segmentra] ========================================"
echo ""

# ── Check prerequisites ────────────────────────────────
echo "[segmentra] Checking prerequisites..."

# Check Docker
if ! docker info >/dev/null 2>&1; then
  echo "[segmentra] ERROR: Docker is not running!"
  echo "[segmentra] Please start Docker and try again."
  exit 1
fi
echo "[segmentra]   Docker ......... OK"

# Check Node.js
if ! command -v node >/dev/null 2>&1; then
  echo "[segmentra] ERROR: Node.js is not installed!"
  echo "[segmentra] Please install Node.js 20+ and try again."
  exit 1
fi
NODE_VERSION=$(node -v | sed 's/v//' | cut -d. -f1)
if [[ "$NODE_VERSION" -lt 20 ]]; then
  echo "[segmentra] WARNING: Node.js $(node -v) detected. Version 20+ recommended."
else
  echo "[segmentra]   Node.js ........ OK ($(node -v))"
fi

# Check npm
if ! command -v npm >/dev/null 2>&1; then
  echo "[segmentra] ERROR: npm is not installed!"
  exit 1
fi
echo "[segmentra]   npm ............ OK ($(npm -v))"
echo ""

# ── Install / refresh dependencies ─────────────────────
# Clean install when node_modules is missing; re-install when package-lock.json or any
# workspace package.json is newer than the last install (node_modules/.package-lock.json).
INSTALL_MARKER="node_modules/.package-lock.json"
if [[ ! -f "$INSTALL_MARKER" ]]; then
  echo "[segmentra] Installing dependencies (npm ci)..."
  if [[ -f package-lock.json ]]; then npm ci; else npm install; fi
  echo "[segmentra] Dependencies installed - OK"
  echo ""
elif [[ -n "$(find package-lock.json package.json apps/*/package.json packages/*/package.json -newer "$INSTALL_MARKER" 2>/dev/null)" ]]; then
  echo "[segmentra] Dependency manifests changed - running npm install..."
  npm install
  echo "[segmentra] Dependencies updated - OK"
  echo ""
fi

# ── Optional: wipe local dev DB volume ─────────────────
if [[ "${SEGMENTRA_RESET_DB:-0}" == "1" ]]; then
  echo "[segmentra] WARNING: SEGMENTRA_RESET_DB=1 — removing docker volumes (DATA LOSS)..."
  docker compose down -v
  echo ""
fi

# ── Start PostgreSQL container ─────────────────────────
echo "[segmentra] Starting PostgreSQL (docker compose)..."
docker compose up -d segmentra-db
echo ""

# ── Wait for PostgreSQL to be ready ────────────────────
echo -n "[segmentra] Waiting for PostgreSQL to be ready"
TRIES=0
MAX_TRIES=30
while ! docker compose exec -T segmentra-db pg_isready -U segmentra >/dev/null 2>&1; do
  TRIES=$((TRIES + 1))
  if [[ $TRIES -ge $MAX_TRIES ]]; then
    echo ""
    echo "[segmentra] ERROR: PostgreSQL did not become ready in ${MAX_TRIES}s"
    exit 1
  fi
  echo -n "."
  sleep 1
done
echo " OK"
echo ""

# ── Environment variables ──────────────────────────────
export DATABASE_URL="${SEGMENTRA_DATABASE_URL:-postgres://segmentra:segmentra@127.0.0.1:15432/segmentra}"
if [[ "$MODE" == "prod" ]]; then
  export NODE_ENV=production
  if [[ -z "${JWT_SECRET:-}" ]]; then
    echo "[segmentra] ERROR: JWT_SECRET must be set in prod mode (>= 32 chars, e.g. openssl rand -hex 32)."
    exit 1
  fi
  if [[ -z "${SEGMENTRA_KEK_B64:-}" ]]; then
    echo "[segmentra] WARNING: SEGMENTRA_KEK_B64 is not set - secrets will be encrypted with a key derived from JWT_SECRET."
  fi
elif [[ -z "${JWT_SECRET:-}" ]]; then
  # Dev: generate a random secret once and keep it in an untracked file so tokens
  # (and secrets encrypted with the JWT-derived key) survive restarts.
  if [[ ! -s .dev-jwt-secret ]]; then
    (umask 077 && node -e "process.stdout.write(require('crypto').randomBytes(32).toString('hex'))" > .dev-jwt-secret)
    echo "[segmentra] Generated development JWT secret in .dev-jwt-secret"
  fi
  JWT_SECRET="$(cat .dev-jwt-secret)"
  export JWT_SECRET
fi
export PORT="${PORT:-8080}"
export BUNDLES_DIR="${BUNDLES_DIR:-./data/bundles}"
export ANSIBLE_RUNNER_CONTAINER="${ANSIBLE_RUNNER_CONTAINER:-segmentra-ansible-runner}"

echo "[segmentra] Configuration:"
echo "[segmentra]   DATABASE_URL = $DATABASE_URL"
echo "[segmentra]   PORT         = $PORT"
echo "[segmentra]   BUNDLES_DIR  = $BUNDLES_DIR"
echo "[segmentra]   MODE         = $MODE"
echo ""

# ── Create directories ─────────────────────────────────
mkdir -p "$BUNDLES_DIR"

# ── Run migrations ─────────────────────────────────────
echo "[segmentra] Running database migrations..."
npm run db:migrate
echo "[segmentra] Migrations complete - OK"
echo ""

# ── Seed roles ─────────────────────────────────────────
echo "[segmentra] Seeding database roles..."
npm run db:seed
echo "[segmentra] Roles seeded - OK"
echo ""

# ── Build workspaces ───────────────────────────────────
echo "[segmentra] Building workspaces..."
npm run build
echo "[segmentra] Build complete - OK"
echo ""

# ── Log files ──────────────────────────────────────────
API_LOG="/tmp/segmentra-api.log"
UI_LOG="/tmp/segmentra-ui.log"
PID_FILE="/tmp/segmentra.pids"

# ── Launch API in background ───────────────────────────
echo "[segmentra] Launching API..."
npm run dev -w apps/api > "$API_LOG" 2>&1 &
API_PID=$!
echo "[segmentra]   API PID: $API_PID (log: $API_LOG)"

# ── Launch UI in background ────────────────────────────
echo "[segmentra] Launching UI..."
(cd "$ROOT_DIR/apps/web" && npm run dev) > "$UI_LOG" 2>&1 &
UI_PID=$!
echo "[segmentra]   UI  PID: $UI_PID (log: $UI_LOG)"
echo ""

# ── Save PIDs for easy cleanup ─────────────────────────
echo "$API_PID $UI_PID" > "$PID_FILE"

# ── Wait for API to be ready ──────────────────────────
echo -n "[segmentra] Waiting for API to be ready"
TRIES=0
while ! curl -sf "http://localhost:$PORT/api/health" >/dev/null 2>&1; do
  TRIES=$((TRIES + 1))
  if [[ $TRIES -ge 30 ]]; then
    echo ""
    echo "[segmentra] WARNING: API did not respond in 30s. Check: tail -f $API_LOG"
    break
  fi
  echo -n "."
  sleep 1
done
if [[ $TRIES -lt 30 ]]; then
  echo " OK"
fi
echo ""

# ── Done ───────────────────────────────────────────────
echo "[segmentra] ========================================"
echo "[segmentra] Setup complete!"
echo "[segmentra] ========================================"
echo ""
echo "[segmentra] Services:"
echo "[segmentra]   API: http://localhost:$PORT/api/health"
echo "[segmentra]   UI:  http://localhost:5173"
echo ""
echo "[segmentra] ========================================"
echo "[segmentra] Default Login Credentials"
echo "[segmentra] ========================================"
echo "[segmentra]   Username: admin"
if [[ -n "${SEGMENTRA_ADMIN_PASSWORD:-}" ]]; then
  echo "[segmentra]   Password: (value of SEGMENTRA_ADMIN_PASSWORD when the admin user was first created)"
else
  echo "[segmentra]   Password: admin123 (dev default, unless the admin user already existed)"
  echo ""
  echo "[segmentra]   IMPORTANT: Change the default password after first login!"
fi
echo ""
echo "[segmentra] Logs:"
echo "[segmentra]   tail -f $API_LOG"
echo "[segmentra]   tail -f $UI_LOG"
echo ""
echo "[segmentra] To stop all services:"
echo "[segmentra]   kill \$(cat $PID_FILE) && docker compose down"
echo ""

# ── Trap Ctrl+C to clean up ───────────────────────────
cleanup() {
  echo ""
  echo "[segmentra] Shutting down..."
  kill "$API_PID" "$UI_PID" 2>/dev/null || true
  wait "$API_PID" "$UI_PID" 2>/dev/null || true
  rm -f "$PID_FILE"
  echo "[segmentra] Services stopped."
  echo "[segmentra] To also stop PostgreSQL: docker compose down"
  exit 0
}
trap cleanup INT TERM

echo "[segmentra] Press Ctrl+C to stop all services."
echo ""

# ── Tail logs until interrupted ────────────────────────
tail -f "$API_LOG" "$UI_LOG"
