#!/usr/bin/env bash
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
echo

# Check if Docker is running
echo "[segmentra] Checking Docker..."
if ! docker info >/dev/null 2>&1; then
  echo "[segmentra] ERROR: Docker is not running!"
  echo "[segmentra] Please start Docker Desktop and try again."
  exit 1
fi
echo "[segmentra] Docker check passed"
echo

# Install dependencies if needed
if [[ ! -d node_modules ]]; then
  echo "[segmentra] Installing dependencies..."
  npm install
  if [[ $? -ne 0 ]]; then
    echo "[segmentra] ERROR: Failed to install dependencies"
    exit 1
  fi
  echo "[segmentra] Dependencies installed - OK"
  echo
fi

# Optional: wipe local dev DB volume (DATA LOSS) if SEGMENTRA_RESET_DB=1
if [[ "${SEGMENTRA_RESET_DB:-0}" == "1" ]]; then
  echo "[segmentra] WARNING: SEGMENTRA_RESET_DB=1 - removing docker volumes (DATA LOSS)..."
  docker compose down -v
  echo
fi

# Start PostgreSQL container
echo "[segmentra] Starting PostgreSQL (docker compose)..."
docker compose up -d segmentra-db
if [[ $? -ne 0 ]]; then
  echo "[segmentra] ERROR: Failed to start PostgreSQL container"
  exit 1
fi

# Wait for PostgreSQL to be ready
echo "[segmentra] Waiting for PostgreSQL to be ready..."
TRY=0
while ! docker exec segmentra-segmentra-db-1 pg_isready -U segmentra >/dev/null 2>&1; do
  TRY=$((TRY + 1))
  if [[ $TRY -gt 30 ]]; then
    echo "[segmentra] ERROR: PostgreSQL did not become ready in time"
    exit 1
  fi
  sleep 1
done
echo "[segmentra] PostgreSQL is ready - OK"
echo

# Set up environment variables
# Use SEGMENTRA_DATABASE_URL if provided, otherwise use the local compose DB.
if [[ -n "${SEGMENTRA_DATABASE_URL:-}" ]]; then
  export DATABASE_URL="$SEGMENTRA_DATABASE_URL"
else
  export DATABASE_URL="postgres://segmentra:segmentra@127.0.0.1:15432/segmentra"
fi

export JWT_SECRET="${JWT_SECRET:-change-me-to-a-long-random-string}"
export PORT="${PORT:-8080}"
export BUNDLES_DIR="${BUNDLES_DIR:-./data/bundles}"
export ANSIBLE_RUNNER_CONTAINER="${ANSIBLE_RUNNER_CONTAINER:-segmentra-ansible-runner}"

echo "[segmentra] Configuration:"
echo "[segmentra]   DATABASE_URL=$DATABASE_URL"
echo "[segmentra]   PORT=$PORT"
echo "[segmentra]   MODE=$MODE"
echo

# Run migrations
echo "[segmentra] Running database migrations..."
npm run db:migrate
if [[ $? -ne 0 ]]; then
  echo "[segmentra] ERROR: Database migrations failed"
  exit 1
fi
echo "[segmentra] Migrations complete - OK"
echo

# Seed roles
echo "[segmentra] Seeding database roles..."
npm run db:seed
if [[ $? -ne 0 ]]; then
  echo "[segmentra] ERROR: Database seeding failed"
  exit 1
fi
echo "[segmentra] Roles seeded - OK"
echo

# Build workspaces
echo "[segmentra] Building workspaces..."
npm run build -ws
if [[ $? -ne 0 ]]; then
  echo "[segmentra] ERROR: Build failed"
  exit 1
fi
echo "[segmentra] Build complete - OK"
echo

# Launch API in background with all environment variables
echo "[segmentra] Launching API..."
(
  export DATABASE_URL
  export JWT_SECRET
  export PORT
  export BUNDLES_DIR
  export ANSIBLE_RUNNER_CONTAINER
  cd "$ROOT_DIR"
  echo "[API] Starting on port $PORT..."
  npm run dev -w apps/api
) &
API_PID=$!

# Launch UI in background
echo "[segmentra] Launching UI..."
(
  cd "$ROOT_DIR/apps/web"
  echo "[UI] Starting Vite dev server..."
  npm run dev
) &
WEB_PID=$!

echo
echo "[segmentra] ========================================"
echo "[segmentra] Setup complete!"
echo "[segmentra] ========================================"
echo
echo "[segmentra] Services:"
echo "[segmentra]   API: http://localhost:$PORT/api/health"
echo "[segmentra]   UI:  http://localhost:5173"
echo

echo "[segmentra] ========================================"
echo "[segmentra] Default Login Credentials"
echo "[segmentra] ========================================"
echo "[segmentra] Username: admin"
echo "[segmentra] Password: admin123"
echo
echo "[segmentra] IMPORTANT: Change the default password after first login!"
echo "[segmentra] You can change it in the UI or via API endpoint."
echo

cleanup() {
  echo
  echo "[segmentra] Stopping dev processes..."
  kill $API_PID $WEB_PID 2>/dev/null || true
  wait $API_PID $WEB_PID 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "[segmentra] All services are running."
echo "[segmentra] Press Ctrl+C to stop all services."
echo

wait $API_PID $WEB_PID
