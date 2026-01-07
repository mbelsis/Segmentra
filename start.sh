#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

echo "[segmentra] Starting dev environment..."

if [[ ! -d node_modules ]]; then
  echo "[segmentra] Installing dependencies (npm install)..."
  npm install
fi

echo "[segmentra] Starting Postgres (docker compose)..."
if [[ "${SEGMENTRA_RESET_DB:-0}" == "1" ]]; then
  echo "[segmentra] SEGMENTRA_RESET_DB=1 -> removing docker volumes (DATA LOSS)..."
  docker compose down -v
fi
docker compose up -d segmentra-db

export DATABASE_URL="${SEGMENTRA_DATABASE_URL:-${DATABASE_URL:-postgres://segmentra:segmentra@127.0.0.1:15432/segmentra}}"
export JWT_SECRET="${JWT_SECRET:-change-me-to-a-long-random-string}"
export SEGMENTRA_BOOTSTRAP_TOKEN="${SEGMENTRA_BOOTSTRAP_TOKEN:-dev-bootstrap-token}"

echo "[segmentra] Using DATABASE_URL=$DATABASE_URL"

echo "[segmentra] Running migrations + seeding roles..."
npm run db:migrate
npm run db:seed

echo "[segmentra] Building workspaces..."
npm run build -ws

echo "[segmentra] Starting API + UI..."

cleanup() {
  echo
  echo "[segmentra] Stopping dev processes..."
  jobs -p | xargs -r kill >/dev/null 2>&1 || true
}
trap cleanup EXIT

npm run dev -w apps/api &
API_PID=$!

(cd apps/web && npm run dev) &
WEB_PID=$!

echo "[segmentra] API PID=$API_PID, WEB PID=$WEB_PID"
echo "[segmentra] API health: http://localhost:8080/api/health"

echo "[segmentra] If you want to access the UI without LDAP:"
echo "  1) Wait for the API to be up, then run:"
echo "     curl -s -X POST http://localhost:8080/api/admin/bootstrap \\"
echo "       -H 'content-type: application/json' \\"
echo "       -d '{\"token\":\"'\"$SEGMENTRA_BOOTSTRAP_TOKEN\"'\",\"username\":\"bootstrap_admin\"}'"
echo "  2) Copy token, then in browser DevTools console:"
echo "     localStorage.setItem('segmentra_token','PASTE_TOKEN'); location.reload()"

wait $API_PID $WEB_PID


