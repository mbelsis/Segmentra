#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

MODE="${1:-}"
echo "[segmentra] Starting dev environment... (mode=${MODE:-normal})"

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
if [[ "$MODE" == "dev" ]]; then
  export SEGMENTRA_BOOTSTRAP_TOKEN="${SEGMENTRA_BOOTSTRAP_TOKEN:-dev-bootstrap-token}"
fi

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

if [[ "$MODE" == "dev" ]]; then
  echo "[segmentra] Dev mode: bootstrapping admin token (no LDAP)..."
  for i in $(seq 1 60); do
    if curl -fsS "http://localhost:8080/api/health" >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done

  set +e
  BOOTSTRAP_JSON="$(curl -s -X POST "http://localhost:8080/api/admin/bootstrap" \
    -H "content-type: application/json" \
    -d "{\"token\":\"$SEGMENTRA_BOOTSTRAP_TOKEN\",\"username\":\"bootstrap_admin\"}")"
  CURL_EXIT=$?
  set -e

  if [[ $CURL_EXIT -ne 0 || -z "$BOOTSTRAP_JSON" ]]; then
    echo "[segmentra] Bootstrap request failed. You can bootstrap manually later."
  else
    TOKEN="$(printf '%s' "$BOOTSTRAP_JSON" | node -e "let s='';process.stdin.on('data',d=>s+=d);process.stdin.on('end',()=>{try{console.log(JSON.parse(s).token||'')}catch{console.log('')}})")"
    if [[ -n "$TOKEN" ]]; then
      echo "$TOKEN" > .dev-admin-jwt.txt
      echo "[segmentra] Wrote JWT to .dev-admin-jwt.txt"
      echo "[segmentra] In browser DevTools console, run:"
      echo "  localStorage.setItem('segmentra_token','$(cat .dev-admin-jwt.txt)'); location.reload()"
    else
      echo "[segmentra] Bootstrap response did not include a token (maybe already initialized)."
      echo "[segmentra] Response: $BOOTSTRAP_JSON"
    fi
  fi
else
  echo "[segmentra] If you want to access the UI without LDAP, run: ./start.sh dev"
fi

wait $API_PID $WEB_PID


