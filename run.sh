#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

ACTION=""
MODE=""
HARDENED_FLAG=0
HARDENED_COMPOSE_FILE="docker-compose.yml:docker-compose.hardened.yml"

# Parse arguments
for arg in "$@"; do
  case "$arg" in
    --start) ACTION="start" ;;
    --stop) ACTION="stop" ;;
    --status) ACTION="status" ;;
    --development|--dev|-d) MODE="development" ;;
    --production|--prod|-p) MODE="production" ;;
    --hardened) HARDENED_FLAG=1 ;;
  esac
done

if [ -z "$ACTION" ] || [ -z "$MODE" ]; then
  echo "Usage: ./run.sh <action> <mode>"
  echo ""
  echo "Actions:"
  echo "  --start    Start all services"
  echo "  --stop     Stop all services"
  echo "  --status   Show service status"
  echo ""
  echo "Modes:"
  echo "  --development  Local dev (Node.js + Docker DB)"
  echo "  --production   Docker Compose (all containers)"
  echo "  --hardened     With --production: also use docker-compose.hardened.yml and record it as"
  echo "                 COMPOSE_FILE in .env (install.sh --production --hardened does the same)."
  echo "                 Once recorded, every run.sh / docker compose call keeps using it."
  echo ""
  echo "Examples:"
  echo "  ./run.sh --start --development"
  echo "  ./run.sh --stop --production"
  echo "  ./run.sh --status --development"
  exit 1
fi

# Install deps when missing, refresh when a manifest is newer than the last install.
ensure_deps() {
  local marker="node_modules/.package-lock.json"
  if [ ! -f "$marker" ]; then
    echo "  Installing dependencies..."
    if [ -f package-lock.json ]; then npm ci; else npm install; fi
  elif [ -n "$(find package-lock.json package.json apps/*/package.json packages/*/package.json -newer "$marker" 2>/dev/null)" ]; then
    echo "  Dependency manifests changed - running npm install..."
    npm install
  fi
}

# Dev JWT secret: use $JWT_SECRET if set, otherwise a random secret generated once
# and stored in the untracked file .dev-jwt-secret.
load_dev_jwt_secret() {
  if [ -z "${JWT_SECRET:-}" ]; then
    if [ ! -s .dev-jwt-secret ]; then
      (umask 077 && node -e "process.stdout.write(require('crypto').randomBytes(32).toString('hex'))" > .dev-jwt-secret)
      echo "  Generated development JWT secret in .dev-jwt-secret"
    fi
    JWT_SECRET="$(cat .dev-jwt-secret)"
    export JWT_SECRET
  fi
}

if [ "$MODE" = "development" ]; then
  case "$ACTION" in
    start)
      echo "[segmentra] Starting development environment..."
      echo

      echo "[1/4] Checking dependencies..."
      ensure_deps

      # Start DB if not running
      echo "[2/4] Starting PostgreSQL..."
      docker compose up -d segmentra-db
      for _ in $(seq 1 30); do
        docker compose exec -T segmentra-db pg_isready -U segmentra >/dev/null 2>&1 && break
        sleep 1
      done

      export DATABASE_URL="${SEGMENTRA_DATABASE_URL:-postgres://segmentra:segmentra@127.0.0.1:15432/segmentra}"
      export BUNDLES_DIR="${BUNDLES_DIR:-./data/bundles}"
      load_dev_jwt_secret
      mkdir -p "$BUNDLES_DIR"

      # Build first: the API dev server runs apps/api/dist
      echo "[3/4] Migrating database and building..."
      npm run db:migrate
      npm run db:seed
      npm run build

      # Start API and UI
      echo "[4/4] Starting API and UI servers..."

      # Start API in background
      npm run dev -w apps/api &
      API_PID=$!

      # Start UI in background
      (cd apps/web && npm run dev) &
      WEB_PID=$!

      echo
      echo "  Services starting..."
      echo
      echo "  API: http://localhost:8080"
      echo "  UI:  http://localhost:5173"
      echo "  DB:  localhost:15432"
      echo
      echo "  Login: admin / admin123 (dev default unless SEGMENTRA_ADMIN_PASSWORD was set on first seed)"
      echo
      echo "  Press Ctrl+C to stop all services"

      # Wait for either to exit, then clean up
      trap "kill $API_PID $WEB_PID 2>/dev/null; exit 0" INT TERM
      wait $API_PID $WEB_PID
      ;;

    stop)
      echo "[segmentra] Stopping development environment..."
      # Stop Node processes
      pkill -f "apps/api" 2>/dev/null || true
      pkill -f "vite" 2>/dev/null || true
      # Stop Docker DB
      docker compose stop segmentra-db
      echo "  All services stopped"
      ;;

    status)
      echo "[segmentra] Development environment status:"
      echo
      echo "  PostgreSQL:"
      docker compose ps segmentra-db 2>/dev/null || echo "    Not running"
      echo
      echo "  API (port 8080):"
      curl -sf http://localhost:8080/api/health >/dev/null 2>&1 && echo "    Running" || echo "    Not running"
      echo
      echo "  UI (port 5173):"
      curl -sf http://localhost:5173 >/dev/null 2>&1 && echo "    Running" || echo "    Not running"
      ;;
  esac

elif [ "$MODE" = "production" ]; then
  # Hardened mode (docker-compose.hardened.yml) must be applied to EVERY compose call, or a
  # plain `docker compose up -d` recreates the containers without it (Docker socket mounted
  # again, API/DB published, writable filesystems). The source of truth is COMPOSE_FILE in
  # .env, which docker compose reads by itself.
  HARDENED=0
  if [ "$HARDENED_FLAG" = "1" ]; then
    touch .env
    chmod 600 .env
    if grep -q '^COMPOSE_FILE=' .env; then
      if ! grep -q '^COMPOSE_FILE=.*docker-compose.hardened.yml' .env; then
        echo "[segmentra] ERROR: .env sets COMPOSE_FILE without docker-compose.hardened.yml; set it to:"
        echo "            COMPOSE_FILE=$HARDENED_COMPOSE_FILE"
        exit 1
      fi
    else
      if [ -s .env ] && [ -n "$(tail -c1 .env)" ]; then echo >> .env; fi
      echo "COMPOSE_FILE=$HARDENED_COMPOSE_FILE" >> .env
      echo "[segmentra] Recorded hardened mode in .env (COMPOSE_FILE=$HARDENED_COMPOSE_FILE)"
    fi
  fi
  if [ -n "${COMPOSE_FILE:-}" ]; then
    # An exported COMPOSE_FILE overrides .env for docker compose.
    case "$COMPOSE_FILE" in *docker-compose.hardened.yml*) HARDENED=1 ;; esac
  elif [ -f .env ] && grep -q '^COMPOSE_FILE=.*docker-compose.hardened.yml' .env; then
    HARDENED=1
  else
    # Not recorded, but the running API container is hardened (started by hand with
    # -f docker-compose.hardened.yml): keep it hardened instead of silently undoing it.
    APP_ID="$(docker compose ps -q segmentra-app 2>/dev/null || true)"
    if [ -n "$APP_ID" ] && [ "$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$APP_ID" 2>/dev/null)" = "true" ]; then
      echo "[segmentra] The running stack uses docker-compose.hardened.yml; keeping it for this command."
      echo "            Run with --hardened once to record it in .env."
      export COMPOSE_FILE="$HARDENED_COMPOSE_FILE"
      HARDENED=1
    fi
  fi
  [ "$HARDENED" = "1" ] && echo "[segmentra] Hardened mode (docker-compose.yml + docker-compose.hardened.yml)"

  case "$ACTION" in
    start)
      echo "[segmentra] Starting production environment..."
      if [ ! -f .env ] || ! grep -q '^JWT_SECRET=.' .env || ! grep -q '^SEGMENTRA_KEK_B64=.' .env; then
        if [ -z "${JWT_SECRET:-}" ] || [ -z "${SEGMENTRA_KEK_B64:-}" ]; then
          echo "  WARNING: JWT_SECRET and/or SEGMENTRA_KEK_B64 are not set (in the environment or .env)."
          echo "           The API container will refuse to start. Run ./install.sh --production to generate them."
        fi
      fi
      # The API container entrypoint runs database migrations and the seed on every start.
      docker compose up -d
      echo
      echo "  Services started (the API runs migrations on startup: docker compose logs -f segmentra-app):"
      echo "    UI:  http://localhost:${WEB_PORT:-80}"
      if [ "$HARDENED" = "1" ]; then
        echo "    API: not published (hardened); use the UI's /api proxy"
        echo "    DB:  not published (hardened)"
      else
        echo "    API: http://127.0.0.1:${API_PORT:-8080}"
        echo "    DB:  127.0.0.1:${DB_PORT:-15432}"
      fi
      echo
      docker compose ps
      ;;

    stop)
      echo "[segmentra] Stopping production environment..."
      docker compose stop
      echo "  All services stopped"
      ;;

    status)
      echo "[segmentra] Production environment status:"
      echo
      docker compose ps
      ;;
  esac
fi
