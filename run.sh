#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

ACTION=""
MODE=""

# Parse arguments
for arg in "$@"; do
  case "$arg" in
    --start) ACTION="start" ;;
    --stop) ACTION="stop" ;;
    --status) ACTION="status" ;;
    --development|--dev|-d) MODE="development" ;;
    --production|--prod|-p) MODE="production" ;;
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
  echo ""
  echo "Examples:"
  echo "  ./run.sh --start --development"
  echo "  ./run.sh --stop --production"
  echo "  ./run.sh --status --development"
  exit 1
fi

if [ "$MODE" = "development" ]; then
  case "$ACTION" in
    start)
      echo "[segmentra] Starting development environment..."
      echo

      # Start DB if not running
      echo "[1/3] Starting PostgreSQL..."
      docker compose up -d segmentra-db
      sleep 2

      # Start API and UI
      echo "[2/3] Starting API and UI servers..."
      export DATABASE_URL="postgres://segmentra:segmentra@127.0.0.1:15432/segmentra"
      export JWT_SECRET="dev-secret-change-me-in-production"
      export BUNDLES_DIR="./data/bundles"

      # Start API in background
      npm run dev -w apps/api &
      API_PID=$!

      # Start UI in background
      (cd apps/web && npm run dev) &
      WEB_PID=$!

      echo
      echo "[3/3] Services starting..."
      echo
      echo "  API: http://localhost:8080"
      echo "  UI:  http://localhost:5173"
      echo "  DB:  localhost:15432"
      echo
      echo "  Login: admin / admin123"
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
  case "$ACTION" in
    start)
      echo "[segmentra] Starting production environment..."
      docker compose up -d
      echo
      echo "  Services started:"
      echo "    UI:  http://localhost:80"
      echo "    API: http://localhost:8080"
      echo "    DB:  localhost:15432"
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
