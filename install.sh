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
  echo " Default credentials:"
  echo "   Username: admin"
  echo "   Password: admin123"
  echo
  echo " Optional: import demo data:"
  echo "   node demo-data/seed-demo-data.js"
  echo "========================================"

elif [ "$MODE" = "production" ]; then
  # Build all Docker images
  echo "[2/6] Building Docker images..."
  docker compose build

  # Start services
  echo "[3/6] Starting all services..."
  docker compose up -d

  # Wait for DB
  echo "[4/6] Waiting for PostgreSQL..."
  sleep 5
  for i in $(seq 1 30); do
    if docker compose exec -T segmentra-db pg_isready -U segmentra >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
  echo "  PostgreSQL ready"

  # Run migrations
  echo "[5/6] Running database migrations..."
  docker compose exec -T segmentra-app sh -c "cd /app && DATABASE_URL=postgres://segmentra:segmentra@segmentra-db:5432/segmentra node node_modules/.bin/node-pg-migrate up -m packages/db/migrations"

  # Seed roles and admin
  echo "[6/6] Seeding default data..."
  docker compose exec -T segmentra-app sh -c "cd /app && DATABASE_URL=postgres://segmentra:segmentra@segmentra-db:5432/segmentra node packages/db/scripts/seed-roles.js"

  echo
  echo "========================================"
  echo " Production installation complete!"
  echo "========================================"
  echo
  echo " Services running:"
  echo "   UI:  http://localhost:80"
  echo "   API: http://localhost:8080"
  echo "   DB:  localhost:15432"
  echo
  echo " Default credentials:"
  echo "   Username: admin"
  echo "   Password: admin123"
  echo
  echo " Manage services:"
  echo "   ./run.sh --start --production"
  echo "   ./run.sh --stop --production"
  echo "========================================"
fi
