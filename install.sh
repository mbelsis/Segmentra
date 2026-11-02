#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

MODE=""
HARDENED=0
ASSUME_YES=0
CHECK_ONLY=0
HARDENED_COMPOSE_FILE="docker-compose.yml:docker-compose.hardened.yml"

install_usage() {
  echo "Usage: ./install.sh --development | --production [--hardened] [--yes] [--check]"
  echo "  --development  Install for local development (Node.js + Docker DB)"
  echo "  --production   Install for production (all Docker containers)"
  echo "  --hardened     With --production: use docker-compose.hardened.yml too (no Docker socket,"
  echo "                 read-only containers, only nginx published; requires the SSH Direct executor)."
  echo "                 Recorded as COMPOSE_FILE in .env, so every later 'docker compose' command,"
  echo "                 ./run.sh and scripts/segmentra-backup.sh keep using the hardened override."
  echo "  --yes, -y      Accept every offer to start Docker or install a missing prerequisite"
  echo "  --check        Only report the prerequisites for the chosen mode; change nothing"
  exit 1
}

# Normalize flags
for arg in "${@:---development}"; do
  case "$arg" in
    --development|--dev|-d) MODE="development" ;;
    --production|--prod|-p) MODE="production" ;;
    --hardened) HARDENED=1 ;;
    --yes|-y) ASSUME_YES=1 ;;
    --check) CHECK_ONLY=1 ;;
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

# ---------------------------------------------------------------------------------------------
# Prerequisites: report everything first, then fix what can be fixed, asking before each change.
# Docker itself is never installed from here (licensing, admin rights, reboots), only started.
# Written for bash 3.2, which is what macOS ships.
# ---------------------------------------------------------------------------------------------
OS="$(uname -s)"
PKG=""
if [ "$OS" = "Darwin" ]; then
  if command -v brew >/dev/null 2>&1; then PKG="brew"; fi
else
  for candidate in apt-get dnf yum brew; do
    if command -v "$candidate" >/dev/null 2>&1; then PKG="$candidate"; break; fi
  done
fi

confirm() {
  if [ "$ASSUME_YES" = "1" ]; then echo "  $1 [Y/n] y (--yes)"; return 0; fi
  if [ ! -t 0 ]; then echo "  $1 Skipped: no terminal to ask on (use --yes to accept)."; return 1; fi
  local reply=""
  read -r -p "  $1 [Y/n] " reply || return 1
  case "$reply" in ""|[Yy]*) return 0 ;; *) return 1 ;; esac
}

run_root() {
  if [ "$(id -u)" = "0" ]; then "$@"
  elif command -v sudo >/dev/null 2>&1; then sudo "$@"
  else echo "  ERROR: this step needs root and sudo is not installed: $*"; return 1
  fi
}

node_major() {
  local v
  v="$(node -v 2>/dev/null)" || v=""
  v="${v#v}"; v="${v%%.*}"
  case "$v" in ''|*[!0-9]*) echo 0 ;; *) echo "$v" ;; esac
}
node_ok() {
  command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1 && [ "$(node_major)" -ge 20 ]
}

docker_state() {
  command -v docker >/dev/null 2>&1 || { echo missing; return 0; }
  local out
  if out="$(docker info 2>&1)"; then echo ok; return 0; fi
  case "$out" in
    *[Pp]ermission\ denied*) echo denied ;;
    *) echo stopped ;;
  esac
}
compose_ok() { docker compose version >/dev/null 2>&1; }

docker_install_hint() {
  if [ "$OS" = "Darwin" ]; then echo "         Install Docker Desktop: https://docs.docker.com/desktop/"
  else echo "         Install Docker Engine and the compose plugin: https://docs.docker.com/engine/install/"
  fi
}

start_docker() {
  if [ -n "${DOCKER_HOST:-}" ]; then
    echo "  ERROR: the Docker daemon at DOCKER_HOST=$DOCKER_HOST is not reachable."
    return 1
  fi
  if ! confirm "Docker is not running. Start it?"; then return 1; fi
  if [ "$OS" = "Darwin" ]; then
    open -a Docker || return 1
  elif command -v systemctl >/dev/null 2>&1; then
    run_root systemctl start docker || return 1
  elif command -v service >/dev/null 2>&1; then
    run_root service docker start || return 1
  else
    echo "  ERROR: no systemctl or service command to start Docker with."
    return 1
  fi
  echo "  Waiting for Docker (up to 2 minutes)..."
  local i
  for i in $(seq 1 60); do
    if [ "$(docker_state)" = "ok" ]; then return 0; fi
    sleep 2
  done
  echo "  ERROR: Docker did not become ready in time."
  return 1
}

# Newest nodejs major version the system's package sources offer (0 if unknown).
node_candidate_major() {
  local v=""
  case "$PKG" in
    apt-get) v="$(apt-cache policy nodejs 2>/dev/null | awk '/Candidate:/ {print $2}')" ;;
    # --whatprovides: Fedora ships it as nodejs22 etc., which only provide "nodejs".
    dnf|yum) v="$("$PKG" -q repoquery --latest-limit=1 --whatprovides nodejs --qf '%{version}\n' 2>/dev/null | sort -V | tail -n1)" ;;
  esac
  v="${v#*:}"; v="${v%%.*}"
  case "$v" in ''|*[!0-9]*) echo 0 ;; *) echo "$v" ;; esac
}

# The distribution's Node.js is too old: use NodeSource, which is a third party, so ask separately.
install_node_nodesource() {
  local family="$1" script
  if ! confirm "This system only offers an older Node.js. Add the third-party NodeSource repository for Node.js 22?"; then return 1; fi
  if ! command -v curl >/dev/null 2>&1; then
    if [ "$family" = "deb" ]; then
      run_root env DEBIAN_FRONTEND=noninteractive apt-get install -y curl ca-certificates gnupg || return 1
    else
      run_root "$PKG" install -y curl || return 1
    fi
  fi
  script="$(mktemp)"
  if ! curl -fsSL "https://$family.nodesource.com/setup_22.x" -o "$script"; then
    rm -f "$script"
    echo "  ERROR: could not download the NodeSource setup script (no internet access?)."
    return 1
  fi
  if ! run_root bash "$script"; then rm -f "$script"; return 1; fi
  rm -f "$script"
  if [ "$family" = "deb" ]; then
    run_root env DEBIAN_FRONTEND=noninteractive apt-get install -y nodejs
  else
    run_root "$PKG" install -y nodejs
  fi
}

install_node() {
  case "$PKG" in
    brew)
      confirm "Install Node.js with Homebrew?" || return 1
      brew install node
      ;;
    apt-get)
      confirm "Install Node.js with apt?" || return 1
      run_root apt-get update -qq || return 1
      if [ "$(node_candidate_major)" -ge 20 ]; then
        run_root env DEBIAN_FRONTEND=noninteractive apt-get install -y nodejs npm
      else
        install_node_nodesource deb
      fi
      ;;
    dnf|yum)
      confirm "Install Node.js with $PKG?" || return 1
      if [ "$(node_candidate_major)" -ge 20 ]; then
        run_root "$PKG" install -y nodejs npm
      else
        install_node_nodesource rpm
      fi
      ;;
    *)
      echo "  No supported package manager found (Homebrew, apt, dnf, yum)."
      return 1
      ;;
  esac
}

# Only needed by the SSH executor when the API runs on this machine (development mode), and
# only for some credentials, so a tool that stays missing is a warning and not a failure.
install_optional_tool() {
  local tool="$1" why="$2" package=""
  command -v "$tool" >/dev/null 2>&1 && return 0
  case "$tool:$PKG" in
    ssh:apt-get) package="openssh-client" ;;
    ssh:dnf|ssh:yum) package="openssh-clients" ;;
    sshpass:apt-get|sshpass:dnf|sshpass:yum) package="sshpass" ;;
  esac
  if [ -n "$package" ] && confirm "$tool not found ($why). Install $package with $PKG?"; then
    if [ "$PKG" = "apt-get" ]; then
      run_root env DEBIAN_FRONTEND=noninteractive apt-get install -y "$package" || true
    else
      run_root "$PKG" install -y "$package" || true
    fi
  fi
  hash -r
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "  WARNING: $tool is still missing: $why. Production mode includes it in the API image."
  fi
}

check_prerequisites() {
  local state compose="ok" node="ok" blocked=0 failed=0 tool
  state="$(docker_state)"
  case "$state" in
    ok)      echo "  [ok]      Docker is running" ;;
    stopped) echo "  [stopped] Docker is installed but not running"; failed=1 ;;
    denied)
      echo "  [blocked] Docker is running but this user may not use it"
      echo "            Add the user to the docker group (sudo usermod -aG docker \$USER), then log in again."
      blocked=1; failed=1
      ;;
    missing)
      echo "  [missing] Docker"
      docker_install_hint
      blocked=1; failed=1
      ;;
  esac
  if [ "$state" != "missing" ]; then
    if compose_ok; then
      echo "  [ok]      Docker Compose"
    else
      compose="missing"
      echo "  [missing] Docker Compose plugin"
      docker_install_hint
      blocked=1; failed=1
    fi
  fi

  if [ "$MODE" = "development" ]; then
    if node_ok; then
      echo "  [ok]      Node.js $(node -v), npm $(npm -v)"
    else
      node="missing"; failed=1
      if command -v node >/dev/null 2>&1; then
        echo "  [old]     Node.js 20+ and npm are required. Found: $(node -v), npm: $(command -v npm >/dev/null 2>&1 && echo yes || echo no)"
      else
        echo "  [missing] Node.js 20+"
      fi
    fi
    for tool in ssh sshpass; do
      if command -v "$tool" >/dev/null 2>&1; then echo "  [ok]      $tool"
      else echo "  [note]    $tool not found (optional)"
      fi
    done
  fi

  if [ "$CHECK_ONLY" = "1" ]; then
    echo
    if [ "$failed" = "1" ]; then echo "Some prerequisites are missing."; exit 1; fi
    echo "All required prerequisites are in place."
    exit 0
  fi

  # Stop before changing anything if a problem cannot be fixed from here.
  if [ "$blocked" = "1" ]; then
    echo
    echo "ERROR: fix the problems above and run the installer again. Nothing was changed."
    exit 1
  fi

  if [ "$state" = "stopped" ] && ! start_docker; then
    echo "ERROR: Docker is not running. Start it and run the installer again."
    exit 1
  fi

  if [ "$node" = "missing" ]; then
    if ! install_node; then
      echo "  Node.js was not installed."
    fi
    hash -r
    if ! node_ok; then
      echo "ERROR: Node.js 20+ and npm are required. Install them from https://nodejs.org and run the installer again."
      echo "       If you use a version manager such as nvm, switch to Node.js 20 or newer in this shell."
      exit 1
    fi
    echo "  Node.js $(node -v), npm $(npm -v) OK"
  fi

  if [ "$MODE" = "development" ]; then
    install_optional_tool ssh "deployments over SSH will not work"
    install_optional_tool sshpass "password-based SSH credentials will not work; SSH keys are fine"
  fi
}

if [ "$MODE" = "development" ]; then STEPS=5; else STEPS=6; fi
echo "[1/$STEPS] Checking prerequisites..."
check_prerequisites

if [ "$MODE" = "development" ]; then
  # Install npm dependencies
  echo "[2/5] Installing npm dependencies..."
  npm install

  # Start PostgreSQL container
  echo "[3/5] Starting PostgreSQL..."
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
  echo "[4/5] Building workspaces..."
  npm run build

  # Run migrations and seed
  echo "[5/5] Setting up database..."
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
