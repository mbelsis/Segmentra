#!/usr/bin/env bash
#
# Full database backup and restore for a Docker-based Segmentra installation.
#
#   ./scripts/segmentra-backup.sh dump   [FILE]        # pg_dump -> backups/segmentra-<timestamp>.sql.gz (or FILE)
#   ./scripts/segmentra-backup.sh restore FILE --yes   # drop and recreate the schema, then restore FILE
#   ./scripts/segmentra-backup.sh list                 # list backups in ./backups
#
# The dump is the complete database (inventory, policies, deployments, audit log, users, encrypted
# secrets). Encrypted secrets are only usable with the same SEGMENTRA_KEK_B64, so keep a copy of
# .env with every backup. A restore replaces everything in the database; stop the API first
# (docker compose stop segmentra-app) so nothing writes during the restore, and start it again
# afterwards. Restore into the same Segmentra version the dump was taken from (or an older dump
# into a newer version: the API runs the migrations on start).
#
# Environment: DB_USER / DB_NAME (default segmentra), COMPOSE_FILE / COMPOSE_PROFILES as for docker compose.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

DB_USER="${DB_USER:-segmentra}"
DB_NAME="${DB_NAME:-segmentra}"
SERVICE="segmentra-db"
BACKUP_DIR="${SEGMENTRA_BACKUP_DIR:-$ROOT_DIR/backups}"

usage() {
  sed -n '2,15p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit 1
}

need_db() {
  if ! docker compose ps --status running --services 2>/dev/null | grep -qx "$SERVICE"; then
    echo "[backup] ERROR: the $SERVICE container is not running (docker compose up -d $SERVICE)" >&2
    exit 1
  fi
}

cmd="${1:-}"
case "$cmd" in
  dump)
    need_db
    mkdir -p "$BACKUP_DIR"
    FILE="${2:-$BACKUP_DIR/segmentra-$(date -u +%Y%m%dT%H%M%SZ).sql.gz}"
    echo "[backup] Dumping database $DB_NAME to $FILE"
    docker compose exec -T "$SERVICE" pg_dump -U "$DB_USER" -d "$DB_NAME" --no-owner --no-privileges | gzip -9 > "$FILE"
    chmod 600 "$FILE"
    echo "[backup] Done: $(du -h "$FILE" | cut -f1)"
    echo "[backup] Keep a copy of .env (SEGMENTRA_KEK_B64, JWT_SECRET) with this file: stored secrets cannot be decrypted without it."
    ;;
  restore)
    FILE="${2:-}"
    [[ -n "$FILE" && -f "$FILE" ]] || { echo "[backup] ERROR: backup file not found: '$FILE'" >&2; usage; }
    if [[ "${3:-}" != "--yes" ]]; then
      echo "[backup] This REPLACES the whole database $DB_NAME with the contents of $FILE."
      echo "[backup] Stop the API first (docker compose stop segmentra-app), then re-run with --yes."
      exit 1
    fi
    need_db
    if docker compose ps --status running --services 2>/dev/null | grep -qx "segmentra-app"; then
      echo "[backup] ERROR: segmentra-app is running. Stop it first: docker compose stop segmentra-app" >&2
      exit 1
    fi
    echo "[backup] Dropping and recreating schema public in $DB_NAME"
    docker compose exec -T -e PGOPTIONS='-c client_min_messages=warning' "$SERVICE" psql -U "$DB_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1 -q \
      -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public; CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";"
    echo "[backup] Restoring $FILE"
    case "$FILE" in
      *.gz) gunzip -c "$FILE" ;;
      *) cat "$FILE" ;;
    esac | docker compose exec -T "$SERVICE" psql -U "$DB_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1 -q
    echo "[backup] Restore complete. Start the API again: docker compose up -d segmentra-app (it runs any pending migrations)."
    ;;
  list)
    ls -lh "$BACKUP_DIR"/segmentra-*.sql.gz 2>/dev/null || echo "[backup] No backups in $BACKUP_DIR"
    ;;
  *)
    usage
    ;;
esac
