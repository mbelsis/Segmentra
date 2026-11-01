#!/usr/bin/env bash
#
# Full database backup and restore for a Docker-based Segmentra installation.
#
#   ./scripts/segmentra-backup.sh dump   [FILE]        # pg_dump -> backups/segmentra-<timestamp>.sql.gz (or FILE)
#   ./scripts/segmentra-backup.sh restore FILE [--yes] # replace the database with FILE (asks unless --yes)
#   ./scripts/segmentra-backup.sh list                 # list backups in ./backups
#
# The dump is the complete database (inventory, policies, deployments, audit log, users, encrypted
# secrets). Encrypted secrets are only usable with the same SEGMENTRA_KEK_B64, so keep a copy of
# .env with every backup. A restore replaces everything in the database; stop the API first
# (docker compose stop segmentra-app) so nothing writes during the restore, and start it again
# afterwards. Restore into the same Segmentra version the dump was taken from (or an older dump
# into a newer version: the API runs the migrations on start). The file is checked first (gzip
# integrity, PostgreSQL dump header and completion marker) and the restore, including dropping
# the old schema, runs as ONE transaction: if anything fails the old database is left intact.
#
# Environment: DB_USER / DB_NAME (default segmentra), COMPOSE_FILE / COMPOSE_PROFILES as for docker compose.
set -euo pipefail
# Dumps contain password hashes and encrypted secrets: never create them group/world-readable.
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

DB_USER="${DB_USER:-segmentra}"
DB_NAME="${DB_NAME:-segmentra}"
SERVICE="segmentra-db"
BACKUP_DIR="${SEGMENTRA_BACKUP_DIR:-$ROOT_DIR/backups}"

usage() {
  sed -n '2,18p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit 1
}

need_db() {
  if ! docker compose ps --status running --services 2>/dev/null | grep -qx "$SERVICE"; then
    echo "[backup] ERROR: the $SERVICE container is not running (docker compose up -d $SERVICE)" >&2
    exit 1
  fi
}

# Print the (decompressed) dump in $FILE.
cat_dump() {
  case "$FILE" in
    *.gz) gunzip -c "$FILE" ;;
    *) cat "$FILE" ;;
  esac
}

cmd="${1:-}"
case "$cmd" in
  dump)
    need_db
    mkdir -p -m 700 "$BACKUP_DIR"
    chmod 700 "$BACKUP_DIR" 2>/dev/null || true
    FILE="${2:-$BACKUP_DIR/segmentra-$(date -u +%Y%m%dT%H%M%SZ).sql.gz}"
    echo "[backup] Dumping database $DB_NAME to $FILE"
    # Write to a temporary file next to the target and rename only after a complete dump,
    # so a failed pg_dump never leaves a truncated file that looks like a valid backup.
    TMP_FILE="$FILE.partial.$$"
    trap 'rm -f "$TMP_FILE"' EXIT
    docker compose exec -T "$SERVICE" pg_dump -U "$DB_USER" -d "$DB_NAME" --no-owner --no-privileges | gzip -9 > "$TMP_FILE"
    chmod 600 "$TMP_FILE"
    mv -f "$TMP_FILE" "$FILE"
    trap - EXIT
    echo "[backup] Done: $(du -h "$FILE" | cut -f1)"
    echo "[backup] Keep a copy of .env (SEGMENTRA_KEK_B64, JWT_SECRET) with this file: stored secrets cannot be decrypted without it."
    ;;
  restore)
    FILE="${2:-}"
    [[ -n "$FILE" && -f "$FILE" ]] || { echo "[backup] ERROR: backup file not found: '$FILE'" >&2; usage; }

    # 1. Validate the file BEFORE touching the database.
    case "$FILE" in
      *.gz)
        if ! gunzip -t "$FILE" 2>/dev/null; then
          echo "[backup] ERROR: $FILE is not a valid gzip file (corrupt or truncated); nothing was changed." >&2
          exit 1
        fi
        ;;
    esac
    # (subshell + "|| true": head/tail closing the pipe early must not trip pipefail)
    DUMP_HEAD="$( (cat_dump | head -n 20) 2>/dev/null || true)"
    DUMP_TAIL="$( (cat_dump | tail -n 20) 2>/dev/null || true)"
    if ! grep -q -- '-- PostgreSQL database dump' <<<"$DUMP_HEAD"; then
      echo "[backup] ERROR: $FILE does not look like a PostgreSQL plain-text dump (no pg_dump header); nothing was changed." >&2
      exit 1
    fi
    if ! grep -q -- '-- PostgreSQL database dump complete' <<<"$DUMP_TAIL"; then
      echo "[backup] ERROR: $FILE has no pg_dump completion marker (truncated dump?); nothing was changed." >&2
      exit 1
    fi

    # 2. Confirmation: --yes, or an interactive prompt.
    if [[ "${3:-}" != "--yes" ]]; then
      echo "[backup] This REPLACES the whole database $DB_NAME with the contents of $FILE."
      if [[ -t 0 && -t 1 ]]; then
        read -r -p "[backup] Type the database name ($DB_NAME) to continue: " answer
        if [[ "$answer" != "$DB_NAME" ]]; then
          echo "[backup] Aborted; nothing was changed." >&2
          exit 1
        fi
      else
        echo "[backup] Stop the API first (docker compose stop segmentra-app), then re-run with --yes."
        exit 1
      fi
    fi
    need_db
    if docker compose ps --status running --services 2>/dev/null | grep -qx "segmentra-app"; then
      echo "[backup] ERROR: segmentra-app is running. Stop it first: docker compose stop segmentra-app" >&2
      exit 1
    fi

    # 3. Drop + recreate the schema and load the dump in ONE transaction (psql -1, stop on the
    #    first error): on any failure PostgreSQL rolls back and the old database is untouched.
    echo "[backup] Restoring $FILE into $DB_NAME (single transaction)"
    {
      printf '%s\n' 'DROP SCHEMA public CASCADE;' 'CREATE SCHEMA public;' 'CREATE EXTENSION IF NOT EXISTS "uuid-ossp";'
      cat_dump
    } | docker compose exec -T -e PGOPTIONS='-c client_min_messages=warning' "$SERVICE" \
          psql -U "$DB_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1 -q --single-transaction -f - >/dev/null \
      || { echo "[backup] ERROR: restore failed; the transaction was rolled back and the previous database is unchanged." >&2; exit 1; }
    echo "[backup] Restore complete. Start the API again: docker compose up -d segmentra-app (it runs any pending migrations)."
    ;;
  list)
    ls -lh "$BACKUP_DIR"/segmentra-*.sql.gz 2>/dev/null || echo "[backup] No backups in $BACKUP_DIR"
    ;;
  *)
    usage
    ;;
esac
