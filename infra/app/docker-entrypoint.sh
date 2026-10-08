#!/bin/sh
# Segmentra API container entrypoint: validate configuration, run migrations + seed, start the API.
set -eu

fail() {
  echo "[segmentra] FATAL: $*" >&2
  exit 1
}

[ -n "${DATABASE_URL:-}" ] || fail "DATABASE_URL must be set."
[ -n "${JWT_SECRET:-}" ] || fail "JWT_SECRET must be set (at least 32 random characters, e.g. 'openssl rand -hex 32')."

if [ "${NODE_ENV:-}" = "production" ] && [ -z "${SEGMENTRA_KEK_B64:-}" ]; then
  fail "SEGMENTRA_KEK_B64 must be set in production (32 random bytes, base64: 'openssl rand -base64 32'). Without it stored secrets are encrypted with a key derived from JWT_SECRET."
fi

if [ "${SEGMENTRA_SKIP_MIGRATIONS:-0}" != "1" ]; then
  echo "[segmentra] Running database migrations..."
  node /app/packages/db/scripts/migrate.js up
  echo "[segmentra] Seeding roles / initial admin..."
  node /app/packages/db/scripts/seed-roles.js
fi

exec "$@"
