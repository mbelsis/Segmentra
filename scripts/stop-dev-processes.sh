#!/usr/bin/env bash
# Stops the development API and UI of THIS checkout only: other projects may run vite or
# node too. Stopping "npm run dev" is not enough, because `node --watch` survives its parent.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
PATTERN='dist/index\.js|/\.bin/vite|sh -c vite|npm run dev'

if ! command -v pgrep >/dev/null 2>&1; then
  echo "  WARNING: pgrep is not installed, so the API and UI were not stopped."
  exit 0
fi

pid_cwd() {
  if [ -e "/proc/$1/cwd" ]; then
    readlink "/proc/$1/cwd" 2>/dev/null
  elif command -v lsof >/dev/null 2>&1; then
    lsof -a -p "$1" -d cwd -Fn 2>/dev/null | sed -n 's/^n//p'
  fi
}

own_pids() {
  local pid cwd
  for pid in $(pgrep -f "$PATTERN" 2>/dev/null); do
    [ "$pid" = "$$" ] && continue
    cwd="$(pid_cwd "$pid")"
    case "$cwd/" in "$ROOT"/*) echo "$pid" ;; esac
  done
}

PIDS="$(own_pids)"
[ -n "$PIDS" ] || exit 0
# shellcheck disable=SC2086
kill $PIDS 2>/dev/null
for _ in 1 2 3 4 5; do
  sleep 1
  PIDS="$(own_pids)"
  [ -n "$PIDS" ] || exit 0
done
# shellcheck disable=SC2086
kill -9 $PIDS 2>/dev/null
exit 0
