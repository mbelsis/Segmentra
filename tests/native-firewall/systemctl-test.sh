#!/bin/sh
# Containers have no systemd PID 1. Model service enablement only; rules are loaded
# by the actual native manager in entrypoint.sh on every container restart.
set -eu
mode=$1
shift
case "$mode" in
  enable) touch "/var/backups/segmentra/test-enabled-$1" ;;
  is-enabled) for arg in "$@"; do case "$arg" in --*) ;; *) test -f "/var/backups/segmentra/test-enabled-$arg" ;; esac; done ;;
  is-active)
    for arg in "$@"; do
      case "$arg" in
        --*) ;;
        firewalld|firewalld.service) firewall-cmd --state >/dev/null ;;
        ufw|ufw.service) ufw status | grep -q '^Status: active' ;;
        *) exit 1 ;;
      esac
    done ;;
  *) echo "unsupported test systemctl command" >&2; exit 1 ;;
esac
