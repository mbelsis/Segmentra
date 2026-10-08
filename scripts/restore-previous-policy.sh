#!/bin/bash
# restore-previous-policy.sh
#
# Restores Segmentra's previous firewall state on target hosts from Segmentra backups.
# Use this after a deployment expires or when you need to rollback deployed policies.
#
# Only Segmentra's own state is restored: nftables `table inet segmentra`, or the
# iptables/ip6tables chains SEGMENTRA-IN/OUT(/FWD) and their INPUT/OUTPUT(/FORWARD) jumps. Tables and
# chains of other tools (Docker, Kubernetes, fail2ban, ...) are never touched; the
# ruleset is never flushed. Backups written by older Segmentra versions (complete
# `nft list ruleset` / iptables-save dumps) are accepted: only Segmentra's part of
# them is restored (hosts still on the legacy full-table iptables design get their
# filter table restored). The restore logic runs on the host and is the same script
# the executor and the Ansible playbook use:
#   infra/ansible-runner/playbooks/files/segmentra-nft.sh
#   infra/ansible-runner/playbooks/files/segmentra-iptables.sh
#
# Usage:
#   ./restore-previous-policy.sh --hosts <hosts-file> --user <ssh-user> --timestamp <backup-timestamp>
#   ./restore-previous-policy.sh --hosts <hosts-file> --user <ssh-user> --latest
#
# Options:
#   --hosts       File with one IP or hostname per line
#   --user        SSH username (must have sudo access)
#   --timestamp   Backup timestamp to restore (e.g., 2026-03-18T11-46)
#   --latest      Restore the most recent backup on each host
#   --dry-run     Show what would be done without making changes
#   --key         Path to SSH private key (optional)
#   --port        SSH port (default: 22)
#
# Examples:
#   ./restore-previous-policy.sh --hosts hosts.txt --user segmentra --latest
#   ./restore-previous-policy.sh --hosts hosts.txt --user segmentra --timestamp 2026-03-18T11-46
#   ./restore-previous-policy.sh --hosts hosts.txt --user segmentra --latest --dry-run
#   ./restore-previous-policy.sh --hosts hosts.txt --user segmentra --latest --key ~/.ssh/segmentra_key

set -euo pipefail

BACKUP_DIR="/var/backups/segmentra"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FILES_DIR="${SEGMENTRA_HOST_SCRIPTS_DIR:-$SCRIPT_DIR/../infra/ansible-runner/playbooks/files}"
NFT_SH="$FILES_DIR/segmentra-nft.sh"
IPT_SH="$FILES_DIR/segmentra-iptables.sh"
HOSTS_FILE=""
SSH_USER=""
TIMESTAMP=""
USE_LATEST=false
DRY_RUN=false
SSH_KEY=""
SSH_PORT="22"

# Parse arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --hosts)     HOSTS_FILE="$2"; shift 2 ;;
    --user)      SSH_USER="$2"; shift 2 ;;
    --timestamp) TIMESTAMP="$2"; shift 2 ;;
    --latest)    USE_LATEST=true; shift ;;
    --dry-run)   DRY_RUN=true; shift ;;
    --key)       SSH_KEY="$2"; shift 2 ;;
    --port)      SSH_PORT="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,/^$/p' "$0" | sed 's/^# \?//'
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

# Validate required arguments
if [ -z "$HOSTS_FILE" ]; then
  echo "Error: --hosts is required"
  exit 1
fi
if [ -z "$SSH_USER" ]; then
  echo "Error: --user is required"
  exit 1
fi
if [ "$USE_LATEST" = false ] && [ -z "$TIMESTAMP" ]; then
  echo "Error: either --timestamp or --latest is required"
  exit 1
fi
if [ ! -f "$HOSTS_FILE" ]; then
  echo "Error: hosts file not found: $HOSTS_FILE"
  exit 1
fi
if [ ! -s "$NFT_SH" ] || [ ! -s "$IPT_SH" ]; then
  echo "Error: host restore scripts not found in $FILES_DIR (set SEGMENTRA_HOST_SCRIPTS_DIR)"
  exit 1
fi

# Build SSH options (array form; host keys are verified, new hosts are accepted once)
KNOWN_HOSTS="${SEGMENTRA_KNOWN_HOSTS:-$HOME/.ssh/known_hosts}"
mkdir -p "$(dirname "$KNOWN_HOSTS")" && chmod 700 "$(dirname "$KNOWN_HOSTS")" 2>/dev/null || true
SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$KNOWN_HOSTS"
          -o ConnectTimeout=15 -o ServerAliveInterval=15 -o ServerAliveCountMax=4
          -o BatchMode=yes -o LogLevel=ERROR -p "$SSH_PORT")
if [ -n "$SSH_KEY" ]; then
  SSH_OPTS+=(-i "$SSH_KEY")
fi

# Run a remote command; stdin is never consumed (-n) so the hosts-file loop is safe.
remote() {
  local host="$1"; shift
  ssh -n "${SSH_OPTS[@]}" "$SSH_USER@$host" "$@"
}

# Run a host script (local file $2) as root on the host: sudo sh -s -- <args...>.
# stdin is the script file, never the hosts file.
remote_script() {
  local host="$1" script="$2"; shift 2
  local args="" a sq="'" esc="'\\''"
  for a in "$@"; do args+=" '${a//$sq/$esc}'"; done
  ssh "${SSH_OPTS[@]}" "$SSH_USER@$host" "sudo -n sh -s --$args" < "$script"
}

# Counters
TOTAL=0
SUCCEEDED=0
FAILED=0
SKIPPED=0

echo "============================================"
echo "  Segmentra Policy Restore"
echo "============================================"
echo "  Hosts file:  $HOSTS_FILE"
echo "  SSH user:    $SSH_USER"
echo "  SSH port:    $SSH_PORT"
if [ "$USE_LATEST" = true ]; then
  echo "  Backup:      latest available"
else
  echo "  Backup:      $TIMESTAMP"
fi
if [ "$DRY_RUN" = true ]; then
  echo "  Mode:        DRY RUN (no changes)"
else
  echo "  Mode:        LIVE"
fi
echo "============================================"
echo ""

while IFS= read -r HOST <&3 || [ -n "$HOST" ]; do
  # Trim whitespace; skip empty lines and comments
  HOST="${HOST#"${HOST%%[![:space:]]*}"}"
  HOST="${HOST%"${HOST##*[![:space:]]}"}"
  [[ -z "$HOST" || "$HOST" =~ ^# ]] && continue

  TOTAL=$((TOTAL + 1))
  echo "--- [$TOTAL] $HOST ---"

  # The script runs everything with `sudo -n` (no password prompt); report a missing
  # NOPASSWD rule clearly instead of as "no backup found".
  RC=0
  remote "$HOST" "sudo -n true" >/dev/null 2>&1 || RC=$?
  if [ "$RC" -eq 255 ]; then
    echo "  ✗ SSH connection failed (exit $RC)"
    FAILED=$((FAILED + 1))
    echo ""
    continue
  elif [ "$RC" -ne 0 ]; then
    echo "  ✗ sudo -n failed for $SSH_USER: this script needs passwordless sudo on the host"
    FAILED=$((FAILED + 1))
    echo ""
    continue
  fi

  # Determine backup file (and with it the backend). Only deployment / removal backups
  # are considered:  nft.ruleset.<timestamp>  /  iptables.<timestamp>
  # (audit backups "*.audit-backup.*", "*.full" reference dumps and other files are excluded).
  # The backend is taken from the backup, not from the installed tools: hosts often have
  # both nft and iptables(-nft) installed. Failures are captured explicitly; set -e must
  # not abort the loop.
  if [ "$USE_LATEST" = true ]; then
    RC=0
    BACKUP_FILE=$(remote "$HOST" "sudo -n ls -1t '$BACKUP_DIR' 2>/dev/null | grep -E '^(nft\.ruleset|iptables)\.[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9][0-9A-Za-z-]*\$' | head -n 1" 2>/dev/null) || RC=$?
    if [ "$RC" -eq 255 ]; then
      echo "  ✗ SSH connection failed (exit $RC)"
      FAILED=$((FAILED + 1))
      echo ""
      continue
    fi
    if [ -z "$BACKUP_FILE" ]; then
      echo "  ✗ No backup files found in $BACKUP_DIR"
      FAILED=$((FAILED + 1))
      echo ""
      continue
    fi
    BACKUP_FILE="$BACKUP_DIR/$BACKUP_FILE"
  else
    if ! [[ "$TIMESTAMP" =~ ^[0-9A-Za-z-]+$ ]]; then
      echo "  ✗ Invalid timestamp: $TIMESTAMP"
      FAILED=$((FAILED + 1))
      echo ""
      continue
    fi
    RC=0
    FOUND=$(remote "$HOST" "for f in '$BACKUP_DIR/nft.ruleset.$TIMESTAMP' '$BACKUP_DIR/iptables.$TIMESTAMP'; do if sudo -n test -f \"\$f\"; then echo \"\$f\"; break; fi; done" 2>/dev/null) || RC=$?
    if [ "$RC" -eq 255 ]; then
      echo "  ✗ SSH connection failed (exit $RC)"
      FAILED=$((FAILED + 1))
      echo ""
      continue
    fi
    if [ -z "$FOUND" ]; then
      echo "  ✗ Backup not found: $BACKUP_DIR/{nft.ruleset,iptables}.$TIMESTAMP"
      FAILED=$((FAILED + 1))
      echo ""
      continue
    fi
    BACKUP_FILE="$FOUND"
  fi
  case "${BACKUP_FILE##*/}" in
    nft.ruleset.*) BACKEND=nft ;;
    *) BACKEND=iptables ;;
  esac
  echo "  Backend: $BACKEND"
  echo "  Backup:  $BACKUP_FILE"

  # Dry run — just show what would happen
  if [ "$DRY_RUN" = true ]; then
    echo "  [dry-run] Would restore from $BACKUP_FILE"
    SKIPPED=$((SKIPPED + 1))
    echo ""
    continue
  fi

  # Scoped restore (see the header). nft: one atomic nft -f transaction replacing only
  # table inet segmentra. iptables: SEGMENTRA-IN/OUT(/FWD) + jumps; the matching ip6tables backup
  # (ip6tables.<timestamp>) is restored too when present. Both families are attempted.
  RC=0
  if [ "$BACKEND" = "nft" ]; then
    remote_script "$HOST" "$NFT_SH" restore "$BACKUP_FILE" 2>&1 | sed 's/^/  /' || RC=$?
  else
    V6_FILE="$BACKUP_DIR/ip6tables.${BACKUP_FILE##*/iptables.}"
    remote_script "$HOST" "$IPT_SH" restore iptables "$BACKUP_FILE" 2>&1 | sed 's/^/  /' || RC=$?
    HAS_V6=$(remote "$HOST" "sudo -n test -s '$V6_FILE' && command -v ip6tables-restore >/dev/null 2>&1 && echo yes || echo no" 2>/dev/null) || HAS_V6=no
    if [ "$HAS_V6" = "yes" ]; then
      RC6=0
      remote_script "$HOST" "$IPT_SH" restore ip6tables "$V6_FILE" 2>&1 | sed 's/^/  /' || RC6=$?
      if [ "$RC" -eq 0 ]; then RC=$RC6; fi
    fi
  fi

  if [ "$RC" -eq 0 ]; then
    # Reboot persistence follows the restored state (distribution's own service; never fails the restore).
    if [ "$BACKEND" = "nft" ]; then
      remote_script "$HOST" "$NFT_SH" persist 2>&1 | sed 's/^/  /' || true
    else
      remote_script "$HOST" "$IPT_SH" persist iptables 2>&1 | sed 's/^/  /' || true
      if [ "${HAS_V6:-no}" = "yes" ]; then remote_script "$HOST" "$IPT_SH" persist ip6tables 2>&1 | sed 's/^/  /' || true; fi
    fi
    echo "  ✓ Restored successfully"
    SUCCEEDED=$((SUCCEEDED + 1))
  else
    echo "  ✗ FAILED (exit $RC) — check host manually"
    FAILED=$((FAILED + 1))
  fi
  echo ""

done 3< "$HOSTS_FILE"

echo "============================================"
echo "  Results"
echo "============================================"
echo "  Total:     $TOTAL"
echo "  Succeeded: $SUCCEEDED"
echo "  Failed:    $FAILED"
if [ "$DRY_RUN" = true ]; then
  echo "  Skipped:   $SKIPPED (dry run)"
fi
echo "============================================"

if [ $FAILED -gt 0 ]; then
  exit 1
fi
