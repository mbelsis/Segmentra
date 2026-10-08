#!/bin/bash
# restore-previous-policy.sh
#
# Restores the previous firewall ruleset on target hosts from Segmentra backups.
# Use this after a deployment expires or when you need to rollback deployed policies.
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

# Build SSH options (array form; host keys are verified, new hosts are accepted once)
KNOWN_HOSTS="${SEGMENTRA_KNOWN_HOSTS:-$HOME/.ssh/known_hosts}"
mkdir -p "$(dirname "$KNOWN_HOSTS")" && chmod 700 "$(dirname "$KNOWN_HOSTS")" 2>/dev/null || true
SSH_OPTS=(-n -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$KNOWN_HOSTS"
          -o ConnectTimeout=15 -o ServerAliveInterval=15 -o ServerAliveCountMax=4
          -o BatchMode=yes -o LogLevel=ERROR -p "$SSH_PORT")
if [ -n "$SSH_KEY" ]; then
  SSH_OPTS+=(-i "$SSH_KEY")
fi

# Run a remote command; stdin is never consumed (-n) so the hosts-file loop is safe.
remote() {
  local host="$1"; shift
  ssh "${SSH_OPTS[@]}" "$SSH_USER@$host" "$@"
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

  # Detect firewall backend (failures are captured explicitly; set -e must not abort the loop)
  RC=0
  BACKEND=$(remote "$HOST" "command -v nft > /dev/null 2>&1 && echo nft || echo iptables" 2>/dev/null) || RC=$?
  if [ "$RC" -ne 0 ] || [ -z "$BACKEND" ]; then
    echo "  ✗ SSH connection failed (exit $RC)"
    FAILED=$((FAILED + 1))
    echo ""
    continue
  fi
  echo "  Backend: $BACKEND"

  # Determine backup file. Only deployment backups are considered:
  #   nft.ruleset.<timestamp>  /  iptables.<timestamp>
  # (audit backups "*.audit-backup.*" and other files are excluded)
  if [ "$BACKEND" = "nft" ]; then
    PREFIX="nft.ruleset."
    PREFIX_RE='^nft\.ruleset\.'
  else
    PREFIX="iptables."
    PREFIX_RE='^iptables\.'
  fi
  if [ "$USE_LATEST" = true ]; then
    RC=0
    BACKUP_FILE=$(remote "$HOST" "sudo -n ls -1t '$BACKUP_DIR' 2>/dev/null | grep -E '${PREFIX_RE}[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9-]+\$' | head -n 1" 2>/dev/null) || RC=$?
    if [ "$RC" -ne 0 ] || [ -z "$BACKUP_FILE" ]; then
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
    BACKUP_FILE="$BACKUP_DIR/$PREFIX$TIMESTAMP"
    RC=0
    EXISTS=$(remote "$HOST" "sudo -n test -f '$BACKUP_FILE' && echo yes || echo no" 2>/dev/null) || RC=$?
    if [ "$EXISTS" != "yes" ]; then
      echo "  ✗ Backup not found: $BACKUP_FILE"
      FAILED=$((FAILED + 1))
      echo ""
      continue
    fi
  fi
  echo "  Backup:  $BACKUP_FILE"

  # Dry run — just show what would happen
  if [ "$DRY_RUN" = true ]; then
    echo "  [dry-run] Would restore from $BACKUP_FILE"
    SKIPPED=$((SKIPPED + 1))
    echo ""
    continue
  fi

  # Restore. nft: "flush ruleset" + backup in ONE file -> single atomic nft -f transaction.
  # iptables: iptables-restore replaces the table (incl. policies) atomically; the matching
  # ip6tables backup (ip6tables.<timestamp>) is restored too when present.
  RC=0
  if [ "$BACKEND" = "nft" ]; then
    remote "$HOST" "sudo -n sh -c 'umask 077; t=\"$BACKUP_FILE.restore\"; { echo \"flush ruleset\"; cat \"$BACKUP_FILE\"; } > \"\$t\" && nft -f \"\$t\"; rc=\$?; rm -f \"\$t\"; exit \$rc'" 2>&1 || RC=$?
  else
    V6_FILE="$BACKUP_DIR/ip6tables.${BACKUP_FILE##*/iptables.}"
    remote "$HOST" "sudo -n sh -c 'iptables-restore < \"$BACKUP_FILE\" && { [ ! -s \"$V6_FILE\" ] || ! command -v ip6tables-restore >/dev/null 2>&1 || ip6tables-restore < \"$V6_FILE\"; }'" 2>&1 || RC=$?
  fi

  if [ "$RC" -eq 0 ]; then
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
