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

# Build SSH options
SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=30 -p $SSH_PORT"
if [ -n "$SSH_KEY" ]; then
  SSH_OPTS="$SSH_OPTS -i $SSH_KEY"
fi

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

while IFS= read -r HOST || [ -n "$HOST" ]; do
  # Skip empty lines and comments
  [[ -z "$HOST" || "$HOST" =~ ^# ]] && continue

  TOTAL=$((TOTAL + 1))
  echo "--- [$TOTAL] $HOST ---"

  # Detect firewall backend
  BACKEND=$(ssh $SSH_OPTS "$SSH_USER@$HOST" "command -v nft > /dev/null 2>&1 && echo nft || echo iptables" 2>/dev/null) || {
    echo "  ✗ SSH connection failed"
    FAILED=$((FAILED + 1))
    echo ""
    continue
  }
  echo "  Backend: $BACKEND"

  # Determine backup file
  if [ "$USE_LATEST" = true ]; then
    if [ "$BACKEND" = "nft" ]; then
      BACKUP_FILE=$(ssh $SSH_OPTS "$SSH_USER@$HOST" "ls -1t $BACKUP_DIR/nft.ruleset.* 2>/dev/null | head -n 1" 2>/dev/null)
    else
      BACKUP_FILE=$(ssh $SSH_OPTS "$SSH_USER@$HOST" "ls -1t $BACKUP_DIR/iptables.* 2>/dev/null | head -n 1" 2>/dev/null)
    fi

    if [ -z "$BACKUP_FILE" ]; then
      echo "  ✗ No backup files found in $BACKUP_DIR"
      FAILED=$((FAILED + 1))
      echo ""
      continue
    fi
    echo "  Backup:  $BACKUP_FILE"
  else
    if [ "$BACKEND" = "nft" ]; then
      BACKUP_FILE="$BACKUP_DIR/nft.ruleset.$TIMESTAMP"
    else
      BACKUP_FILE="$BACKUP_DIR/iptables.$TIMESTAMP"
    fi

    # Verify backup exists
    EXISTS=$(ssh $SSH_OPTS "$SSH_USER@$HOST" "[ -f '$BACKUP_FILE' ] && echo yes || echo no" 2>/dev/null)
    if [ "$EXISTS" != "yes" ]; then
      echo "  ✗ Backup not found: $BACKUP_FILE"
      FAILED=$((FAILED + 1))
      echo ""
      continue
    fi
    echo "  Backup:  $BACKUP_FILE"
  fi

  # Dry run — just show what would happen
  if [ "$DRY_RUN" = true ]; then
    echo "  [dry-run] Would restore from $BACKUP_FILE"
    SKIPPED=$((SKIPPED + 1))
    echo ""
    continue
  fi

  # Restore
  if [ "$BACKEND" = "nft" ]; then
    ssh $SSH_OPTS "$SSH_USER@$HOST" "sudo nft flush ruleset && sudo nft -f '$BACKUP_FILE'" 2>&1
  else
    ssh $SSH_OPTS "$SSH_USER@$HOST" "sudo iptables-restore < '$BACKUP_FILE'" 2>&1
  fi

  if [ $? -eq 0 ]; then
    echo "  ✓ Restored successfully"
    SUCCEEDED=$((SUCCEEDED + 1))
  else
    echo "  ✗ FAILED — check host manually"
    FAILED=$((FAILED + 1))
  fi
  echo ""

done < "$HOSTS_FILE"

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
