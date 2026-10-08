/**
 * Host-side shell logic for scoped nftables backups and restores.
 *
 * Segmentra owns exactly one nftables object: `table inet segmentra`. Backups and
 * restores are limited to that table. A full `nft list ruleset` can NOT be replayed
 * with `nft -f` on hosts where other tools use iptables-nft (Docker, Kubernetes,
 * fail2ban...): their rules are printed as xtables-compat expressions
 * (`xt target "DNAT"`) that nft refuses to load ("unsupported xtables compat
 * expression"), so a full-ruleset restore always fails there — and would clobber
 * other tools' tables even where it works.
 *
 * The same script is shipped to Ansible as
 * infra/ansible-runner/playbooks/files/segmentra-nft.sh — keep the two
 * byte-identical. After changing SEGMENTRA_NFT_SH, rebuild the executor and run:
 *   node -e "import('./packages/executor/dist/nft-scripts.js').then(m=>require('fs').writeFileSync('infra/ansible-runner/playbooks/files/segmentra-nft.sh', m.SEGMENTRA_NFT_SH))"
 */
import { shq } from './ssh-options.js';
import { PERSIST_COMMON_SH } from './persist-scripts.js';

/** First line of a scoped nft backup; `${NFT_BACKUP_V2_HEADER}: absent` = the table did not exist. */
export const NFT_BACKUP_V2_HEADER = '# segmentra-backup v2 nft';

/**
 * POSIX sh script. Usage:
 *   sh -c "$SCRIPT" segmentra-nft backup  <backup-file>
 *   sh -c "$SCRIPT" segmentra-nft restore <backup-file>
 *
 * backup:  writes `table inet segmentra` (`nft list table`) behind a "# segmentra-backup v2 nft"
 *          header, or only the header "# segmentra-backup v2 nft: absent" when the table does
 *          not exist. `nft list ruleset` is additionally saved as <backup-file>.full for manual
 *          disaster recovery only (it is never replayed).
 * restore: ONE atomic `nft -f` transaction: `add table inet segmentra` + `delete table inet
 *          segmentra` + the backed-up table block (if any). Other tables are never touched and
 *          `flush ruleset` is never used. Pre-v2 backups (a complete `nft list ruleset` dump)
 *          are accepted: only their `table inet segmentra { ... }` block is used (brace
 *          matching), and if they contain none the table is just deleted.
 *          Exit codes: 3 = backup missing, 4 = restore failed (nothing changed), 6 = no nft.
 *   sh -c "$SCRIPT" segmentra-nft persist | unpersist | check
 * persist:   reboot persistence with the distribution's own nftables.service (see
 *            persist-scripts.ts): the LIVE table inet segmentra (`nft -s list table`) is written to
 *            /etc/nftables.d/segmentra.nft (Debian/Ubuntu) or /etc/nftables/segmentra.nft (RHEL
 *            family) behind `add table` + `delete table` (safe to load at boot and repeatedly), the
 *            distro config (/etc/nftables.conf, /etc/sysconfig/nftables.conf) gets exactly one
 *            include line, and nftables.service is enabled (never started) unless firewalld is
 *            active/enabled. No live table -> same as unpersist. A live log-only (learning/test)
 *            policy is never persisted (the boot file keeps the last enforced policy).
 * unpersist: removes the include line and the file (nftables.service is left as it is).
 * check:     reports what persist would do / whether the boot file matches the live table,
 *            without changing anything. Always exits 0 unless the table cannot be read (4).
 */
export const SEGMENTRA_NFT_SH = `#!/bin/sh
# Managed by Segmentra. See packages/executor/src/nft-scripts.ts
set -u
PATH="$PATH:/usr/sbin:/sbin"; export PATH
mode=\${1:-}
bfile=\${2:-}
case "$mode" in
  backup|restore) if [ -z "$bfile" ]; then echo "segmentra-nft: $mode needs a backup file argument" >&2; exit 2; fi ;;
  persist|unpersist|check) ;;
  *) echo "segmentra-nft: invalid mode '$mode'" >&2; exit 2 ;;
esac
if ! command -v nft >/dev/null 2>&1; then echo "segmentra-nft: nft not found" >&2; exit 6; fi
HDR='${NFT_BACKUP_V2_HEADER}'
info() { echo "[segmentra:nft] $*"; }
tmpd=$(mktemp -d 2>/dev/null) || { echo "segmentra-nft: mktemp failed" >&2; exit 1; }
trap 'rm -rf "$tmpd"' EXIT

# Print the top-level "table inet segmentra { ... }" block of an nft listing. Braces are
# counted (ignoring braces inside double-quoted strings) so nested blocks are handled.
# Exit status 3 if the block starts but never closes (truncated file).
extract_table() {
  awk '
    !inb && index($0, "table inet segmentra {") == 1 { inb = 1; depth = 0 }
    inb {
      print
      n = length($0); q = 0
      for (i = 1; i <= n; i++) {
        ch = substr($0, i, 1)
        if (ch == "\\"") q = !q
        else if (!q && ch == "{") depth++
        else if (!q && ch == "}") { depth--; if (depth == 0) { done = 1; exit } }
      }
    }
    END { if (inb && !done) exit 3 }
  ' "$1"
}

backup_table() {
  umask 077
  if ! nft list tables > "$tmpd/tables" 2>"$tmpd/err"; then
    echo "segmentra-nft: nft list tables failed: $(tr '\\n' ' ' < "$tmpd/err")" >&2; exit 4
  fi
  if grep -qx 'table inet segmentra' "$tmpd/tables"; then
    if ! nft list table inet segmentra > "$tmpd/table" 2>"$tmpd/err"; then
      echo "segmentra-nft: nft list table inet segmentra failed: $(tr '\\n' ' ' < "$tmpd/err")" >&2; exit 4
    fi
    if ! extract_table "$tmpd/table" > "$tmpd/block" || [ ! -s "$tmpd/block" ]; then
      echo "segmentra-nft: could not parse the output of nft list table inet segmentra" >&2; exit 4
    fi
    { echo "$HDR"; echo "# Only table inet segmentra; other tables are never backed up or restored."; cat "$tmpd/block"; } > "$tmpd/out" || exit 4
    state=present
  else
    { echo "$HDR: absent"; echo "# table inet segmentra did not exist; restoring this backup deletes it."; } > "$tmpd/out" || exit 4
    state=absent
  fi
  cp "$tmpd/out" "$bfile.tmp" && mv -f "$bfile.tmp" "$bfile" || { echo "segmentra-nft: could not write $bfile" >&2; exit 4; }
  # Reference copy for manual disaster recovery only (may not be loadable with nft -f).
  if nft list ruleset > "$bfile.full.tmp" 2>/dev/null; then mv -f "$bfile.full.tmp" "$bfile.full"; else rm -f "$bfile.full.tmp"; fi
  info "backup written: $bfile (table inet segmentra $state)"
}

restore_table() {
  if [ ! -f "$bfile" ]; then echo "segmentra-nft: backup missing: $bfile" >&2; exit 3; fi
  first=$(head -n 1 "$bfile")
  case "$first" in
    "$HDR: absent") : > "$tmpd/block"; fmt=v2 ;;
    "$HDR")
      if ! extract_table "$bfile" > "$tmpd/block" || [ ! -s "$tmpd/block" ]; then
        echo "segmentra-nft: backup $bfile is corrupt (no complete table inet segmentra block)" >&2; exit 4
      fi
      fmt=v2 ;;
    "# segmentra-backup "*) echo "segmentra-nft: $bfile is not a backup format this version understands ($first)" >&2; exit 4 ;;
    *)
      # Pre-v2 backup (complete nft list ruleset dump): use only our table from it.
      if ! extract_table "$bfile" > "$tmpd/block"; then
        echo "segmentra-nft: table inet segmentra block in $bfile is incomplete" >&2; exit 4
      fi
      fmt=full-ruleset ;;
  esac
  { echo 'add table inet segmentra'; echo 'delete table inet segmentra'; cat "$tmpd/block"; } > "$tmpd/restore.nft" || exit 4
  if ! nft -f "$tmpd/restore.nft"; then echo "segmentra-nft: nft -f failed; nothing was changed" >&2; exit 4; fi
  if [ -s "$tmpd/block" ]; then
    info "restored table inet segmentra from $bfile ($fmt backup); other tables untouched"
  else
    info "table inet segmentra did not exist at backup time ($bfile, $fmt backup); removed it; other tables untouched"
  fi
}

${PERSIST_COMMON_SH}
nft_paths() {
  case "$P_DISTRO" in
    debian) NCONF=/etc/nftables.conf; NFILE=/etc/nftables.d/segmentra.nft ;;
    rhel) NCONF=/etc/sysconfig/nftables.conf; NFILE=/etc/nftables/segmentra.nft ;;
    *) NCONF=; NFILE= ;;
  esac
  NINC="include \\"$NFILE\\""
}

# Boot-time file for the live table -> $tmpd/persist.nft.
# Returns 1 = no live table, 2 = live table is a log-only (learning/test) policy, 3 = read error.
nft_render() {
  nft list tables > "$tmpd/ptables" 2>/dev/null || return 3
  grep -qx 'table inet segmentra' "$tmpd/ptables" || return 1
  nft -s list table inet segmentra > "$tmpd/plist" 2>/dev/null || return 3
  if ! extract_table "$tmpd/plist" > "$tmpd/pblock" || [ ! -s "$tmpd/pblock" ]; then return 3; fi
  if grep -q 'FW-AUDIT: ALLOW: catch-all' "$tmpd/pblock"; then return 2; fi
  {
    echo '#!/usr/sbin/nft -f'
    echo "# Managed by Segmentra: table inet segmentra, loaded at boot by nftables.service through"
    echo "# the include line in $NCONF. Rewritten on every deployment; do not edit."
    echo 'add table inet segmentra'
    echo 'delete table inet segmentra'
    cat "$tmpd/pblock"
  } > "$tmpd/persist.nft"
}

nft_unpersist() {
  if ! drop_include "$NCONF" "$NINC" || ! rm -f "$NFILE"; then
    pwarn write_failed "could not remove the include line from $NCONF or $NFILE"; presult not_persisted none error; exit 4
  fi
  info "reboot persistence removed ($NFILE, include line in $NCONF)"
  presult removed none none
}

nft_persist() {
  pm=$1
  P_FAMILY=nft
  detect_distro
  nft_paths
  if [ -z "$NFILE" ]; then
    pwarn unsupported_distro "reboot persistence is supported on Debian, Ubuntu and RHEL-family hosts only; table inet segmentra will not survive a reboot"
    presult not_persisted none unsupported; return 0
  fi
  if [ "$pm" = unpersist ]; then nft_unpersist; return 0; fi
  nft_render; rr=$?
  case "$rr" in
    3) pwarn read_failed "could not read table inet segmentra"; presult not_persisted none error; exit 4 ;;
    1)
      if [ "$pm" = persist ]; then nft_unpersist; return 0; fi
      if [ -f "$NFILE" ] || grep -qxF -- "$NINC" "$NCONF" 2>/dev/null; then state=differs; else state=none; fi ;;
    2)
      pnote log_only_active "a log-only Firewall Learning / policy test policy is active; it is not persisted, the boot configuration keeps the last enforced policy"
      if [ -f "$NFILE" ] && grep -qxF -- "$NINC" "$NCONF" 2>/dev/null; then state=learning; else state=missing; fi ;;
    *)
      if [ "$pm" = persist ]; then
        if ! replace_file "$NFILE" "$tmpd/persist.nft" 600 || ! ensure_include "$NCONF" "$NINC"; then
          pwarn write_failed "could not write $NFILE or the include line in $NCONF"; presult not_persisted none error; exit 4
        fi
        info "table inet segmentra saved to $NFILE (included from $NCONF)"
      fi
      if same_file "$NFILE" "$tmpd/persist.nft" && grep -qxF -- "$NINC" "$NCONF" 2>/dev/null; then state=in_sync
      elif [ -f "$NFILE" ]; then state=differs; else state=missing; fi ;;
  esac
  if grep -q '^[[:space:]]*flush[[:space:]][[:space:]]*ruleset' "$NCONF" 2>/dev/null; then
    pnote conf_flush_ruleset "$NCONF contains flush ruleset: harmless at boot (it runs before Docker / Kubernetes start), but never run systemctl restart/reload nftables on a running host, it would remove their rules"
  fi
  st=not_persisted; meth=none
  if ! have_systemctl || ! unit_exists nftables.service; then
    pwarn no_nftables_service "nftables.service (systemd) is not available on this host; table inet segmentra will not survive a reboot"
  elif firewalld_on; then
    pwarn firewalld_active "firewalld is active or enabled and conflicts with nftables.service, which Segmentra therefore does not enable: table inet segmentra will not survive a reboot while firewalld manages the firewall (to persist it, disable firewalld and enable nftables.service; translating the policy into firewalld is not supported)"
  elif [ "$pm" = persist ] && ! enable_unit nftables.service; then
    :
  elif unit_enabled nftables.service; then
    st=persisted; meth=nftables.service
  else
    meth=nftables.service
    pwarn service_disabled "nftables.service is not enabled; Segmentra enables it on the next deployment"
    st=not_persisted
  fi
  if [ "$st" = persisted ]; then
    case "$state" in in_sync|learning) ;; *) st=not_persisted ;; esac
  fi
  if [ "$state" = none ]; then st=removed; fi
  presult "$st" "$meth" "$state"
}

case "$mode" in
  backup) backup_table ;;
  restore) restore_table ;;
  persist|unpersist|check) nft_persist "$mode" ;;
esac
exit 0
`;

/** `sh -c '<SEGMENTRA_NFT_SH>' segmentra-nft <args...>` (args are shell-quoted). */
export function segmentraNftCommand(args: string[]): string {
  return `sh -c ${shq(SEGMENTRA_NFT_SH)} segmentra-nft ${args.map((a) => shq(a)).join(' ')}`;
}
