#!/bin/sh
# Managed by Segmentra. See packages/executor/src/nft-scripts.ts
set -u
PATH="$PATH:/usr/sbin:/sbin"; export PATH
mode=${1:-}
bfile=${2:-}
case "$mode" in
  backup|restore) if [ -z "$bfile" ]; then echo "segmentra-nft: $mode needs a backup file argument" >&2; exit 2; fi ;;
  persist|unpersist|check) ;;
  *) echo "segmentra-nft: invalid mode '$mode'" >&2; exit 2 ;;
esac
if ! command -v nft >/dev/null 2>&1; then echo "segmentra-nft: nft not found" >&2; exit 6; fi
HDR='# segmentra-backup v2 nft'
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
        if (ch == "\"") q = !q
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
    echo "segmentra-nft: nft list tables failed: $(tr '\n' ' ' < "$tmpd/err")" >&2; exit 4
  fi
  if grep -qx 'table inet segmentra' "$tmpd/tables"; then
    if ! nft list table inet segmentra > "$tmpd/table" 2>"$tmpd/err"; then
      echo "segmentra-nft: nft list table inet segmentra failed: $(tr '\n' ' ' < "$tmpd/err")" >&2; exit 4
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

# ---- reboot persistence with the distribution's own service (nothing of Segmentra runs at boot) ----
PMARK='# managed by Segmentra (reboot persistence) - do not edit this line or the next'
PBK=/var/backups/segmentra/persist
P_DISTRO=unsupported
P_FAMILY=
pwarn() { echo "SEGMENTRA_PERSIST_WARN $1 $2"; }
pnote() { echo "SEGMENTRA_PERSIST_NOTE $1 $2"; }
presult() { echo "SEGMENTRA_PERSIST status=$1 method=$2 distro=$P_DISTRO family=$P_FAMILY state=$3"; }

detect_distro() {
  P_DISTRO=unsupported
  [ -r /etc/os-release ] || return 0
  ids=" $(sed -n -e 's/^ID=//p' -e 's/^ID_LIKE=//p' /etc/os-release | tr -d '"' | tr -d "'" | tr '\n' ' ') "
  case "$ids" in
    *" debian "*|*" ubuntu "*) P_DISTRO=debian ;;
    *" rhel "*|*" centos "*|*" rocky "*|*" almalinux "*|*" fedora "*) P_DISTRO=rhel ;;
  esac
}

have_systemctl() { command -v systemctl >/dev/null 2>&1; }
unit_exists() {
  for d in /etc/systemd/system /run/systemd/system /usr/lib/systemd/system /lib/systemd/system; do
    if [ -f "$d/$1" ]; then return 0; fi
  done
  return 1
}
unit_enabled() { have_systemctl && [ "$(systemctl is-enabled "$1" 2>/dev/null)" = enabled ]; }
firewalld_on() {
  have_systemctl || return 1
  if systemctl is-active --quiet firewalld.service 2>/dev/null; then return 0; fi
  unit_enabled firewalld.service
}
# Enable (never start or restart) a unit: starting it now would reload the whole saved
# configuration, which may flush the rules of Docker, Kubernetes, fail2ban, ...
enable_unit() {
  if unit_enabled "$1"; then return 0; fi
  systemctl enable "$1" >/dev/null 2>"$tmpd/enerr" || { pwarn enable_failed "systemctl enable $1 failed: $(tr '\n' ' ' < "$tmpd/enerr")"; return 1; }
  unit_enabled "$1"
}

same_file() { [ -f "$1" ] && [ -f "$2" ] && [ "$(cksum < "$1")" = "$(cksum < "$2")" ]; }

# replace_file <dest> <new-content> <mode-if-new>: atomic replace when the content differs.
# An existing file keeps its owner/mode; its previous content is kept in $PBK.
replace_file() {
  if same_file "$1" "$2"; then return 0; fi
  if [ -f "$1" ]; then
    mkdir -p "$PBK" 2>/dev/null && chmod 700 "$PBK" 2>/dev/null
    cp -p "$1" "$PBK/$(echo "$1" | tr / _).prev" 2>/dev/null
    cp -p "$1" "$1.segmentra-tmp" || return 1
  else
    mkdir -p "$(dirname "$1")" || return 1
    : > "$1.segmentra-tmp" || return 1
    chmod "$3" "$1.segmentra-tmp"
  fi
  if ! cat "$2" > "$1.segmentra-tmp" || ! mv -f "$1.segmentra-tmp" "$1"; then rm -f "$1.segmentra-tmp"; return 1; fi
  if command -v restorecon >/dev/null 2>&1; then restorecon "$1" >/dev/null 2>&1; fi
  return 0
}

# ensure_include <conf> <line>: <conf> contains <line> exactly once, preceded by PMARK, appended
# at the end; every other line is left as it is. A missing <conf> is created WITHOUT flush ruleset.
ensure_include() {
  if [ -f "$1" ]; then
    if [ "$(grep -cxF -- "$2" "$1")" = 1 ] && [ "$(grep -cxF -- "$PMARK" "$1")" = 1 ]; then return 0; fi
    awk -v l="$2" -v m="$PMARK" '$0 != l && $0 != m' "$1" > "$tmpd/pconf" || return 1
    printf '%s\n%s\n' "$PMARK" "$2" >> "$tmpd/pconf"
  else
    printf '#!/usr/sbin/nft -f\n%s\n%s\n' "$PMARK" "$2" > "$tmpd/pconf"
  fi
  replace_file "$1" "$tmpd/pconf" 755
}

# drop_include <conf> <line>: remove <line> and PMARK from <conf> (other lines untouched).
drop_include() {
  [ -f "$1" ] || return 0
  if ! grep -qxF -- "$2" "$1" && ! grep -qxF -- "$PMARK" "$1"; then return 0; fi
  awk -v l="$2" -v m="$PMARK" '$0 != l && $0 != m' "$1" > "$tmpd/pconf" || return 1
  replace_file "$1" "$tmpd/pconf" 755
}

nft_paths() {
  case "$P_DISTRO" in
    debian) NCONF=/etc/nftables.conf; NFILE=/etc/nftables.d/segmentra.nft ;;
    rhel) NCONF=/etc/sysconfig/nftables.conf; NFILE=/etc/nftables/segmentra.nft ;;
    *) NCONF=; NFILE= ;;
  esac
  NINC="include \"$NFILE\""
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
