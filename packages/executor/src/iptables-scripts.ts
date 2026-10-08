/**
 * Host-side shell logic for the chain-scoped iptables/ip6tables design.
 *
 * Segmentra owns only the SEGMENTRA-IN / SEGMENTRA-OUT chains of the filter
 * table plus one jump to each from INPUT / OUTPUT — and, on hosts that filter
 * forwarded traffic (gateways with FORWARD rules / protected devices), the
 * SEGMENTRA-FWD chain plus one jump from FORWARD. Everything else (DOCKER*,
 * KUBE-*, f2b-*, built-in chain policies) is left alone.
 *
 * The same script is shipped to Ansible as
 * infra/ansible-runner/playbooks/files/segmentra-iptables.sh — keep the two
 * byte-identical. After changing SEGMENTRA_IPTABLES_SH, rebuild the executor and run:
 *   node -e "import('./packages/executor/dist/iptables-scripts.js').then(m=>require('fs').writeFileSync('infra/ansible-runner/playbooks/files/segmentra-iptables.sh', m.SEGMENTRA_IPTABLES_SH))"
 */
import { shq } from './ssh-options.js';
import { PERSIST_COMMON_SH } from './persist-scripts.js';

/** Root-owned copies of the last pre-chain-design ("legacy") policy files, used to identify legacy rules. */
export const LEGACY_POLICY_FILE = '/etc/segmentra.legacy.policy';
export const LEGACY_POLICY_FILE6 = '/etc/segmentra.legacy.policy6';

/**
 * POSIX sh script. Usage:
 *   sh -c "$SCRIPT" segmentra-iptables apply       <iptables|ip6tables> <policy-file> [legacy-policy-file]
 *   sh -c "$SCRIPT" segmentra-iptables apply-audit <iptables|ip6tables> <policy-file>
 *   sh -c "$SCRIPT" segmentra-iptables remove      <iptables|ip6tables> [legacy-policy-file]
 *   sh -c "$SCRIPT" segmentra-iptables backup      <iptables|ip6tables> <backup-file>
 *   sh -c "$SCRIPT" segmentra-iptables restore     <iptables|ip6tables> <backup-file>
 *   sh -c "$SCRIPT" segmentra-iptables persist|unpersist|check <iptables|ip6tables>
 *
 * apply:       one `iptables-restore --noflush` transaction fills SEGMENTRA-IN/OUT
 *              and inserts the INPUT/OUTPUT jumps at position 1 if missing; when the
 *              fragment declares SEGMENTRA-FWD it is filled in the same transaction and
 *              the FORWARD jump inserted at position 1; otherwise an existing FORWARD jump
 *              and SEGMENTRA-FWD chain are removed (forwarding no longer filtered).
 *              Duplicate jumps are removed; then legacy Segmentra rules are cleaned up.
 * apply-audit: as apply, without legacy cleanup (log-only audit; restored from backup).
 * remove:      deletes the jumps, flushes + deletes the chains (incl. SEGMENTRA-FWD), cleans
 *              up legacy rules.
 * backup:      writes a "segmentra-backup v2" file holding ONLY Segmentra's state (the
 *              SEGMENTRA-IN/OUT/FWD chains of the filter table, whether the INPUT/OUTPUT/
 *              FORWARD jumps existed, and whether the host was still on the legacy full-table design),
 *              plus the complete `<family>-save` output as <backup-file>.full (used only
 *              for legacy hosts and for manual disaster recovery).
 * restore:     scoped restore of a backup: SEGMENTRA-IN/OUT/FWD get their backed-up content
 *              (or are deleted if they did not exist), the jumps are re-created/removed
 *              to match. Chains and tables of other tools are never touched. Also accepts
 *              pre-v2 backups (a complete `<family>-save` dump): the SEGMENTRA chains are
 *              extracted from it. Legacy hosts (rules directly in INPUT/OUTPUT) are restored
 *              by replacing the complete filter table — see restore_backup below.
 *              Exit codes: 3 = backup missing, 4 = restore failed, 5 = chain removal failed.
 *
 * persist:     reboot persistence with the distribution's own service (see persist-scripts.ts):
 *              the LIVE SEGMENTRA-IN/OUT/FWD chains and INPUT/OUTPUT/FORWARD jumps are merged
 *              into the distro's saved rules file — /etc/iptables/rules.v4|rules.v6
 *              (iptables-persistent, Debian/Ubuntu) or /etc/sysconfig/iptables|ip6tables
 *              (iptables-services, RHEL family). Only Segmentra's lines of the *filter section
 *              are replaced (declarations, -A SEGMENTRA-* rules, the jumps, which go first in
 *              their chains); every other line stays byte-identical. A missing file is created
 *              with only *filter, ACCEPT policies and Segmentra's lines (only if the package is
 *              installed). netfilter-persistent / iptables(+ip6tables).service is enabled, never
 *              started; nothing is enabled while firewalld is active/enabled. Packages are never
 *              installed. No live Segmentra state -> Segmentra's lines are removed. A live
 *              log-only (learning/test) policy is never persisted.
 * unpersist:   removes Segmentra's lines from the saved rules file.
 * check:       reports what persist would do without changing anything.
 *
 * Legacy cleanup (hosts deployed by the old full-table design, i.e. no jump existed
 * before this run): rules directly in INPUT/OUTPUT are deleted only when positively
 * identified as Segmentra's — a "segmentra"/"mgmt_ssh" comment, an "FW-AUDIT:" LOG
 * prefix, or an exact (canonicalised) match with a rule of the legacy policy file.
 * Built-in policies are reset to ACCEPT only when the legacy file set them to DROP.
 * Unidentified rules are left in place and reported as warnings on stdout.
 */
export const SEGMENTRA_IPTABLES_SH = `#!/bin/sh
# Managed by Segmentra. See packages/executor/src/iptables-scripts.ts
set -u
PATH="$PATH:/usr/sbin:/sbin"; export PATH
mode=\${1:-}
ipt=\${2:-}
case "$ipt" in iptables|ip6tables) ;; *) echo "segmentra-iptables: invalid family '$ipt'" >&2; exit 2 ;; esac
bfile=
case "$mode" in
  apply|apply-audit) pol=\${3:-}; legacy=\${4:-} ;;
  remove) pol=; legacy=\${3:-} ;;
  backup|restore) pol=; legacy=; bfile=\${3:-}
    if [ -z "$bfile" ]; then echo "segmentra-iptables: $mode needs a backup file argument" >&2; exit 2; fi ;;
  persist|unpersist|check) pol=; legacy= ;;
  *) echo "segmentra-iptables: invalid mode '$mode'" >&2; exit 2 ;;
esac
save="$ipt-save"
restore="$ipt-restore"
IN=SEGMENTRA-IN
OUT=SEGMENTRA-OUT
FWD=SEGMENTRA-FWD
LIN=SEGMENTRA-LEGACY-IN
LOUT=SEGMENTRA-LEGACY-OUT
info() { echo "[segmentra:$ipt] $*"; }
warn() { echo "[segmentra:$ipt] warning: $*"; }
tmpd=$(mktemp -d 2>/dev/null) || { echo "segmentra-iptables: mktemp failed" >&2; exit 1; }
trap 'rm -rf "$tmpd"' EXIT
had_jump=0
if $ipt -C INPUT -j $IN 2>/dev/null; then had_jump=1; fi

dedupe_jumps() {
  for pair in INPUT:$IN OUTPUT:$OUT FORWARD:$FWD; do
    ch=\${pair%%:*}; tg=\${pair#*:}
    # -S prints the policy first, so rule number = line number - 1. Keep the first
    # (top-most) jump, delete the others bottom-up.
    nums=$($ipt -S $ch | grep -nxF -- "-A $ch -j $tg" | cut -d: -f1 | tail -n +2 | sort -rn)
    for n in $nums; do $ipt -D $ch $((n - 1)) || return 1; info "removed duplicate $ch -> $tg jump"; done
  done
  return 0
}

# drop_fwd: delete the FORWARD jump(s) and the SEGMENTRA-FWD chain if present (forwarding is
# then no longer filtered by Segmentra).
drop_fwd() {
  while $ipt -C FORWARD -j $FWD 2>/dev/null; do $ipt -D FORWARD -j $FWD || return 1; done
  if $ipt -S $FWD >/dev/null 2>&1; then
    $ipt -F $FWD || return 1
    $ipt -X $FWD || { echo "segmentra-iptables: could not delete chain $FWD (still referenced?)" >&2; return 1; }
    info "removed chain $FWD"
  fi
  return 0
}

apply_chains() {
  if [ ! -s "$pol" ]; then echo "segmentra-iptables: policy file '$pol' missing or empty" >&2; exit 3; fi
  if ! grep -q "^:$IN " "$pol" || grep -Eq '^:(INPUT|OUTPUT|FORWARD) ' "$pol"; then
    echo "segmentra-iptables: '$pol' is not a Segmentra chain fragment; refusing to apply" >&2; exit 3
  fi
  want_fwd=0
  if grep -q "^:$FWD " "$pol"; then want_fwd=1; fi
  {
    sed '/^COMMIT[[:space:]]*$/d' "$pol"
    if ! $ipt -C INPUT -j $IN 2>/dev/null; then echo "-I INPUT 1 -j $IN"; fi
    if ! $ipt -C OUTPUT -j $OUT 2>/dev/null; then echo "-I OUTPUT 1 -j $OUT"; fi
    if [ "$want_fwd" = 1 ] && ! $ipt -C FORWARD -j $FWD 2>/dev/null; then echo "-I FORWARD 1 -j $FWD"; fi
    echo COMMIT
  } > "$tmpd/apply"
  # Chains are filled and the jumps inserted in ONE atomic transaction.
  if ! $restore --noflush < "$tmpd/apply"; then echo "segmentra-iptables: $restore failed" >&2; exit 4; fi
  if [ "$want_fwd" = 0 ]; then
    drop_fwd || { echo "segmentra-iptables: could not remove $FWD" >&2; exit 4; }
  fi
  dedupe_jumps || { echo "segmentra-iptables: could not remove duplicate jumps" >&2; exit 4; }
  if [ "$want_fwd" = 1 ]; then
    info "applied $IN/$OUT/$FWD; INPUT/OUTPUT/FORWARD jumps present"
  else
    info "applied $IN/$OUT; INPUT/OUTPUT jumps present"
  fi
}

remove_chains() {
  for pair in INPUT:$IN OUTPUT:$OUT FORWARD:$FWD; do
    ch=\${pair%%:*}; tg=\${pair#*:}
    while $ipt -C $ch -j $tg 2>/dev/null; do $ipt -D $ch -j $tg || exit 5; done
  done
  for c in $IN $OUT $FWD; do
    if $ipt -S $c >/dev/null 2>&1; then
      $ipt -F $c || exit 5
      $ipt -X $c || { echo "segmentra-iptables: could not delete chain $c (still referenced?)" >&2; exit 5; }
      info "removed chain $c"
    fi
  done
}

legacy_cleanup() {
  use_file=0
  if [ "$had_jump" = 0 ] && [ -n "$legacy" ] && [ -s "$legacy" ] && grep -Eq '^-A (INPUT|OUTPUT) ' "$legacy"; then
    # Load the legacy rules into scratch chains so iptables-save prints them in
    # canonical form, comparable with the live INPUT/OUTPUT rules.
    $ipt -F $LIN 2>/dev/null; $ipt -X $LIN 2>/dev/null; $ipt -F $LOUT 2>/dev/null; $ipt -X $LOUT 2>/dev/null
    {
      echo '*filter'; echo ":$LIN - [0:0]"; echo ":$LOUT - [0:0]"
      sed -n -e "s/^-A INPUT /-A $LIN /p" -e "s/^-A OUTPUT /-A $LOUT /p" "$legacy"
      echo COMMIT
    } > "$tmpd/scratch"
    if $restore --noflush < "$tmpd/scratch" 2>"$tmpd/err"; then
      use_file=1
    else
      warn "could not parse legacy policy file $legacy ($(tr '\\n' ' ' < "$tmpd/err")); only marker-identified legacy rules are removed"
    fi
  fi
  if ! $save -t filter > "$tmpd/save" 2>"$tmpd/err"; then
    warn "$save failed; legacy cleanup skipped"; return 0
  fi
  awk -v usefile="$use_file" -v lin="$LIN" -v lout="$LOUT" -v del="$tmpd/del" -v keep="$tmpd/keep" '
    index($0, "-A " lin " ") == 1 { li[substr($0, length(lin) + 5)]++; next }
    index($0, "-A " lout " ") == 1 { lo[substr($0, length(lout) + 5)]++; next }
    /^-A (INPUT|OUTPUT) / { n++; ch[n] = $2; rest[n] = substr($0, length($2) + 5) }
    END {
      for (i = 1; i <= n; i++) {
        r = rest[i]; c = ch[i]
        if (r == "-j SEGMENTRA-IN" || r == "-j SEGMENTRA-OUT" || r == "-j SEGMENTRA-FWD") continue
        ours = (r ~ /--comment "?(segmentra|mgmt_ssh)/) || (r ~ /--log-prefix "FW-AUDIT:/)
        if (!ours && usefile == 1) {
          if (c == "INPUT" && li[r] > 0) { li[r]--; ours = 1 }
          else if (c == "OUTPUT" && lo[r] > 0) { lo[r]--; ours = 1 }
        }
        if (ours) print "-D " c " " r > del; else print "-A " c " " r > keep
      }
    }' "$tmpd/save"
  if [ "$use_file" = 1 ]; then
    $ipt -F $LIN 2>/dev/null; $ipt -X $LIN 2>/dev/null; $ipt -F $LOUT 2>/dev/null; $ipt -X $LOUT 2>/dev/null
  fi
  # Built-in policies: reset to ACCEPT only when the legacy Segmentra file set them to DROP.
  # Done BEFORE deleting legacy rules so access never depends on a half-removed legacy
  # ruleset (apply: SEGMENTRA-IN already decides first; remove: the intent is no filtering).
  if [ "$had_jump" = 0 ]; then
    $save -t filter > "$tmpd/save2" 2>/dev/null || : > "$tmpd/save2"
    for ch in INPUT OUTPUT FORWARD; do
      grep -q "^:$ch DROP" "$tmpd/save2" || continue
      if [ "$use_file" = 1 ] && grep -q "^:$ch DROP" "$legacy"; then
        if [ "$ch" = FORWARD ] && grep -Eq '^:(DOCKER|KUBE-)' "$tmpd/save2"; then
          warn "FORWARD policy DROP left unchanged (Docker/Kubernetes chains present; may be theirs)"
          continue
        fi
        if $ipt -P $ch ACCEPT; then info "reset $ch policy DROP -> ACCEPT (set by a legacy Segmentra deployment)"; fi
      elif [ "$ch" = INPUT ]; then
        warn "INPUT policy is DROP but it could not be attributed to Segmentra; left unchanged"
      fi
    done
  fi
  if [ -s "$tmpd/del" ]; then
    # One transaction per rule: iptables-nft mis-resolves several -D of adjacent
    # rules within a single restore batch. On apply these rules sit after our jump
    # (and on remove the policies were reset above), so deleting them one at a time
    # never closes access.
    # If deletion by rule spec fails (iptables-nft cannot always re-match a rule it
    # printed itself), fall back to deleting that exact rule by its current position.
    ok=0; bad=0
    while IFS= read -r line; do
      if printf '*filter\\n%s\\nCOMMIT\\n' "$line" | $restore --noflush 2>"$tmpd/err"; then ok=$((ok + 1)); continue; fi
      c=$(echo "$line" | cut -d' ' -f2); r=\${line#-D $c }
      n=$($ipt -S "$c" | grep -nxF -- "-A $c $r" | head -n 1 | cut -d: -f1)
      if [ -n "$n" ] && [ "$n" -gt 1 ] && $ipt -D "$c" $((n - 1)) 2>>"$tmpd/err"; then ok=$((ok + 1))
      else bad=$((bad + 1)); warn "could not remove legacy rule: $line ($(tr '\\n' ' ' < "$tmpd/err"))"; fi
    done < "$tmpd/del"
    info "removed $ok legacy Segmentra rule(s) from INPUT/OUTPUT"
    [ "$bad" = 0 ] || warn "$bad legacy Segmentra rule(s) could not be removed"
  fi
  if [ "$had_jump" = 0 ] && [ -s "$tmpd/keep" ] && { [ "$use_file" = 1 ] || [ -s "$tmpd/del" ]; }; then
    while IFS= read -r line; do
      warn "rule not identified as Segmentra's, left in place: $line"
    done < "$tmpd/keep"
  fi
  return 0
}

# ---- scoped backup / restore -------------------------------------------------------------

V2HDR="# segmentra-backup v2 $ipt"
EMPTY_FILTER='*filter\\n:INPUT ACCEPT [0:0]\\n:FORWARD ACCEPT [0:0]\\n:OUTPUT ACCEPT [0:0]\\nCOMMIT\\n'
if [ "$ipt" = ip6tables ]; then sfx=6; else sfx=; fi
# Policy files a legacy (full-table design) deployment leaves behind.
LEGACY_FILES="/etc/segmentra.policy$sfx /etc/segmentra.legacy.policy$sfx /etc/segmentra.legacy.policy$sfx.migrated /etc/segmentra.policy$sfx.removed"

# Filter-table lines owned by Segmentra in a save file: SEGMENTRA-IN/OUT/FWD declarations + rules.
seg_fragment() {
  awk -v a="$IN" -v b="$OUT" -v f="$FWD" '
    substr($0, 1, 1) == "*" { inf = ($0 == "*filter"); next }
    !inf { next }
    index($0, ":" a " ") == 1 || index($0, ":" b " ") == 1 || index($0, ":" f " ") == 1 { print; next }
    index($0, "-A " a " ") == 1 || index($0, "-A " b " ") == 1 || index($0, "-A " f " ") == 1 { print }
  ' "$1"
}

# save_has_jump <save-file> <chain> <target>: filter table has "-A <chain> ... -j <target>".
save_has_jump() {
  awk -v c="$2" -v t="$3" '
    substr($0, 1, 1) == "*" { inf = ($0 == "*filter"); next }
    inf && index($0, "-A " c " ") == 1 && $NF == t && $(NF - 1) == "-j" { f = 1 }
    END { exit !f }
  ' "$1"
}

# is_legacy <save-file>: the dump shows a host on the legacy full-table design (no jump to
# SEGMENTRA-IN, and Segmentra rules directly in INPUT/OUTPUT — same markers as legacy_cleanup —
# or an INPUT policy DROP while a legacy-format Segmentra policy file is present on the host).
is_legacy() {
  if save_has_jump "$1" INPUT $IN; then return 1; fi
  if awk '
    substr($0, 1, 1) == "*" { inf = ($0 == "*filter"); next }
    inf && /^-A (INPUT|OUTPUT) / && (/--comment "?(segmentra|mgmt_ssh)/ || /--log-prefix "FW-AUDIT:/) { f = 1 }
    END { exit !f }' "$1"; then return 0; fi
  if awk '
    substr($0, 1, 1) == "*" { inf = ($0 == "*filter"); next }
    inf && /^:INPUT DROP/ { f = 1 }
    END { exit !f }' "$1"; then
    for lf in $LEGACY_FILES; do
      if [ -f "$lf" ] && grep -Eq '^-A (INPUT|OUTPUT) ' "$lf"; then return 0; fi
    done
  fi
  return 1
}

backup_state() {
  umask 077
  full="$bfile.full"
  if ! $save > "$tmpd/full" 2>"$tmpd/err"; then
    echo "segmentra-iptables: $save failed: $(tr '\\n' ' ' < "$tmpd/err")" >&2; exit 4
  fi
  # No tables loaded -> empty dump; store an explicit open filter table instead
  if [ ! -s "$tmpd/full" ]; then printf "$EMPTY_FILTER" > "$tmpd/full"; fi
  seg_fragment "$tmpd/full" > "$tmpd/frag"
  ci=0; co=0; cf=0; ji=0; jo=0; jf=0; lg=0
  if grep -q "^:$IN " "$tmpd/frag"; then ci=1; fi
  if grep -q "^:$OUT " "$tmpd/frag"; then co=1; fi
  if grep -q "^:$FWD " "$tmpd/frag"; then cf=1; fi
  if save_has_jump "$tmpd/full" INPUT $IN; then ji=1; fi
  if save_has_jump "$tmpd/full" OUTPUT $OUT; then jo=1; fi
  if save_has_jump "$tmpd/full" FORWARD $FWD; then jf=1; fi
  if is_legacy "$tmpd/full"; then lg=1; fi
  {
    echo "$V2HDR"
    echo "# Segmentra's own filter-table state only (chains $IN/$OUT/$FWD + INPUT/OUTPUT/FORWARD jumps)."
    echo "# Complete $save output at the time of the backup: $full"
    echo "# chain-in=$ci chain-out=$co chain-fwd=$cf jump-in=$ji jump-out=$jo jump-fwd=$jf legacy=$lg"
    if [ -s "$tmpd/frag" ]; then echo '*filter'; cat "$tmpd/frag"; echo COMMIT; fi
  } > "$tmpd/v2" || exit 4
  cp "$tmpd/full" "$full.tmp" && mv -f "$full.tmp" "$full" || { echo "segmentra-iptables: could not write $full" >&2; exit 4; }
  cp "$tmpd/v2" "$bfile.tmp" && mv -f "$bfile.tmp" "$bfile" || { echo "segmentra-iptables: could not write $bfile" >&2; exit 4; }
  info "backup written: $bfile (chains: in=$ci out=$co fwd=$cf, jumps: in=$ji out=$jo fwd=$jf, legacy=$lg)"
}

# Legacy hosts only: Segmentra's rules live directly in INPUT/OUTPUT (and may have set the
# built-in policies), so they cannot be separated from other rules. The complete filter table
# of the backup is restored (-T filter: nat/mangle/raw/... are left alone). Filter-table rules
# other tools added after the backup are lost — the behaviour of the legacy design itself.
restore_full_filter() {
  if [ ! -s "$1" ]; then echo "segmentra-iptables: full backup $1 missing; cannot restore legacy host" >&2; exit 3; fi
  if ! grep -qx '[*]filter' "$1"; then echo "segmentra-iptables: $1 has no filter table" >&2; exit 4; fi
  if ! $restore -T filter < "$1"; then echo "segmentra-iptables: $restore -T filter < $1 failed" >&2; exit 4; fi
  info "legacy host: restored the complete filter table from $1"
}

# Restore only SEGMENTRA-IN/OUT/FWD and the INPUT/OUTPUT/FORWARD jumps from the fragment in
# $tmpd/frag. Backups taken before SEGMENTRA-FWD existed contain no FWD chain: restoring them
# removes it (and its jump), which is exactly the state at backup time.
restore_scoped() {
  hi=0; ho=0; hf=0
  if grep -q "^:$IN " "$tmpd/frag"; then hi=1; fi
  if grep -q "^:$OUT " "$tmpd/frag"; then ho=1; fi
  if grep -q "^:$FWD " "$tmpd/frag"; then hf=1; fi
  [ "$hi" = 1 ] || ji=0
  [ "$ho" = 1 ] || jo=0
  [ "$hf" = 1 ] || jf=0
  if [ "$hi" = 1 ] || [ "$ho" = 1 ] || [ "$hf" = 1 ]; then
    # Declaring an existing chain with --noflush flushes it: the chains get their backed-up
    # content (and missing jumps are inserted) in ONE atomic transaction.
    {
      echo '*filter'
      cat "$tmpd/frag"
      if [ "$ji" = 1 ] && ! $ipt -C INPUT -j $IN 2>/dev/null; then echo "-I INPUT 1 -j $IN"; fi
      if [ "$jo" = 1 ] && ! $ipt -C OUTPUT -j $OUT 2>/dev/null; then echo "-I OUTPUT 1 -j $OUT"; fi
      if [ "$jf" = 1 ] && ! $ipt -C FORWARD -j $FWD 2>/dev/null; then echo "-I FORWARD 1 -j $FWD"; fi
      echo COMMIT
    } > "$tmpd/apply"
    if ! $restore --noflush < "$tmpd/apply"; then echo "segmentra-iptables: $restore failed; nothing was changed" >&2; exit 4; fi
  fi
  # Jumps / chains that did not exist when the backup was taken.
  if [ "$ji" = 0 ]; then while $ipt -C INPUT -j $IN 2>/dev/null; do $ipt -D INPUT -j $IN || exit 5; done; fi
  if [ "$jo" = 0 ]; then while $ipt -C OUTPUT -j $OUT 2>/dev/null; do $ipt -D OUTPUT -j $OUT || exit 5; done; fi
  if [ "$jf" = 0 ]; then while $ipt -C FORWARD -j $FWD 2>/dev/null; do $ipt -D FORWARD -j $FWD || exit 5; done; fi
  for pair in $IN:$hi $OUT:$ho $FWD:$hf; do
    c=\${pair%%:*}; h=\${pair#*:}
    if [ "$h" = 0 ] && $ipt -S $c >/dev/null 2>&1; then
      $ipt -F $c || exit 5
      $ipt -X $c || { echo "segmentra-iptables: could not delete chain $c (still referenced?)" >&2; exit 5; }
    fi
  done
  dedupe_jumps || { echo "segmentra-iptables: could not remove duplicate jumps" >&2; exit 4; }
  info "restored $IN/$OUT/$FWD from $bfile (chains: in=$hi out=$ho fwd=$hf, jumps: in=$ji out=$jo fwd=$jf); other chains untouched"
}

restore_backup() {
  if [ ! -s "$bfile" ]; then echo "segmentra-iptables: backup missing or empty: $bfile" >&2; exit 3; fi
  first=$(head -n 1 "$bfile")
  case "$first" in
    "$V2HDR")
      hdr=$(grep -m 1 '^# chain-in=' "$bfile" || true)
      case " $hdr " in *" legacy="[01]" "*) ;; *) echo "segmentra-iptables: malformed backup header in $bfile" >&2; exit 4 ;; esac
      ji=0; jo=0; jf=0
      case " $hdr " in *" jump-in=1 "*) ji=1 ;; esac
      case " $hdr " in *" jump-out=1 "*) jo=1 ;; esac
      case " $hdr " in *" jump-fwd=1 "*) jf=1 ;; esac
      case " $hdr " in *" legacy=1 "*) restore_full_filter "$bfile.full"; return ;; esac
      ;;
    "# segmentra-backup "*)
      echo "segmentra-iptables: $bfile is not a $ipt backup this version understands ($first)" >&2; exit 4 ;;
    *)
      # Pre-v2 backup: a complete $save dump. Only Segmentra's part of it is restored.
      ji=0; jo=0; jf=0
      if save_has_jump "$bfile" INPUT $IN; then ji=1; fi
      if save_has_jump "$bfile" OUTPUT $OUT; then jo=1; fi
      if save_has_jump "$bfile" FORWARD $FWD; then jf=1; fi
      if is_legacy "$bfile"; then restore_full_filter "$bfile"; return; fi
      ;;
  esac
  seg_fragment "$bfile" > "$tmpd/frag"
  restore_scoped
}

${PERSIST_COMMON_SH}
ipt_paths() {
  IFILE=; IUNIT=; IPLUG=; IMETH=none
  case "$P_DISTRO" in
    debian)
      IUNIT=netfilter-persistent.service; IMETH=netfilter-persistent
      if [ "$ipt" = iptables ]; then IFILE=/etc/iptables/rules.v4; IPLUG=/usr/share/netfilter-persistent/plugins.d/15-ip4tables
      else IFILE=/etc/iptables/rules.v6; IPLUG=/usr/share/netfilter-persistent/plugins.d/25-ip6tables; fi ;;
    rhel)
      IUNIT=$ipt.service; IMETH=iptables-services
      if [ "$ipt" = iptables ]; then IFILE=/etc/sysconfig/iptables; else IFILE=/etc/sysconfig/ip6tables; fi ;;
  esac
}

# Segmentra's live lines -> $tmpd/pdecl (chain declarations) and $tmpd/prules (jumps first, then
# the SEGMENTRA-* rules). Returns 1 = no Segmentra chains, 2 = log-only policy, 3 = read error.
ipt_render() {
  : > "$tmpd/pdecl"; : > "$tmpd/prules"
  $save > "$tmpd/psave" 2>/dev/null || return 3
  seg_fragment "$tmpd/psave" > "$tmpd/pfrag"
  grep '^:' "$tmpd/pfrag" > "$tmpd/pdecl"
  [ -s "$tmpd/pdecl" ] || return 1
  if grep -q 'FW-AUDIT: ALLOW: catch-all' "$tmpd/pfrag"; then return 2; fi
  {
    if save_has_jump "$tmpd/psave" INPUT $IN; then echo "-A INPUT -j $IN"; fi
    if save_has_jump "$tmpd/psave" OUTPUT $OUT; then echo "-A OUTPUT -j $OUT"; fi
    if save_has_jump "$tmpd/psave" FORWARD $FWD; then echo "-A FORWARD -j $FWD"; fi
    grep '^-A ' "$tmpd/pfrag"
  } > "$tmpd/prules"
  return 0
}

# ipt_merge <saved-file|/dev/null>: the saved file with Segmentra's lines of its *filter section
# replaced by $tmpd/pdecl + $tmpd/prules (inserted after the chain declarations, so the jumps are
# the first rules of INPUT/OUTPUT/FORWARD). All other lines are printed unchanged. Without a
# *filter section (or file) and with something to add, a minimal *filter section is appended.
ipt_merge() {
  awk -v decl="$tmpd/pdecl" -v rules="$tmpd/prules" '
    BEGIN {
      while ((getline l < decl) > 0) d[++nd] = l
      while ((getline l < rules) > 0) r[++nr] = l
    }
    function emit(  i) { if (!done) { for (i = 1; i <= nd; i++) print d[i]; for (i = 1; i <= nr; i++) print r[i]; done = 1 } }
    function ours(s) {
      if (s ~ /^:SEGMENTRA-(IN|OUT|FWD)[ \\t]/) return 1
      if (s ~ /^-A SEGMENTRA-(IN|OUT|FWD)[ \\t]/) return 1
      if (s ~ /^-A (INPUT|OUTPUT|FORWARD) -j SEGMENTRA-(IN|OUT|FWD)[ \\t]*$/) return 1
      return 0
    }
    substr($0, 1, 1) == "*" { if (inf && !done) emit(); inf = ($0 == "*filter"); if (inf) seen = 1; print; next }
    inf && ours($0) { next }
    inf && !done && $0 !~ /^:/ && $0 !~ /^#/ && NF > 0 { emit() }
    { print }
    END {
      if (!seen && nd + nr > 0) {
        print "*filter"; print ":INPUT ACCEPT [0:0]"; print ":FORWARD ACCEPT [0:0]"; print ":OUTPUT ACCEPT [0:0]"
        emit(); print "COMMIT"
      }
    }' "$1"
}

ipt_persist() {
  pm=$1
  P_FAMILY=$ipt
  detect_distro
  ipt_paths
  if [ -z "$IFILE" ]; then
    pwarn unsupported_distro "reboot persistence is supported on Debian, Ubuntu and RHEL-family hosts only; the $ipt SEGMENTRA chains will not survive a reboot"
    presult not_persisted none unsupported; return 0
  fi
  if [ "$pm" = unpersist ]; then : > "$tmpd/pdecl"; : > "$tmpd/prules"; rr=1
  else ipt_render; rr=$?; fi
  if [ "$rr" = 3 ]; then pwarn read_failed "$save failed"; presult not_persisted none error; exit 4; fi
  pkg=1
  if [ "$P_DISTRO" = debian ]; then
    if [ ! -e "$IPLUG" ] || ! unit_exists netfilter-persistent.service; then pkg=0; fi
  elif ! unit_exists "$IUNIT"; then pkg=0; fi
  havenew=0
  if [ "$rr" != 2 ]; then
    if [ -f "$IFILE" ]; then ipt_merge "$IFILE" > "$tmpd/pnew"; havenew=1
    elif [ "$rr" = 0 ]; then ipt_merge /dev/null > "$tmpd/pnew"; havenew=1; fi
  fi
  if [ "$pm" != check ] && [ "$havenew" = 1 ] && { [ "$pkg" = 1 ] || [ -f "$IFILE" ]; }; then
    if ! replace_file "$IFILE" "$tmpd/pnew" 600; then
      pwarn write_failed "could not write $IFILE"; presult not_persisted none error; exit 4
    fi
    if [ "$rr" = 0 ]; then info "SEGMENTRA chains merged into $IFILE"; else info "SEGMENTRA lines removed from $IFILE"; fi
  fi
  if [ "$rr" = 2 ]; then
    pnote log_only_active "a log-only Firewall Learning / policy test policy is active; it is not persisted, the boot configuration keeps the last enforced policy"
    if [ -f "$IFILE" ] && grep -q "^:$IN " "$IFILE"; then state=learning; else state=missing; fi
  elif [ "$havenew" = 0 ]; then state=none
  elif same_file "$IFILE" "$tmpd/pnew"; then state=in_sync
  elif [ -f "$IFILE" ]; then state=differs
  else state=missing; fi
  if [ "$rr" = 1 ] && [ "$pm" != check ]; then presult removed none none; return 0; fi
  if [ "$rr" = 1 ] && [ "$state" = in_sync ]; then state=none; fi
  if [ "$P_DISTRO" = debian ] && unit_enabled nftables.service && grep -q '^[[:space:]]*flush[[:space:]][[:space:]]*ruleset' /etc/nftables.conf 2>/dev/null; then
    pnote nftables_flush_conflict "nftables.service is also enabled and /etc/nftables.conf contains flush ruleset; depending on boot order it can remove the restored iptables rules (disable nftables.service or remove flush ruleset)"
  fi
  if [ -f "$IFILE" ] && awk '
      substr($0, 1, 1) == "*" { inf = ($0 == "*filter"); next }
      inf && /^-A INPUT -j (REJECT|DROP)/ { f = 1 }
      END { exit !f }' "$IFILE"; then
    pnote saved_rules_final_reject "$IFILE ends INPUT with a catch-all REJECT/DROP of its own: after a reboot it also drops traffic Segmentra allows (Segmentra allows with RETURN, so later rules still apply)"
  fi
  st=not_persisted; meth=none
  if [ "$pkg" = 0 ]; then
    if [ "$P_DISTRO" = debian ]; then
      pwarn iptables_persistent_missing "the iptables-persistent package (netfilter-persistent) is not installed and Segmentra does not install packages: install iptables-persistent to make the $ipt rules survive a reboot"
    else
      pwarn iptables_services_missing "the iptables-services package ($IUNIT) is not installed and Segmentra does not install packages: install iptables-services to make the $ipt rules survive a reboot"
    fi
  elif firewalld_on; then
    pwarn firewalld_active "firewalld is active or enabled and conflicts with $IUNIT, which Segmentra therefore does not enable: the $ipt rules will not survive a reboot while firewalld manages the firewall (disable firewalld and enable $IUNIT to persist them)"
  elif [ "$pm" = persist ] && ! enable_unit "$IUNIT"; then
    :
  elif unit_enabled "$IUNIT"; then
    st=persisted; meth=$IMETH
  else
    meth=$IMETH
    pwarn service_disabled "$IUNIT is not enabled; Segmentra enables it on the next deployment"
  fi
  if [ "$st" = persisted ]; then
    case "$state" in in_sync|learning|none) ;; *) st=not_persisted ;; esac
  fi
  if [ "$state" = none ]; then st=removed; fi
  presult "$st" "$meth" "$state"
}

case "$mode" in
  apply) apply_chains; legacy_cleanup ;;
  apply-audit) apply_chains ;;
  remove) remove_chains; legacy_cleanup ;;
  backup) backup_state ;;
  restore) restore_backup ;;
  persist|unpersist|check) ipt_persist "$mode" ;;
esac
exit 0
`;

/**
 * Shell snippet (run as root) that keeps a copy of a legacy-format
 * /etc/segmentra.policy[6] before it is overwritten, so its rules can be
 * identified and removed later.
 */
export function preserveLegacyPolicyScript(): string {
  return [
    `if [ -f /etc/segmentra.policy ] && grep -Eq '^-A (INPUT|OUTPUT) ' /etc/segmentra.policy; then cp -p /etc/segmentra.policy ${LEGACY_POLICY_FILE}; fi`,
    `if [ -f /etc/segmentra.policy6 ] && grep -Eq '^-A (INPUT|OUTPUT) ' /etc/segmentra.policy6; then cp -p /etc/segmentra.policy6 ${LEGACY_POLICY_FILE6}; fi`
  ].join('\n');
}

/** `sh -c '<SEGMENTRA_IPTABLES_SH>' segmentra-iptables <args...>` (args are shell-quoted). */
export function segmentraIptablesCommand(args: string[]): string {
  return `sh -c ${shq(SEGMENTRA_IPTABLES_SH)} segmentra-iptables ${args.map((a) => shq(a)).join(' ')}`;
}

/**
 * Shell snippet (run as root) run after a deployment/removal is confirmed
 * successful: the legacy policy files have served their purpose, so retire
 * them (kept as *.migrated for reference) and never match against them again.
 */
export function retireLegacyPolicyScript(): string {
  return [
    `if [ -f ${LEGACY_POLICY_FILE} ]; then mv -f ${LEGACY_POLICY_FILE} ${LEGACY_POLICY_FILE}.migrated; fi`,
    `if [ -f ${LEGACY_POLICY_FILE6} ]; then mv -f ${LEGACY_POLICY_FILE6} ${LEGACY_POLICY_FILE6}.migrated; fi`
  ].join('\n');
}
