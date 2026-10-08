/**
 * Host-side shell logic for the chain-scoped iptables/ip6tables design.
 *
 * Segmentra owns only the SEGMENTRA-IN / SEGMENTRA-OUT chains of the filter
 * table plus one jump to each from INPUT / OUTPUT. Everything else (DOCKER*,
 * KUBE-*, f2b-*, built-in chain policies) is left alone.
 *
 * The same script is shipped to Ansible as
 * infra/ansible-runner/playbooks/files/segmentra-iptables.sh — keep the two
 * byte-identical. After changing SEGMENTRA_IPTABLES_SH, rebuild the executor and run:
 *   node -e "import('./packages/executor/dist/iptables-scripts.js').then(m=>require('fs').writeFileSync('infra/ansible-runner/playbooks/files/segmentra-iptables.sh', m.SEGMENTRA_IPTABLES_SH))"
 */
import { shq } from './ssh-options.js';

/** Root-owned copies of the last pre-chain-design ("legacy") policy files, used to identify legacy rules. */
export const LEGACY_POLICY_FILE = '/etc/segmentra.legacy.policy';
export const LEGACY_POLICY_FILE6 = '/etc/segmentra.legacy.policy6';

/**
 * POSIX sh script. Usage:
 *   sh -c "$SCRIPT" segmentra-iptables apply       <iptables|ip6tables> <policy-file> [legacy-policy-file]
 *   sh -c "$SCRIPT" segmentra-iptables apply-audit <iptables|ip6tables> <policy-file>
 *   sh -c "$SCRIPT" segmentra-iptables remove      <iptables|ip6tables> [legacy-policy-file]
 *
 * apply:       one `iptables-restore --noflush` transaction fills SEGMENTRA-IN/OUT
 *              and inserts the INPUT/OUTPUT jumps at position 1 if missing; duplicate
 *              jumps are removed; then legacy Segmentra rules are cleaned up.
 * apply-audit: as apply, without legacy cleanup (log-only audit; restored from backup).
 * remove:      deletes the jumps, flushes + deletes the chains, cleans up legacy rules.
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
mode=\${1:-}
ipt=\${2:-}
case "$ipt" in iptables|ip6tables) ;; *) echo "segmentra-iptables: invalid family '$ipt'" >&2; exit 2 ;; esac
case "$mode" in
  apply|apply-audit) pol=\${3:-}; legacy=\${4:-} ;;
  remove) pol=; legacy=\${3:-} ;;
  *) echo "segmentra-iptables: invalid mode '$mode'" >&2; exit 2 ;;
esac
save="$ipt-save"
restore="$ipt-restore"
IN=SEGMENTRA-IN
OUT=SEGMENTRA-OUT
LIN=SEGMENTRA-LEGACY-IN
LOUT=SEGMENTRA-LEGACY-OUT
info() { echo "[segmentra:$ipt] $*"; }
warn() { echo "[segmentra:$ipt] warning: $*"; }
tmpd=$(mktemp -d 2>/dev/null) || { echo "segmentra-iptables: mktemp failed" >&2; exit 1; }
trap 'rm -f "$tmpd"/apply "$tmpd"/scratch "$tmpd"/err "$tmpd"/save "$tmpd"/save2 "$tmpd"/del "$tmpd"/keep; rmdir "$tmpd"' EXIT
had_jump=0
if $ipt -C INPUT -j $IN 2>/dev/null; then had_jump=1; fi

dedupe_jumps() {
  for pair in INPUT:$IN OUTPUT:$OUT; do
    ch=\${pair%%:*}; tg=\${pair#*:}
    # -S prints the policy first, so rule number = line number - 1. Keep the first
    # (top-most) jump, delete the others bottom-up.
    nums=$($ipt -S $ch | grep -nxF -- "-A $ch -j $tg" | cut -d: -f1 | tail -n +2 | sort -rn)
    for n in $nums; do $ipt -D $ch $((n - 1)) || return 1; info "removed duplicate $ch -> $tg jump"; done
  done
  return 0
}

apply_chains() {
  if [ ! -s "$pol" ]; then echo "segmentra-iptables: policy file '$pol' missing or empty" >&2; exit 3; fi
  if ! grep -q "^:$IN " "$pol" || grep -Eq '^:(INPUT|OUTPUT|FORWARD) ' "$pol"; then
    echo "segmentra-iptables: '$pol' is not a Segmentra chain fragment; refusing to apply" >&2; exit 3
  fi
  {
    sed '/^COMMIT[[:space:]]*$/d' "$pol"
    if ! $ipt -C INPUT -j $IN 2>/dev/null; then echo "-I INPUT 1 -j $IN"; fi
    if ! $ipt -C OUTPUT -j $OUT 2>/dev/null; then echo "-I OUTPUT 1 -j $OUT"; fi
    echo COMMIT
  } > "$tmpd/apply"
  # Chains are filled and the jumps inserted in ONE atomic transaction.
  if ! $restore --noflush < "$tmpd/apply"; then echo "segmentra-iptables: $restore failed" >&2; exit 4; fi
  dedupe_jumps || { echo "segmentra-iptables: could not remove duplicate jumps" >&2; exit 4; }
  info "applied $IN/$OUT; INPUT/OUTPUT jumps present"
}

remove_chains() {
  for pair in INPUT:$IN OUTPUT:$OUT; do
    ch=\${pair%%:*}; tg=\${pair#*:}
    while $ipt -C $ch -j $tg 2>/dev/null; do $ipt -D $ch -j $tg || exit 5; done
  done
  for c in $IN $OUT; do
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
        if (r == "-j SEGMENTRA-IN" || r == "-j SEGMENTRA-OUT") continue
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

case "$mode" in
  apply) apply_chains; legacy_cleanup ;;
  apply-audit) apply_chains ;;
  remove) remove_chains; legacy_cleanup ;;
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
