/**
 * Segmentra state left on a host by a DIFFERENT firewall backend than the one a deployment targets.
 *
 * Each backend only replaces its own objects (nftables: `table inet segmentra`; iptables: the SEGMENTRA-IN/OUT/FWD
 * chains and their jumps; ufw/firewalld: their segmentra-* objects). Netfilter evaluates all of them, so after a
 * host's backend is changed in the inventory the previous backend's default-deny would stay active next to the new
 * policy and keep dropping what the new one allows, while the deployment reports success. The native managers
 * already refuse raw leftovers (require_manager in manager-scripts.ts); this is the same check for the raw backends.
 *
 * The script runs as root, prints `segmentra-backend-conflict: none` and exits 0 when the host is clean, or prints
 * `segmentra-backend-conflict: <found...>` and exits 3.
 */
export const BACKEND_CONFLICT_EXIT = 3;

export function backendConflictCheckScript(target: 'nftables' | 'iptables'): string {
  return [
    'PATH="$PATH:/usr/sbin:/sbin"',
    `target=${target}`,
    'found=""',
    'if [ "$target" != nftables ] && command -v nft >/dev/null 2>&1 && nft list table inet segmentra >/dev/null 2>&1; then',
    '  found="$found nftables(table inet segmentra)"',
    'fi',
    'for t in iptables-save ip6tables-save; do',
    '  command -v "$t" >/dev/null 2>&1 || continue',
    '  out=$("$t" 2>/dev/null) || continue',
    // Raw iptables: Segmentra's jumps from the built-in chains (and DOCKER-USER on Docker hosts).
    `  if [ "$target" != iptables ] && printf '%s\\n' "$out" | grep -Eq -- '^-A (INPUT|OUTPUT|FORWARD|DOCKER-USER) (.* )?-j SEGMENTRA-'; then`,
    '    case "$found" in *"iptables($t)"*) ;; *) found="$found iptables($t)";; esac',
    '  fi',
    // ufw keeps Segmentra's chains behind its own before-input/output chains.
    `  if printf '%s\\n' "$out" | grep -Eq -- '^-A ufw6?-before-(input|output) -j SEGMENTRA-'; then`,
    '    case "$found" in *ufw*) ;; *) found="$found ufw";; esac',
    '  fi',
    'done',
    'if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1 && firewall-cmd --info-policy=segmentra-in >/dev/null 2>&1; then',
    '  found="$found firewalld(policy segmentra-in)"',
    'fi',
    'if [ -n "$found" ]; then echo "segmentra-backend-conflict:$found"; exit ' + BACKEND_CONFLICT_EXIT + '; fi',
    'echo "segmentra-backend-conflict: none"'
  ].join('\n');
}

/** Human-readable error for a conflict found by backendConflictCheckScript. */
export function backendConflictMessage(target: string, output: string): string {
  const found = /segmentra-backend-conflict:\s*(.*)/.exec(output)?.[1]?.trim() || 'another backend';
  return (
    `Segmentra rules from another firewall backend are still active on this host (${found}) while this deployment ` +
    `targets ${target}. Both would be enforced, and the old default-deny would keep dropping traffic the new policy ` +
    `allows. Remove the previous backend's Segmentra rules first (Inventory -> host -> Remove previous backend rules, ` +
    `or POST /api/hosts/:id/firewall/remove-backend-rules), then deploy again.`
  );
}
