/**
 * Scoped firewall backups / restores (shell snippets run as root on the host).
 *
 * Backups contain only Segmentra's own state — `table inet segmentra` (nftables) or the
 * SEGMENTRA-IN/OUT(/FWD) chains + INPUT/OUTPUT(/FORWARD) jumps (iptables/ip6tables) — and restores
 * touch only that state, so rules of Docker, Kubernetes, fail2ban, ... are never
 * replayed or removed. The host-side logic lives in SEGMENTRA_NFT_SH and
 * SEGMENTRA_IPTABLES_SH; this module only builds the command lines.
 */
import { shq } from './ssh-options.js';
import { SEGMENTRA_NFT_SH, segmentraNftCommand } from './nft-scripts.js';
import { SEGMENTRA_IPTABLES_SH, segmentraIptablesCommand } from './iptables-scripts.js';

export const SEGMENTRA_BACKUP_DIR = '/var/backups/segmentra';
/** Root-owned copies of the host scripts, installed by installHostScriptsSnippet() (used by the unattended auto-revert). */
export const HOST_NFT_SCRIPT = `${SEGMENTRA_BACKUP_DIR}/segmentra-nft.sh`;
export const HOST_IPTABLES_SCRIPT = `${SEGMENTRA_BACKUP_DIR}/segmentra-iptables.sh`;

/**
 * Shell snippet (root, umask 077, backup dir exists) that installs SEGMENTRA_NFT_SH and
 * SEGMENTRA_IPTABLES_SH as HOST_NFT_SCRIPT / HOST_IPTABLES_SCRIPT (atomic replace), so a
 * scheduled revert is a self-contained command on the host.
 */
export function installHostScriptsSnippet(): string {
  return [
    [SEGMENTRA_NFT_SH, HOST_NFT_SCRIPT],
    [SEGMENTRA_IPTABLES_SH, HOST_IPTABLES_SCRIPT]
  ]
    .map(
      ([content, dest]) =>
        `printf '%s' ${shq(content)} > ${shq(`${dest}.tmp`)} && chmod 700 ${shq(`${dest}.tmp`)} && mv -f ${shq(`${dest}.tmp`)} ${shq(dest)}`
    )
    .join('\n');
}

type ScriptSource = 'inline' | 'installed';

function nftCmd(args: string[], src: ScriptSource): string {
  return src === 'installed' ? `/bin/sh ${shq(HOST_NFT_SCRIPT)} ${args.map((a) => shq(a)).join(' ')}` : segmentraNftCommand(args);
}

function iptCmd(args: string[], src: ScriptSource): string {
  return src === 'installed'
    ? `/bin/sh ${shq(HOST_IPTABLES_SCRIPT)} ${args.map((a) => shq(a)).join(' ')}`
    : segmentraIptablesCommand(args);
}

/**
 * Shell snippet (root) writing a scoped backup. nftables: `file` (+ `file.full`, reference
 * only). iptables: `file` (+ `file.full`), and when `file6` is given and ip6tables-save
 * exists, `file6` (+ `file6.full`). The nftables / IPv4-only forms just return a non-zero
 * status on failure; the dual-family form EXITS the calling script with the failing status,
 * so use it only at the top level of a root script.
 */
export function scopedBackupSnippet(
  backend: 'nftables' | 'iptables',
  file: string,
  file6?: string,
  src: ScriptSource = 'inline'
): string {
  if (backend === 'nftables') return nftCmd(['backup', file], src);
  const v4 = iptCmd(['backup', 'iptables', file], src);
  if (!file6) return v4;
  return [
    `${v4} || exit $?`,
    `if command -v ip6tables-save >/dev/null 2>&1; then ${iptCmd(['backup', 'ip6tables', file6], src)} || exit $?; fi`
  ].join('\n');
}

/**
 * Shell snippet (root) restoring a scoped backup (also accepts pre-v2 full-ruleset /
 * full iptables-save backups, see the host scripts). For iptables the IPv6 backup is
 * restored too when `file6` exists and ip6tables-restore is available; both families are
 * attempted even if one fails. The snippet's exit status is non-zero if any restore failed
 * (3 = backup missing); it does not call `exit`, so it can be composed.
 */
export function scopedRestoreSnippet(
  backend: 'nftables' | 'iptables',
  file: string,
  file6?: string,
  src: ScriptSource = 'inline'
): string {
  if (backend === 'nftables') return nftCmd(['restore', file], src);
  const v4 = iptCmd(['restore', 'iptables', file], src);
  if (!file6) return v4;
  return [
    `seg_rc=0; seg_rc6=0`,
    `${v4} || seg_rc=$?`,
    `if [ -s ${shq(file6)} ] && command -v ip6tables-restore >/dev/null 2>&1; then ${iptCmd(['restore', 'ip6tables', file6], src)} || seg_rc6=$?; fi`,
    `if [ "$seg_rc" = 0 ]; then seg_rc=$seg_rc6; fi`,
    `(exit $seg_rc)`
  ].join('\n');
}

/**
 * Shell snippet (root) syncing reboot persistence with the distribution's own service to the
 * LIVE Segmentra state (see persist-scripts.ts): `persist` writes/merges it (or removes it when
 * no Segmentra state is live), `unpersist` removes it, `check` only reports. iptables runs for
 * IPv4 and, when ip6tables-save exists, IPv6. Never fails the calling script: its output
 * (SEGMENTRA_PERSIST* lines, parsePersistenceOutput) reports the outcome.
 */
export function persistSnippet(
  backend: 'nftables' | 'iptables',
  mode: 'persist' | 'unpersist' | 'check',
  src: ScriptSource = 'inline'
): string {
  if (backend === 'nftables') return `${nftCmd([mode], src)} || :`;
  const v6 = 'if command -v ip6tables-save >/dev/null 2>&1; then';
  if (src === 'installed') {
    return [`${iptCmd([mode, 'iptables'], src)} || :`, `${v6} ${iptCmd([mode, 'ip6tables'], src)} || :; fi`].join('\n');
  }
  // Inline: the script is embedded ONCE (a temp file used for both families) so the command
  // line stays far below the 128 KiB single-argument limit of ssh/sudo on Linux.
  return [
    `seg_ps=$(mktemp 2>/dev/null) && printf '%s' ${shq(SEGMENTRA_IPTABLES_SH)} > "$seg_ps" && {`,
    `  /bin/sh "$seg_ps" ${mode} iptables || :`,
    `  ${v6} /bin/sh "$seg_ps" ${mode} ip6tables || :; fi`,
    '  rm -f "$seg_ps"',
    '}'
  ].join('\n');
}
