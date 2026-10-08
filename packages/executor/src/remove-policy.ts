import crypto from 'node:crypto';
import type { SshHostInfo } from './types.js';
import { runSshCommand, shq, sudoSh, type SshConnectionOptions } from './ssh-options.js';
import {
  LEGACY_POLICY_FILE,
  LEGACY_POLICY_FILE6,
  preserveLegacyPolicyScript,
  retireLegacyPolicyScript,
  segmentraIptablesCommand
} from './iptables-scripts.js';
import { SEGMENTRA_BACKUP_DIR, scopedBackupSnippet } from './firewall-backup.js';

const BACKUP_DIR = SEGMENTRA_BACKUP_DIR;

export interface RemovePolicyResult {
  success: boolean;
  exitCode: number;
  stdout: string;
  stderr: string;
}

/**
 * Remove Segmentra's policy from a host, leaving every other firewall rule alone.
 *
 * A scoped backup of Segmentra's own state is taken first (same files and format
 * as a deployment: nft.ruleset.<ts> / iptables.<ts> + ip6tables.<ts> in
 * /var/backups/segmentra, see firewall-backup.ts); nothing is changed if it cannot
 * be written. Then:
 *  - nftables: `nft delete table inet segmentra` (a missing table is not an error);
 *  - iptables/ip6tables: the INPUT/OUTPUT(/FORWARD) jumps are deleted (all copies), the
 *    SEGMENTRA-IN/OUT(/FWD) chains flushed and deleted, and rules left by the legacy
 *    full-table design are cleaned up when positively identifiable.
 * /etc/segmentra.policy[6] are renamed to *.removed afterwards.
 * With host.backend 'auto'/undefined, both are attempted where the tools exist.
 */
export async function removeSegmentraPolicy(host: SshHostInfo, opts: SshConnectionOptions = {}): Promise<RemovePolicyResult> {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
  const ts = `${timestamp}-${crypto.randomBytes(2).toString('hex')}`;
  const doNft = host.backend !== 'iptables';
  const doIpt = host.backend !== 'nftables';
  const b = (name: string) => shq(`${BACKUP_DIR}/${name}.${ts}`);

  const script = [
    'set -e',
    'umask 077',
    `mkdir -p ${shq(BACKUP_DIR)} && chmod 700 ${shq(BACKUP_DIR)}`,
    `do_nft=${doNft ? 1 : 0}; do_ipt=${doIpt ? 1 : 0}`,
    'has_nft=0; if [ "$do_nft" = 1 ] && command -v nft >/dev/null 2>&1; then has_nft=1; fi',
    'has_ipt=0; if [ "$do_ipt" = 1 ] && command -v iptables-save >/dev/null 2>&1; then has_ipt=1; fi',
    'if [ "$has_nft" = 0 ] && [ "$has_ipt" = 0 ]; then echo "error: no supported firewall tooling (nft / iptables) found" >&2; exit 6; fi',
    // --- backup (abort on failure: set -e) ---
    'if [ "$has_nft" = 1 ]; then',
    `  ${scopedBackupSnippet('nftables', `${BACKUP_DIR}/nft.ruleset.${ts}`)}`,
    `  test -s ${b('nft.ruleset')}`,
    'fi',
    'if [ "$has_ipt" = 1 ]; then',
    `  ${scopedBackupSnippet('iptables', `${BACKUP_DIR}/iptables.${ts}`, `${BACKUP_DIR}/ip6tables.${ts}`)}`,
    `  test -s ${b('iptables')}`,
    'fi',
    // --- removal ---
    'if [ "$has_nft" = 1 ]; then',
    '  if nft list table inet segmentra >/dev/null 2>&1; then',
    '    nft delete table inet segmentra',
    '    echo "[segmentra:nft] removed table inet segmentra"',
    '  else',
    '    echo "[segmentra:nft] table inet segmentra not present"',
    '  fi',
    'fi',
    'if [ "$has_ipt" = 1 ]; then',
    // A host still on the legacy full-table design: its installed policy identifies the legacy rules
    `  ${preserveLegacyPolicyScript().split('\n').join('\n  ')}`,
    `  ${segmentraIptablesCommand(['remove', 'iptables', LEGACY_POLICY_FILE])}`,
    '  if command -v ip6tables-save >/dev/null 2>&1 && command -v ip6tables-restore >/dev/null 2>&1; then',
    `    ${segmentraIptablesCommand(['remove', 'ip6tables', LEGACY_POLICY_FILE6])}`,
    '  fi',
    `  ${retireLegacyPolicyScript().split('\n').join('\n  ')}`,
    'fi',
    // The policy is no longer deployed; keep the files for reference only.
    'for f in /etc/segmentra.policy /etc/segmentra.policy6; do if [ -f "$f" ]; then mv -f "$f" "$f.removed"; fi; done',
    'echo "Segmentra policy removed"'
  ].join('\n');

  try {
    const r = await runSshCommand(host, sudoSh(script), opts);
    const ok = r.exitCode === 0;
    return {
      success: ok,
      exitCode: r.exitCode,
      stdout: r.stdout,
      stderr: ok ? r.stderr : `${r.stderr}\nError: removing the Segmentra policy failed (exit ${r.exitCode})\n`
    };
  } catch (error: any) {
    return { success: false, exitCode: 1, stdout: '', stderr: `Exception: ${error?.message ?? String(error)}` };
  }
}
