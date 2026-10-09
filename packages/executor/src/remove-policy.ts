import crypto from 'node:crypto';
import type { SshHostInfo } from './types.js';
import { DETECT_FIREWALL_BACKEND, isManagedBackend, managerCommand } from './manager-scripts.js';
import { runSshSudo, shq, type SshConnectionOptions } from './ssh-options.js';
import {
  LEGACY_POLICY_FILE,
  LEGACY_POLICY_FILE6,
  preserveLegacyPolicyScript,
  retireLegacyPolicyScript
} from './iptables-scripts.js';
import {
  HOST_IPTABLES_SCRIPT,
  SEGMENTRA_BACKUP_DIR,
  installHostScriptsSnippet,
  persistSnippet,
  scopedBackupSnippet
} from './firewall-backup.js';
import { parsePersistenceOutput, type PersistenceResult } from './persist-scripts.js';

const BACKUP_DIR = SEGMENTRA_BACKUP_DIR;

export interface RemovePolicyResult {
  success: boolean;
  exitCode: number;
  stdout: string;
  stderr: string;
  /** Reboot persistence after the removal (status 'removed' when Segmentra's boot configuration was removed). */
  persistence?: PersistenceResult;
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
 * /etc/segmentra.policy[6] are renamed to *.removed afterwards, and Segmentra's part of the
 * distribution's boot configuration (include line + segmentra.nft, or the SEGMENTRA
 * lines merged into rules.v4/v6 or /etc/sysconfig/iptables/ip6tables) is removed, so the rules do
 * not come back after a reboot (see persist-scripts.ts).
 * With host.backend 'auto'/undefined, both are attempted where the tools exist.
 */
export async function removeSegmentraPolicy(host: SshHostInfo, opts: SshConnectionOptions = {}): Promise<RemovePolicyResult> {
  if (!host.backend || host.backend === 'auto') {
    const detected = await runSshSudo(host, DETECT_FIREWALL_BACKEND, opts);
    if (detected.exitCode !== 0 || !['nftables', 'iptables', 'firewalld', 'ufw'].includes(detected.stdout.trim())) {
      return { success: false, exitCode: detected.exitCode || 1, stdout: detected.stdout, stderr: detected.stderr || 'No supported firewall manager detected' };
    }
    host = { ...host, backend: detected.stdout.trim() as Exclude<SshHostInfo['backend'], 'auto'> };
  }
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
  const ts = `${timestamp}-${crypto.randomBytes(2).toString('hex')}`;
  if (isManagedBackend(host.backend)) {
    const backup = `${BACKUP_DIR}/${host.backend}.remove.${ts}.json`;
    const script = ['set -e', 'umask 077', `mkdir -p ${shq(BACKUP_DIR)}`, installHostScriptsSnippet(),
      managerCommand(host.backend, 'backup', backup, true), managerCommand(host.backend, 'remove', undefined, true)].join('\n');
    const result = await runSshSudo(host, script, opts);
    return { success: result.exitCode === 0, ...result, persistence: parsePersistenceOutput(result.stdout) };
  }
  const doNft = host.backend !== 'iptables';
  const doIpt = host.backend !== 'nftables';
  const b = (name: string) => shq(`${BACKUP_DIR}/${name}.${ts}`);

  const script = [
    'set -e',
    'umask 077',
    `mkdir -p ${shq(BACKUP_DIR)} && chmod 700 ${shq(BACKUP_DIR)}`,
    // Install the host scripts once and call the installed copies: embedding them inline for
    // every step would exceed the 128 KiB command-line argument limit.
    installHostScriptsSnippet(),
    `do_nft=${doNft ? 1 : 0}; do_ipt=${doIpt ? 1 : 0}`,
    'has_nft=0; if [ "$do_nft" = 1 ] && command -v nft >/dev/null 2>&1; then has_nft=1; fi',
    'has_ipt=0; if [ "$do_ipt" = 1 ] && command -v iptables-save >/dev/null 2>&1; then has_ipt=1; fi',
    'if [ "$has_nft" = 0 ] && [ "$has_ipt" = 0 ]; then echo "error: no supported firewall tooling (nft / iptables) found" >&2; exit 6; fi',
    // --- backup (abort on failure: set -e) ---
    'if [ "$has_nft" = 1 ]; then',
    `  ${scopedBackupSnippet('nftables', `${BACKUP_DIR}/nft.ruleset.${ts}`, undefined, 'installed')}`,
    `  test -s ${b('nft.ruleset')}`,
    'fi',
    'if [ "$has_ipt" = 1 ]; then',
    `  ${scopedBackupSnippet('iptables', `${BACKUP_DIR}/iptables.${ts}`, `${BACKUP_DIR}/ip6tables.${ts}`, 'installed')}`,
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
    `  /bin/sh ${shq(HOST_IPTABLES_SCRIPT)} remove iptables ${shq(LEGACY_POLICY_FILE)}`,
    '  if command -v ip6tables-save >/dev/null 2>&1 && command -v ip6tables-restore >/dev/null 2>&1; then',
    `    /bin/sh ${shq(HOST_IPTABLES_SCRIPT)} remove ip6tables ${shq(LEGACY_POLICY_FILE6)}`,
    '  fi',
    `  ${retireLegacyPolicyScript().split('\n').join('\n  ')}`,
    'fi',
    // The policy is no longer deployed; keep the files for reference only.
    'for f in /etc/segmentra.policy /etc/segmentra.policy6; do if [ -f "$f" ]; then mv -f "$f" "$f.removed"; fi; done',
    // Remove Segmentra's part of the boot configuration (never fails the removal).
    'if [ "$has_nft" = 1 ]; then',
    persistSnippet('nftables', 'unpersist', 'installed'),
    'fi',
    'if [ "$has_ipt" = 1 ]; then',
    persistSnippet('iptables', 'unpersist', 'installed'),
    'fi',
    'echo "Segmentra policy removed"'
  ].join('\n');

  try {
    const r = await runSshSudo(host, script, opts);
    const ok = r.exitCode === 0;
    return {
      success: ok,
      exitCode: r.exitCode,
      stdout: r.stdout,
      stderr: ok ? r.stderr : `${r.stderr}\nError: removing the Segmentra policy failed (exit ${r.exitCode})\n`,
      ...(ok ? { persistence: parsePersistenceOutput(r.stdout) } : {})
    };
  } catch (error: any) {
    return { success: false, exitCode: 1, stdout: '', stderr: `Exception: ${error?.message ?? String(error)}` };
  }
}
