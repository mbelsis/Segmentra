import crypto from 'node:crypto';
import fs from 'node:fs';
import { promisify } from 'node:util';
import { hashLiveRuleset, liveRulesReadScript } from './read-rules.js';
import {
  SEGMENTRA_BACKUP_DIR,
  installHostScriptsSnippet,
  persistSnippet,
  scopedBackupSnippet,
  scopedRestoreSnippet
} from './firewall-backup.js';
import {
  LEGACY_POLICY_FILE,
  LEGACY_POLICY_FILE6,
  preserveLegacyPolicyScript,
  retireLegacyPolicyScript,
  segmentraIptablesCommand
} from './iptables-scripts.js';
import { parsePersistenceOutput, persistenceSummary, type PersistenceResult } from './persist-scripts.js';
import {
  runSshCommand,
  runSshSudo,
  scpUpload,
  shq,
  type ExecResult,
  type SshConnectionOptions
} from './ssh-options.js';

const writeFile = promisify(fs.writeFile);

export interface SshHost {
  hostname: string;
  ip: string;
  port: number;
  username: string;
  authMethod?: 'key' | 'password';
  privateKeyPath?: string;
  password?: string;
  /** Passphrase of the private key (key auth); undefined for unencrypted keys. */
  keyPassphrase?: string;
  /** sudo password; undefined = passwordless sudo (sudo -n). */
  sudoPassword?: string;
  policyFilePath: string; // local path to policy file
  /** iptables backend only: local path to the ip6tables-restore file (CompileOutput.ip6tablesRules). */
  ip6PolicyFilePath?: string;
  backend: 'nftables' | 'iptables';
}

export interface SshExecutionResult {
  hostname: string;
  success: boolean;
  exitCode: number;
  stdout: string;
  stderr: string;
  skipped?: boolean; // true if skipped due to cancellation
  /** Remote path of the pre-deployment backup created in this run. */
  backupPath?: string;
  /** True if the previous ruleset was restored (apply failure) or an automatic revert is pending/fired. */
  rolledBack?: boolean;
  /**
   * "v2:"-prefixed sha256 of Segmentra's own live state (nft table / SEGMENTRA chains +
   * jumps) read back after a successful apply; identical to readHostFirewallRules().rulesHash
   * (see hashLiveRuleset).
   */
  liveRulesHash?: string;
  /**
   * Reboot persistence with the distribution's own service, synced after the final state is
   * known (successful apply, or rollback). See persist-scripts.ts.
   */
  persistence?: PersistenceResult;
}

export const BACKUP_DIR = SEGMENTRA_BACKUP_DIR;
const DEFAULT_ROLLBACK_TIMEOUT_SEC = 120;

/**
 * Execute SSH deployment to multiple hosts.
 *
 * Per host: back up Segmentra's current state — table inet segmentra, or the
 * SEGMENTRA-IN/OUT(/FWD) chains + jumps (deploy aborts if the backup can't be written),
 * schedule an automatic revert on the host, apply the policy,
 * verify reachability over a NEW SSH connection, and only then cancel the
 * revert. If the host becomes unreachable the revert fires after
 * `rollbackTimeoutSec` seconds.
 *
 * @param shouldContinue - Optional callback checked between hosts. Return false to stop.
 * @param knownHostsPath - Optional known_hosts file (strict checking if it exists).
 * @param rollbackTimeoutSec - Seconds before the automatic revert fires (default 120).
 * @param commandTimeoutMs - Per-SSH-command timeout (default 5 minutes).
 */
export async function runSshDeployment(params: {
  hosts: SshHost[];
  stdoutPath?: string;
  stderrPath?: string;
  shouldContinue?: () => Promise<boolean>;
  knownHostsPath?: string;
  rollbackTimeoutSec?: number;
  commandTimeoutMs?: number;
}): Promise<SshExecutionResult[]> {
  const results: SshExecutionResult[] = [];
  const allStdout: string[] = [];
  const allStderr: string[] = [];

  for (const host of params.hosts) {
    if (params.shouldContinue) {
      const cont = await params.shouldContinue();
      if (!cont) {
        results.push({
          hostname: host.hostname,
          success: false,
          exitCode: 0,
          stdout: 'Skipped: deployment was stopped before this host was processed',
          stderr: '',
          skipped: true
        });
        allStdout.push(`=== ${host.hostname} ===\nSkipped (deployment stopped)\n`);
        continue;
      }
    }

    const result = await deployToHost(host, {
      knownHostsPath: params.knownHostsPath,
      timeoutMs: params.commandTimeoutMs,
      rollbackTimeoutSec: params.rollbackTimeoutSec ?? DEFAULT_ROLLBACK_TIMEOUT_SEC
    });
    results.push(result);
    allStdout.push(`=== ${host.hostname} ===\n${result.stdout}\n`);
    allStderr.push(`=== ${host.hostname} ===\n${result.stderr}\n`);
  }

  if (params.stdoutPath) await writeFile(params.stdoutPath, allStdout.join('\n'), 'utf8');
  if (params.stderrPath) await writeFile(params.stderrPath, allStderr.join('\n'), 'utf8');

  return results;
}

type DeployOpts = SshConnectionOptions & { rollbackTimeoutSec: number };

/**
 * Shell snippet (run as root) restoring the scoped backup taken in this run: only
 * table inet segmentra (one atomic nft -f) or SEGMENTRA-IN/OUT(/FWD) + jumps are restored;
 * other tools' tables/chains are never touched. Uses the script copies installed on the
 * host in step 3, so it also works unattended (auto-revert via systemd-run / nohup).
 */
function buildRestoreScript(backend: 'nft' | 'iptables', paths: BackupPaths): string {
  const restore =
    backend === 'nft'
      ? scopedRestoreSnippet('nftables', paths.backupFile, undefined, 'installed')
      : scopedRestoreSnippet('iptables', paths.backupFile, paths.backupFile6, 'installed');
  // The boot configuration follows the restored state (persist syncs it to the live state;
  // it never changes the exit status of the restore).
  return [
    restore,
    'seg_restore_rc=$?',
    persistSnippet(backend === 'nft' ? 'nftables' : 'iptables', 'persist', 'installed'),
    '(exit $seg_restore_rc)'
  ].join('\n');
}

type BackupPaths = { backupFile: string; backupFile6: string };

/** Root shell script applying /etc/segmentra.policy (+ /etc/segmentra.policy6) with the chain-scoped iptables design. */
function iptablesApplyScript(): string {
  return [
    'set -e',
    segmentraIptablesCommand(['apply', 'iptables', '/etc/segmentra.policy', LEGACY_POLICY_FILE]),
    'if [ -f /etc/segmentra.policy6 ]; then',
    '  if command -v ip6tables-restore >/dev/null 2>&1; then',
    `    ${segmentraIptablesCommand(['apply', 'ip6tables', '/etc/segmentra.policy6', LEGACY_POLICY_FILE6])}`,
    '  else echo "warning: ip6tables-restore not found; IPv6 rules not applied" >&2; fi',
    'fi'
  ].join('\n');
}

async function deployToHost(host: SshHost, opts: DeployOpts): Promise<SshExecutionResult> {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
  const nonce = crypto.randomBytes(4).toString('hex');
  const ext = host.backend === 'nftables' ? 'nft' : 'iptables';
  const remoteUpload = `.segmentra-${timestamp}-${nonce}.policy`; // in the SSH user's home (not world-writable /tmp)
  const remoteUpload6 = `.segmentra-${timestamp}-${nonce}.policy6`;
  const unit = `segmentra-revert-${timestamp.replace(/[^0-9A-Za-z]/g, '')}-${nonce}`;
  const run = (cmd: string, o: { timeoutMs?: number } = {}) =>
    runSshCommand(host, cmd, { knownHostsPath: opts.knownHostsPath, timeoutMs: o.timeoutMs ?? opts.timeoutMs });
  // Root commands: one `sudo sh -c` per step, honouring the host's sudo mode (password or not).
  const sudo = (script: string, o: { args?: string[] } = {}) =>
    runSshSudo(host, script, { knownHostsPath: opts.knownHostsPath, timeoutMs: opts.timeoutMs, args: o.args });

  let stdout = '';
  let stderr = '';
  const add = (r: ExecResult) => { stdout += r.stdout; stderr += r.stderr; };
  const fail = (exitCode: number, msg: string, extra: Partial<SshExecutionResult> = {}): SshExecutionResult => ({
    hostname: host.hostname,
    success: false,
    exitCode: exitCode || 1,
    stdout,
    stderr: stderr + `\n${msg}\n`,
    ...extra
  });

  try {
    // Step 1: Ensure backup directory exists
    const mkdirResult = await sudo(`mkdir -p ${shq(BACKUP_DIR)} && chmod 700 ${shq(BACKUP_DIR)}`);
    add(mkdirResult);
    if (mkdirResult.exitCode !== 0) {
      // This is the first command on the host, so a failure here is usually SSH itself
      // (unreachable host, timeout, auth) rather than the directory: surface the real error.
      const detail =
        (mkdirResult.stderr || mkdirResult.stdout || '').trim().split('\n').pop()?.replace(/^Error:\s*/, '') || `exit code ${mkdirResult.exitCode}`;
      const reason = mkdirResult.sudoError
        ? 'sudo failed'
        : mkdirResult.exitCode === 255 || mkdirResult.exitCode === 124 ? 'SSH connection failed' : 'could not create backup directory';
      return fail(mkdirResult.exitCode, `Error: ${reason}: ${detail}`);
    }

    // Step 2: Make sure the tool for the policy's backend exists. Both may be installed (modern
    // distros ship iptables-nft next to nft), so only the required tool is checked.
    const requiredTool = ext === 'nft' ? 'nft' : 'iptables-restore';
    const detectResult = await run(
      `PATH="$PATH:/usr/sbin:/sbin"; command -v ${requiredTool} >/dev/null 2>&1 && echo present || echo missing`
    );
    if (detectResult.exitCode !== 0) {
      add(detectResult);
      return fail(detectResult.exitCode, 'Error: backend detection failed');
    }
    stdout += `Backend: ${ext === 'nft' ? 'nftables' : 'iptables'} (${requiredTool} ${detectResult.stdout.trim()})\n`;
    if (detectResult.stdout.trim() !== 'present') {
      return fail(1, `Error: ${requiredTool} is not installed on the host, but the policy targets ${ext === 'nft' ? 'nftables' : 'iptables'}`);
    }

    // Step 3: Back up Segmentra's own state (as root). The deploy is aborted if this fails.
    // Scoped: nft = table inet segmentra only (a full `nft list ruleset` cannot be replayed
    // on hosts where Docker & co. use iptables-nft); iptables = SEGMENTRA-IN/OUT(/FWD) + jumps
    // (the full iptables-save is kept next to it as <file>.full). The host scripts are
    // installed first so the scheduled revert is self-contained.
    const paths: BackupPaths =
      ext === 'nft'
        ? { backupFile: `${BACKUP_DIR}/nft.ruleset.${timestamp}`, backupFile6: '' }
        : { backupFile: `${BACKUP_DIR}/iptables.${timestamp}`, backupFile6: `${BACKUP_DIR}/ip6tables.${timestamp}` };
    const backupScript = [
      'set -e',
      'umask 077',
      installHostScriptsSnippet(),
      ...(ext === 'nft'
        ? [`if [ -f /etc/nftables.conf ]; then cp /etc/nftables.conf ${shq(`${BACKUP_DIR}/nftables.conf.${timestamp}`)}; fi`]
        : []),
      ext === 'nft'
        ? scopedBackupSnippet('nftables', paths.backupFile, undefined, 'installed')
        : scopedBackupSnippet('iptables', paths.backupFile, paths.backupFile6, 'installed'),
      `test -s ${shq(paths.backupFile)}`
    ].join('\n');
    const backupResult = await sudo(backupScript);
    add(backupResult);
    if (backupResult.exitCode !== 0) {
      return fail(backupResult.exitCode, 'Error: failed to back up current firewall rules; deployment aborted (no changes made)');
    }
    stdout += `Backup written: ${paths.backupFile}\n`;
    const backupPath = paths.backupFile;

    // Step 4: Upload policy file(s) to the SSH user's home directory
    const scpResult = await scpUpload(host, host.policyFilePath, remoteUpload, opts);
    add(scpResult);
    if (scpResult.exitCode !== 0) return fail(scpResult.exitCode, 'Error: policy upload failed', { backupPath });

    const hasV6 = ext === 'iptables' && !!host.ip6PolicyFilePath && fs.existsSync(host.ip6PolicyFilePath);
    if (hasV6) {
      const scp6 = await scpUpload(host, host.ip6PolicyFilePath!, remoteUpload6, opts);
      add(scp6);
      if (scp6.exitCode !== 0) return fail(scp6.exitCode, 'Error: IPv6 policy upload failed', { backupPath });
    }

    // Step 5: Install policy file(s) to a root-owned location. Paths are relative
    // to the SSH user's home, so resolve $HOME before switching to root.
    const installScript = [
      'set -e',
      // Keep a copy of a legacy (full-table design) policy so its rules can be identified and cleaned up
      ...(ext === 'iptables' ? [preserveLegacyPolicyScript()] : []),
      `install -m 600 -o root "$1/${remoteUpload}" /etc/segmentra.policy`,
      `rm -f "$1/${remoteUpload}"`,
      hasV6
        ? `install -m 600 -o root "$1/${remoteUpload6}" /etc/segmentra.policy6 && rm -f "$1/${remoteUpload6}"`
        : 'rm -f /etc/segmentra.policy6'
    ].join('\n');
    const setupResult = await sudo(installScript, { args: ['segmentra', '"$HOME"'] });
    add(setupResult);
    if (setupResult.exitCode !== 0) return fail(setupResult.exitCode, 'Error: failed to install policy file', { backupPath });

    // Step 6: Schedule automatic revert (lockout protection). The revert touches
    // a marker file when it fires so a late cancel can detect that it already ran.
    const restoreScript = buildRestoreScript(ext, paths);
    const marker = `${BACKUP_DIR}/revert-fired.${timestamp}-${nonce}`;
    const firingScript = `touch ${shq(marker)}; ${restoreScript}`;
    const delay = Math.max(30, Math.floor(opts.rollbackTimeoutSec));
    const watchdog = `sleep ${delay}; ${firingScript}`;
    const scheduleScript = [
      'if command -v systemd-run >/dev/null 2>&1 && [ -d /run/systemd/system ] &&',
      `   systemd-run --quiet --unit=${unit} --on-active=${delay} --timer-property=AccuracySec=1s /bin/sh -c ${shq(firingScript)} >/dev/null 2>&1; then`,
      `  echo "systemd:${unit}"`,
      'else',
      `  nohup sh -c ${shq(watchdog)} >/dev/null 2>&1 </dev/null &`,
      '  echo "pid:$!"',
      'fi'
    ].join('\n');
    const scheduledAt = Date.now();
    const deadline = scheduledAt + delay * 1000;
    const schedResult = await sudo(scheduleScript);
    add(schedResult);
    const token = (schedResult.stdout.trim().split('\n').pop() ?? '').trim();
    if (schedResult.exitCode !== 0 || !/^(systemd:[A-Za-z0-9-]+|pid:\d+)$/.test(token)) {
      return fail(schedResult.exitCode, 'Error: could not schedule automatic revert; deployment aborted (no changes made)', { backupPath });
    }
    stdout += `Automatic revert scheduled in ${delay}s (${token})\n`;
    // Exit code 9 = the revert already fired (or is firing); the deployment has been undone.
    const cancelScript = token.startsWith('systemd:')
      ? [
          `if [ -e ${shq(marker)} ]; then exit 9; fi`,
          `systemctl stop ${shq(`${unit}.timer`)} || exit 1`,
          `systemctl reset-failed ${shq(`${unit}.timer`)} ${shq(`${unit}.service`)} >/dev/null 2>&1`,
          `if [ -e ${shq(marker)} ]; then exit 9; fi`,
          'exit 0'
        ].join('\n')
      : [
          `pid=${token.slice(4)}`,
          `if [ -e ${shq(marker)} ] || ! kill -0 "$pid" 2>/dev/null; then exit 9; fi`,
          'kill "$pid" 2>/dev/null',
          'sleep 1',
          'if kill -0 "$pid" 2>/dev/null; then exit 1; fi',
          `if [ -e ${shq(marker)} ]; then exit 9; fi`,
          'exit 0'
        ].join('\n');
    const revertFiredMsg = `The automatic revert already fired; Segmentra's previous state (${backupPath}) was restored and the deployment is NOT active`;

    // Step 7: Apply firewall rules (as root; redirects happen inside sudo).
    // nft: replaces only table inet segmentra. iptables: fills only the SEGMENTRA-IN/OUT(/FWD)
    // chains (iptables-restore --noflush) and inserts the INPUT/OUTPUT(/FORWARD) jumps in the same
    // transaction, then cleans up rules left by the legacy full-table design.
    const applyScript = ext === 'nft' ? 'nft -f /etc/segmentra.policy' : iptablesApplyScript();
    const applyResult = await sudo(applyScript);
    add(applyResult);

    if (applyResult.exitCode !== 0) {
      stdout += '\n=== Rollback (apply failed) ===\n';
      const rb = await sudo(restoreScript);
      add(rb);
      if (rb.exitCode === 0) {
        stdout += `Restored ${backupPath}\n`;
        const c = await sudo(cancelScript);
        add(c);
      } else {
        stderr += `Immediate rollback failed; automatic revert will retry within ${delay}s\n`;
      }
      const rbPersist = parsePersistenceOutput(rb.stdout);
      return fail(applyResult.exitCode, 'Firewall apply failed; rollback attempted', {
        backupPath,
        rolledBack: true,
        ...(rbPersist.status !== 'unknown' ? { persistence: rbPersist } : {})
      });
    }

    // Step 8: Verify reachability over a NEW SSH connection, finishing well
    // before the revert deadline (otherwise a successful probe could just be
    // the revert having restored access).
    const marginMs = 8_000;
    let reachable = false;
    for (let attempt = 1; attempt <= 3 && !reachable; attempt++) {
      const remaining = deadline - Date.now() - marginMs;
      if (remaining < 3_000) break;
      const probe = await run('echo segmentra-ok', { timeoutMs: Math.min(20_000, remaining) });
      reachable = probe.exitCode === 0 && probe.stdout.includes('segmentra-ok') && Date.now() < deadline - marginMs / 2;
      if (!reachable) {
        stderr += `Reachability check ${attempt} failed: ${probe.stderr.trim() || `exit ${probe.exitCode}`}\n`;
        if (attempt < 3 && deadline - Date.now() - marginMs > 5_000) await new Promise((r) => setTimeout(r, 2000));
      }
    }
    if (!reachable) {
      return fail(
        1,
        `Host not reachable over a new SSH connection after apply; the automatic revert restores ${backupPath} ${delay}s after scheduling`,
        { backupPath, rolledBack: true }
      );
    }

    // Step 9: Cancel the revert (verifying it has not fired yet)
    let cancelResult = await sudo(cancelScript);
    for (let attempt = 2; attempt <= 3 && cancelResult.exitCode !== 0 && cancelResult.exitCode !== 9; attempt++) {
      stderr += `Cancel attempt ${attempt - 1} failed: ${cancelResult.stderr.trim()}\n`;
      await new Promise((r) => setTimeout(r, 1000));
      cancelResult = await sudo(cancelScript);
    }
    add(cancelResult);
    if (cancelResult.exitCode === 9) {
      return fail(9, revertFiredMsg, { backupPath, rolledBack: true });
    }
    if (cancelResult.exitCode !== 0) {
      return fail(
        cancelResult.exitCode,
        `Could not cancel the automatic revert (${token}); Segmentra's previous state (${backupPath}) will be restored`,
        { backupPath, rolledBack: true }
      );
    }
    stdout += 'Reachability verified; automatic revert cancelled\n';
    if (ext === 'iptables') {
      // Migration from the legacy design is confirmed; never match against the legacy policy again.
      const retire = await sudo(retireLegacyPolicyScript());
      if (retire.exitCode !== 0) stderr += `Warning: could not retire legacy policy files: ${retire.stderr.trim()}\n`;
    }

    // Step 9b: Reboot persistence with the distribution's own service (nftables.service /
    // netfilter-persistent / iptables-services). Done only now, when the new state is final:
    // a revert or rollback before this point leaves the previous boot configuration in place.
    // Never fails the deployment; missing pieces (firewalld, package not installed, unsupported
    // distro) are reported as warnings.
    const persistRes = await sudo(persistSnippet(ext === 'nft' ? 'nftables' : 'iptables', 'persist', 'installed'));
    add(persistRes);
    const persistence = parsePersistenceOutput(persistRes.stdout);
    stdout += `Reboot persistence: ${persistenceSummary(persistence)}\n`;

    // Step 10: Read back live ruleset for drift detection (same read + normalization as readHostFirewallRules)
    let liveRulesHash: string | undefined;
    const live = await sudo(liveRulesReadScript(ext === 'nft' ? 'nftables' : 'iptables'));
    if (live.exitCode === 0) {
      liveRulesHash = hashLiveRuleset(ext === 'nft' ? 'nftables' : 'iptables', live.stdout);
    } else {
      stderr += `Warning: could not read back live ruleset: ${live.stdout.trim()} ${live.stderr.trim()}\n`;
    }

    return { hostname: host.hostname, success: true, exitCode: 0, stdout, stderr, backupPath, liveRulesHash, persistence };
  } catch (error: any) {
    return fail(1, `Exception: ${error.message}`);
  }
}
