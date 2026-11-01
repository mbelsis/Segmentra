import crypto from 'node:crypto';
import type { FirewallBackend } from './types.js';
import { isManagedBackend, managerCommand } from './manager-scripts.js';
import { BACKEND_CONFLICT_EXIT, backendConflictCheckScript, backendConflictMessage } from './backend-conflict.js';
import fs from 'node:fs';
import { promisify } from 'node:util';
import { hashLiveRuleset, liveRulesReadScript } from './read-rules.js';
import {
  HOST_IPTABLES_SCRIPT,
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
  retireLegacyPolicyScript
} from './iptables-scripts.js';
import { parsePersistenceOutput, persistenceSummary, type PersistenceResult } from './persist-scripts.js';
import {
  defaultTimeout,
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
  backend: FirewallBackend;
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
function buildRestoreScript(backend: 'nft' | 'iptables' | 'firewalld' | 'ufw', paths: BackupPaths): string {
  if (isManagedBackend(backend)) return scopedRestoreSnippet(backend, paths.backupFile, undefined, 'installed');
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

/**
 * Root shell script applying /etc/segmentra.policy (+ /etc/segmentra.policy6) with the chain-scoped
 * iptables design. Uses the host script copy installed in step 3 (keeps the command short enough
 * to be wrapped in a remote `timeout`, see remoteTimeoutWrap).
 */
function iptablesApplyScript(): string {
  const ipt = (args: string[]) => `/bin/sh ${shq(HOST_IPTABLES_SCRIPT)} ${args.map((a) => shq(a)).join(' ')}`;
  return [
    'set -e',
    ipt(['apply', 'iptables', '/etc/segmentra.policy', LEGACY_POLICY_FILE]),
    'if [ -f /etc/segmentra.policy6 ]; then',
    '  if command -v ip6tables-restore >/dev/null 2>&1; then',
    `    ${ipt(['apply', 'ip6tables', '/etc/segmentra.policy6', LEGACY_POLICY_FILE6])}`,
    '  else echo "warning: ip6tables-restore not found; IPv6 rules not applied" >&2; fi',
    'fi'
  ].join('\n');
}

/**
 * Root script (run on the host) bounding `script` with the host's own `timeout`, so a command
 * whose SSH session timed out locally does not keep changing the firewall on the host while the
 * rollback runs. Hosts whose `timeout` lacks the coreutils / busybox >= 1.30 syntax (probed with
 * `timeout 1 true`) run the script unbounded. Exit 124 = the remote timeout fired.
 */
export function remoteTimeoutWrap(script: string, seconds: number): string {
  const secs = Math.max(5, Math.floor(seconds));
  return [
    'if command -v timeout >/dev/null 2>&1 && timeout 1 true >/dev/null 2>&1; then',
    `  timeout ${secs} /bin/sh -c ${shq(script)}`,
    'else',
    `  /bin/sh -c ${shq(script)}`,
    'fi'
  ].join('\n');
}

const ACTIVE_SERVICE_STATES = 'active|activating|deactivating|reloading|refreshing';

/**
 * Root script cancelling the scheduled revert (`token` = "systemd:<unit>" or "pid:<n>").
 * Exit 0 = cancelled before it fired; 9 = it already fired or is firing (marker present, the
 * transient .service is active, or the watchdog is gone); anything else = cancel failed.
 * A running restore is never stopped half-way (that could leave a partial ruleset); the caller
 * waits for it to finish instead (see awaitRevertSettled).
 */
export function revertCancelScript(token: string, marker: string): string {
  if (token.startsWith('systemd:')) {
    const unit = token.slice('systemd:'.length);
    return [
      `if [ -e ${shq(marker)} ]; then exit 9; fi`,
      // A failed stop (unit already elapsed and unloaded) is only fatal when the revert did not run.
      `if ! systemctl stop ${shq(`${unit}.timer`)}; then if [ -e ${shq(marker)} ]; then exit 9; fi; exit 1; fi`,
      // Stopping the timer does not stop a .service the timer already started.
      `case "$(systemctl is-active ${shq(`${unit}.service`)} 2>/dev/null)" in ${ACTIVE_SERVICE_STATES}) exit 9 ;; esac`,
      `if [ -e ${shq(marker)} ]; then exit 9; fi`,
      `systemctl reset-failed ${shq(`${unit}.timer`)} ${shq(`${unit}.service`)} >/dev/null 2>&1`,
      'exit 0'
    ].join('\n');
  }
  return [
    `pid=${token.slice(4)}`,
    `if [ -e ${shq(marker)} ] || ! kill -0 "$pid" 2>/dev/null; then exit 9; fi`,
    'kill "$pid" 2>/dev/null',
    'sleep 1',
    'if kill -0 "$pid" 2>/dev/null; then exit 1; fi',
    `if [ -e ${shq(marker)} ]; then exit 9; fi`,
    'exit 0'
  ].join('\n');
}

export type RevertState = 'pending' | 'running' | 'done' | 'gone' | 'unknown';

/**
 * Root script printing the state of the scheduled revert: pending (not fired yet), running
 * (firing now), done (fired and finished), gone (neither scheduled nor fired: cancelled, or
 * lost in a reboot).
 */
export function revertStatusScript(token: string, marker: string): string {
  if (token.startsWith('systemd:')) {
    const unit = token.slice('systemd:'.length);
    return [
      `case "$(systemctl is-active ${shq(`${unit}.service`)} 2>/dev/null)" in ${ACTIVE_SERVICE_STATES}) echo running; exit 0 ;; esac`,
      `if [ -e ${shq(marker)} ]; then echo done`,
      `elif systemctl is-active --quiet ${shq(`${unit}.timer`)} 2>/dev/null; then echo pending`,
      'else echo gone; fi'
    ].join('\n');
  }
  return [
    `pid=${token.slice(4)}`,
    `if kill -0 "$pid" 2>/dev/null; then if [ -e ${shq(marker)} ]; then echo running; else echo pending; fi`,
    `elif [ -e ${shq(marker)} ]; then echo done`,
    'else echo gone; fi'
  ].join('\n');
}

export function parseRevertState(stdout: string, exitCode: number): RevertState {
  const s = (stdout.trim().split('\n').pop() ?? '').trim();
  return exitCode === 0 && ['pending', 'running', 'done', 'gone'].includes(s) ? (s as RevertState) : 'unknown';
}

/** How long past the revert deadline to keep waiting for it to finish (restore + persistence sync). */
export const REVERT_SETTLE_GRACE_MS = 120_000;

/**
 * Wait until the scheduled revert has settled — fired and finished ('done'), or no longer
 * scheduled ('gone') — polling `getState` from the deadline on. Returns the last state seen;
 * 'pending' / 'running' / 'unknown' mean it had not settled (or the host could not be asked)
 * `graceMs` after the deadline. The host lock must stay held until this returns: a new
 * deployment started while the old revert is armed would be silently rolled back by it.
 */
export async function awaitRevertSettled(
  getState: () => Promise<RevertState>,
  deadline: number,
  o: { graceMs?: number; pollMs?: number; now?: () => number; sleep?: (ms: number) => Promise<void> } = {}
): Promise<RevertState> {
  const now = o.now ?? Date.now;
  const sleep = o.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const giveUp = deadline + (o.graceMs ?? REVERT_SETTLE_GRACE_MS);
  const pollMs = o.pollMs ?? 5_000;
  let last: RevertState = 'unknown';
  for (;;) {
    // Before the deadline only 'running'/'done' (fired early) or 'gone' can end the wait.
    last = await getState();
    if (last === 'done' || last === 'gone') return last;
    if (now() >= giveUp) return last;
    const untilDeadline = deadline - now();
    await sleep(Math.max(250, Math.min(untilDeadline > 0 ? untilDeadline : pollMs, pollMs, giveUp - now())));
  }
}

export function describeRevertState(state: RevertState, backupPath: string): string {
  switch (state) {
    case 'done': return `the automatic revert fired and finished; Segmentra's previous state (${backupPath}) is restored`;
    case 'gone': return 'the automatic revert is no longer scheduled and did not fire';
    case 'running': return `the automatic revert is STILL RUNNING (restoring ${backupPath}); check the host before deploying again`;
    case 'pending': return 'the automatic revert is STILL PENDING on the host; check the host before deploying again';
    default: return `the state of the automatic revert could not be determined (host unreachable); it restores ${backupPath} when it fires - check the host before deploying again`;
  }
}

async function deployToHost(host: SshHost, opts: DeployOpts): Promise<SshExecutionResult> {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
  const nonce = crypto.randomBytes(4).toString('hex');
  const ext = host.backend === 'nftables' ? 'nft' : host.backend;
  const remoteUpload = `.segmentra-${timestamp}-${nonce}.policy`; // in the SSH user's home (not world-writable /tmp)
  const remoteUpload6 = `.segmentra-${timestamp}-${nonce}.policy6`;
  const unit = `segmentra-revert-${timestamp.replace(/[^0-9A-Za-z]/g, '')}-${nonce}`;
  const run = (cmd: string, o: { timeoutMs?: number } = {}) =>
    runSshCommand(host, cmd, { knownHostsPath: opts.knownHostsPath, timeoutMs: o.timeoutMs ?? opts.timeoutMs });
  // Root commands: one `sudo sh -c` per step, honouring the host's sudo mode (password or not).
  const sudo = (script: string, o: { args?: string[]; timeoutMs?: number } = {}) =>
    runSshSudo(host, script, { knownHostsPath: opts.knownHostsPath, timeoutMs: o.timeoutMs ?? opts.timeoutMs, args: o.args });

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
    const requiredTool = ext === 'nft' ? 'nft' : ext === 'firewalld' ? 'firewall-cmd' : ext === 'ufw' ? 'ufw' : 'iptables-restore';
    const detectResult = await run(
      `PATH="$PATH:/usr/sbin:/sbin"; command -v ${requiredTool} >/dev/null 2>&1 && echo present || echo missing`
    );
    if (detectResult.exitCode !== 0) {
      add(detectResult);
      return fail(detectResult.exitCode, 'Error: backend detection failed');
    }
    stdout += `Backend: ${host.backend} (${requiredTool} ${detectResult.stdout.trim()})\n`;
    if (detectResult.stdout.trim() !== 'present') {
      return fail(1, `Error: ${requiredTool} is not installed on the host, but the policy targets ${host.backend}`);
    }

    // Step 2b: Refuse while another backend's Segmentra rules are still active (the inventory backend was changed):
    // the old default-deny would stay enforced next to the new policy. Nothing on the host has changed yet.
    if (ext === 'nft' || ext === 'iptables') {
      const conflict = await sudo(backendConflictCheckScript(ext === 'nft' ? 'nftables' : 'iptables'));
      add(conflict);
      if (conflict.exitCode === BACKEND_CONFLICT_EXIT) {
        return fail(conflict.exitCode, `Error: ${backendConflictMessage(host.backend, conflict.stdout)}`);
      }
      if (conflict.exitCode !== 0) {
        return fail(conflict.exitCode, `Error: could not check for Segmentra rules of another firewall backend (exit ${conflict.exitCode})`);
      }
    }

    // Step 3: Back up Segmentra's own state (as root). The deploy is aborted if this fails.
    // Scoped: nft = table inet segmentra only (a full `nft list ruleset` cannot be replayed
    // on hosts where Docker & co. use iptables-nft); iptables = SEGMENTRA-IN/OUT(/FWD) + jumps
    // (the full iptables-save is kept next to it as <file>.full). The host scripts are
    // installed first so the scheduled revert is self-contained.
    const paths: BackupPaths =
      isManagedBackend(host.backend)
        ? { backupFile: `${BACKUP_DIR}/${host.backend}.${timestamp}-${nonce}.json`, backupFile6: '' }
        : ext === 'nft'
        ? { backupFile: `${BACKUP_DIR}/nft.ruleset.${timestamp}-${nonce}`, backupFile6: '' }
        : { backupFile: `${BACKUP_DIR}/iptables.${timestamp}-${nonce}`, backupFile6: `${BACKUP_DIR}/ip6tables.${timestamp}-${nonce}` };
    const backupScript = [
      'set -e',
      'umask 077',
      installHostScriptsSnippet(),
      ...(ext === 'nft'
        ? [`if [ -f /etc/nftables.conf ]; then cp /etc/nftables.conf ${shq(`${BACKUP_DIR}/nftables.conf.${timestamp}-${nonce}`)}; fi`]
        : []),
      isManagedBackend(host.backend)
        ? scopedBackupSnippet(host.backend, paths.backupFile, undefined, 'installed')
        : ext === 'nft'
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
    const cancelScript = revertCancelScript(token, marker);
    const statusScript = revertStatusScript(token, marker);
    /** Wait (holding the caller's host lock) until the armed revert has fired and finished. */
    const settleRevert = async (): Promise<RevertState> => {
      const state = await awaitRevertSettled(async () => {
        const r = await sudo(statusScript, { timeoutMs: 20_000 });
        return parseRevertState(r.stdout, r.exitCode);
      }, deadline);
      stdout += `Automatic revert state: ${state}\n`;
      return state;
    };
    const revertFiredMsg = `The automatic revert already fired; Segmentra's previous state (${backupPath}) was restored and the deployment is NOT active`;

    // Step 7: Apply firewall rules (as root; redirects happen inside sudo).
    // nft: replaces only table inet segmentra. iptables: fills only the SEGMENTRA-IN/OUT(/FWD)
    // chains (iptables-restore --noflush) and inserts the INPUT/OUTPUT(/FORWARD) jumps in the same
    // transaction, then cleans up rules left by the legacy full-table design.
    const applyScript = isManagedBackend(host.backend) ? managerCommand(host.backend, 'apply', '/etc/segmentra.policy', true)
      : ext === 'nft' ? 'nft -f /etc/segmentra.policy' : iptablesApplyScript();
    // Bounded on the host as well, ending before the local SSH timeout: a timed-out apply must
    // not keep changing the firewall while the rollback below restores the backup.
    const localTimeoutMs = opts.timeoutMs ?? defaultTimeout();
    const applyResult = await sudo(remoteTimeoutWrap(applyScript, Math.min(localTimeoutMs / 1000 - 15, delay - 15)));
    add(applyResult);

    if (applyResult.exitCode !== 0) {
      stdout += '\n=== Rollback (apply failed) ===\n';
      const rb = await sudo(restoreScript);
      add(rb);
      let outcome: string;
      if (rb.exitCode === 0) {
        stdout += `Restored ${backupPath}\n`;
        const c = await sudo(cancelScript);
        add(c);
        if (c.exitCode === 0) {
          outcome = `rollback succeeded (${backupPath} restored), automatic revert cancelled`;
        } else {
          // The revert restores the same backup; wait for it so a retry cannot be rolled back by it.
          outcome = `rollback succeeded (${backupPath} restored); ${describeRevertState(await settleRevert(), backupPath)}`;
        }
      } else {
        stderr += `Immediate rollback failed (exit ${rb.exitCode}); waiting for the automatic revert (${delay}s after scheduling)\n`;
        outcome = `immediate rollback FAILED; ${describeRevertState(await settleRevert(), backupPath)}`;
      }
      const rbPersist = parsePersistenceOutput(rb.stdout);
      return fail(applyResult.exitCode, `Firewall apply failed${applyResult.exitCode === 124 ? ' (timed out)' : ''}; ${outcome}`, {
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
      stderr += `Host not reachable over a new SSH connection after apply; waiting for the automatic revert (${delay}s after scheduling)\n`;
      const state = await settleRevert();
      return fail(1, `Host not reachable over a new SSH connection after apply; ${describeRevertState(state, backupPath)}`, {
        backupPath,
        rolledBack: true
      });
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
      const state = await settleRevert();
      return fail(9, state === 'done' ? revertFiredMsg : `${revertFiredMsg}; ${describeRevertState(state, backupPath)}`, { backupPath, rolledBack: true });
    }
    if (cancelResult.exitCode !== 0) {
      stderr += `Could not cancel the automatic revert (${token}); waiting for it to restore ${backupPath}\n`;
      const state = await settleRevert();
      return fail(cancelResult.exitCode, `Could not cancel the automatic revert (${token}); ${describeRevertState(state, backupPath)}`, {
        backupPath,
        rolledBack: true
      });
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
    const persistRes = await sudo(persistSnippet(host.backend, 'persist', 'installed'));
    add(persistRes);
    const persistence = parsePersistenceOutput(persistRes.stdout);
    stdout += `Reboot persistence: ${persistenceSummary(persistence)}\n`;
    if (isManagedBackend(host.backend) && (persistRes.exitCode !== 0 || persistence.status !== 'persisted')) {
      const rb = await sudo(restoreScript);
      add(rb);
      if (rb.exitCode !== 0) {
        return fail(
          1,
          `Native manager reboot persistence verification failed; rollback FAILED (exit ${rb.exitCode}), host left with the unpersisted new policy - check the host manually`,
          { backupPath, rolledBack: false, persistence }
        );
      }
      return fail(1, `Native manager reboot persistence verification failed; rollback succeeded (${backupPath} restored)`, {
        backupPath,
        rolledBack: true,
        persistence
      });
    }

    // Step 10: Read back live ruleset for drift detection (same read + normalization as readHostFirewallRules)
    let liveRulesHash: string | undefined;
    const live = await sudo(liveRulesReadScript(host.backend));
    if (live.exitCode === 0) {
      liveRulesHash = hashLiveRuleset(host.backend, live.stdout);
    } else {
      stderr += `Warning: could not read back live ruleset: ${live.stdout.trim()} ${live.stderr.trim()}\n`;
    }

    return { hostname: host.hostname, success: true, exitCode: 0, stdout, stderr, backupPath, liveRulesHash, persistence };
  } catch (error: any) {
    return fail(1, `Exception: ${error.message}`);
  }
}
