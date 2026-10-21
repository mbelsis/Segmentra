import crypto from 'node:crypto';
import type { FirewallBackend } from './types.js';
import { isManagedBackend } from './manager-scripts.js';
import fs from 'node:fs';
import { promisify } from 'node:util';
import {
  isSafeAbsolutePath,
  runSshSudo,
  scpDownload,
  scpUpload,
  shq,
  type ExecResult,
  type SshConnectionOptions
} from './ssh-options.js';
import { segmentraIptablesCommand } from './iptables-scripts.js';
import { SEGMENTRA_BACKUP_DIR, persistSnippet, scopedBackupSnippet, scopedRestoreSnippet } from './firewall-backup.js';
import { parsePersistenceOutput, type PersistenceResult } from './persist-scripts.js';

const writeFile = promisify(fs.writeFile);
const readFile = promisify(fs.readFile);

export interface AuditSshHost {
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
  backend: FirewallBackend;
}

export interface AuditSessionResult {
  hostname: string;
  success: boolean;
  exitCode: number;
  stdout: string;
  stderr: string;
  backupPath?: string;
  logFilePath?: string;
  /** Reboot persistence after the restore (the boot configuration follows the restored state). */
  persistence?: PersistenceResult;
}

const BACKUP_DIR = SEGMENTRA_BACKUP_DIR;
const RSYSLOG_CONF = '/etc/rsyslog.d/99-segmentra-audit.conf';
const AUDIT_POLICY_PATH = '/etc/segmentra-audit.policy';
/**
 * Shell function that makes rsyslog read its configuration again. Service managers first; without
 * one (containers, chroots, minimal images) the daemon is restarted directly: rsyslog 8 only reopens
 * its output files on SIGHUP and keeps running with the old configuration.
 */
const RSYSLOG_RELOAD_FN = [
  'seg_reload_rsyslog() {',
  '  if command -v systemctl >/dev/null 2>&1 && systemctl restart rsyslog >/dev/null 2>&1; then return 0; fi',
  '  if command -v service >/dev/null 2>&1 && service rsyslog restart >/dev/null 2>&1; then return 0; fi',
  '  if command -v rc-service >/dev/null 2>&1 && rc-service rsyslog restart >/dev/null 2>&1; then return 0; fi',
  '  if pgrep -x rsyslogd >/dev/null 2>&1; then',
  '    pkill -x rsyslogd 2>/dev/null || true',
  '    seg_i=0; while pgrep -x rsyslogd >/dev/null 2>&1 && [ "$seg_i" -lt 10 ]; do sleep 1; seg_i=$((seg_i+1)); done',
  '  fi',
  '  if ! pgrep -x rsyslogd >/dev/null 2>&1; then rm -f /run/rsyslogd.pid /var/run/rsyslogd.pid; fi',
  '  if rsyslogd >/dev/null 2>&1; then return 0; fi',
  '  echo "warning: could not restart rsyslog" >&2',
  '  return 1',
  '}'
].join('\n');
const RSYSLOG_RESTART = `${RSYSLOG_RELOAD_FN}\nseg_reload_rsyslog || true`;

/**
 * State file for the fallback log collection (next to the audit log file): where the kernel log
 * files ended when the session started, a journald cursor, and whether the rsyslog drop-in works.
 */
const offsetsPath = (logFilePath: string) => `${logFilePath}.offsets`;
const KERNEL_LOG_FILES = ['/var/log/kern.log', '/var/log/messages', '/var/log/syslog'];

function recordKernelLogOffsetsSnippet(logFilePath: string, rsyslogState: string): string {
  const off = shq(offsetsPath(logFilePath));
  return [
    `umask 077; : > ${off}`,
    `echo "since $(date +%s)" >> ${off}`,
    `echo "rsyslog ${rsyslogState}" >> ${off}`,
    'if command -v journalctl >/dev/null 2>&1; then',
    `  seg_cur=$(journalctl -k -q --no-pager -n 0 --show-cursor 2>/dev/null | sed -n 's/^-- cursor: //p'); [ -n "$seg_cur" ] && echo "cursor $seg_cur" >> ${off}`,
    'fi',
    `for seg_f in ${KERNEL_LOG_FILES.join(' ')}; do if [ -f "$seg_f" ]; then echo "file $seg_f $(wc -c < "$seg_f")" >> ${off}; fi; done`,
    'true'
  ].join('\n');
}

/**
 * Hosts without rsyslog, or where the drop-in could not be activated: append this session's
 * FW-AUDIT lines from journald (kernel stream, by cursor) or from the kernel log files (from the
 * recorded offsets) to the audit log file, then move the markers so a later collection does not
 * read the same lines again.
 */
function collectKernelLogFallbackSnippet(logFilePath: string): string {
  const log = shq(logFilePath);
  const off = shq(offsetsPath(logFilePath));
  return [
    `if [ -f ${off} ] && ! grep -q '^rsyslog active' ${off}; then`,
    `  seg_since=$(sed -n 's/^since //p' ${off}); seg_cur=$(sed -n 's/^cursor //p' ${off})`,
    '  seg_tmp=$(mktemp) || exit 1',
    '  seg_new=$(mktemp) || exit 1',
    `  grep -v '^since \\|^cursor \\|^file ' ${off} > "$seg_new"`,
    '  echo "since $(date +%s)" >> "$seg_new"',
    '  if command -v journalctl >/dev/null 2>&1; then',
    '    if [ -n "$seg_cur" ]; then journalctl -k -q --no-pager -o short-iso --show-cursor --after-cursor="$seg_cur" > "$seg_tmp" 2>/dev/null || true;',
    '    else journalctl -k -q --no-pager -o short-iso --show-cursor --since="@${seg_since:-0}" > "$seg_tmp" 2>/dev/null || true; fi',
    '    seg_next=$(sed -n \'s/^-- cursor: //p\' "$seg_tmp" | tail -n 1); [ -n "$seg_next" ] && echo "cursor $seg_next" >> "$seg_new"',
    '  fi',
    '  if ! grep -q FW-AUDIT "$seg_tmp" 2>/dev/null; then',
    '    : > "$seg_tmp"',
    // The same kernel line is usually in more than one file (kern.log and syslog): use the first file with lines.
    `    sed -n 's/^file //p' ${off} | while read -r seg_f seg_off; do`,
    '      [ -f "$seg_f" ] || continue',
    '      seg_size=$(wc -c < "$seg_f")',
    '      if [ "$seg_size" -ge "${seg_off:-0}" ]; then tail -c +$((${seg_off:-0}+1)) "$seg_f"; else cat "$seg_f"; fi | grep -F FW-AUDIT >> "$seg_tmp" || true',
    '      if grep -q "SRC=\\|saddr" "$seg_tmp" 2>/dev/null; then break; fi',
    '    done',
    '  fi',
    `  for seg_f in ${KERNEL_LOG_FILES.join(' ')}; do if [ -f "$seg_f" ]; then echo "file $seg_f $(wc -c < "$seg_f")" >> "$seg_new"; fi; done`,
    '  seg_n=$(grep -F FW-AUDIT "$seg_tmp" | grep -c "SRC=\\|saddr" || true)',
    '  if [ "$seg_n" -gt 0 ]; then',
    `    grep -F FW-AUDIT "$seg_tmp" >> ${log}`,
    `    echo "collected $seg_n FW-AUDIT lines from the kernel log (rsyslog drop-in inactive)"`,
    '  fi',
    `  cat "$seg_new" > ${off}`,
    '  rm -f "$seg_tmp" "$seg_new"',
    'fi',
    'true'
  ].join('\n');
}

function collector(host: AuditSshHost) {
  let stdout = '';
  let stderr = '';
  return {
    add(r: ExecResult) { stdout += r.stdout; stderr += r.stderr; },
    out: (s: string) => { stdout += s; },
    err: (s: string) => { stderr += s; },
    result(success: boolean, exitCode: number, extra: Partial<AuditSessionResult> = {}): AuditSessionResult {
      return { hostname: host.hostname, success, exitCode: success ? 0 : exitCode || 1, stdout, stderr, ...extra };
    }
  };
}

/**
 * Start an audit session: back up Segmentra's own state (as root; aborts if the
 * backup can't be written) and configure rsyslog to capture FW-AUDIT kernel log lines.
 *
 * The backup is scoped (see firewall-backup.ts): nftables = table inet segmentra only,
 * iptables = SEGMENTRA-IN/OUT(/FWD) + INPUT/OUTPUT(/FORWARD) jumps (full iptables-save kept as
 * `<backupPath>.full`). The log-only policy only replaces that state, so restoring it
 * never touches rules of Docker, Kubernetes, fail2ban, ...
 */
export async function startAuditSession(
  host: AuditSshHost,
  logFilePath: string,
  opts: SshConnectionOptions = {}
): Promise<AuditSessionResult> {
  if (isManagedBackend(host.backend)) {
    return { hostname: host.hostname, success: false, exitCode: 1, stdout: '', stderr: 'Learning sessions are not supported for native firewalld/UFW backends; the enforced permanent policy was not changed.' };
  }
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
  const backupPath = `${BACKUP_DIR}/${host.backend === 'nftables' ? 'nft' : 'iptables'}.audit-backup.${timestamp}`;
  const c = collector(host);
  const sudo = (script: string, o: { args?: string[] } = {}) => runSshSudo(host, script, { ...opts, args: o.args });

  try {
    if (!isSafeAbsolutePath(logFilePath)) {
      c.err(`Invalid log file path: ${logFilePath}\n`);
      return c.result(false, 1);
    }

    // Step 1+2: Ensure backup directory exists and back up existing rules as root.
    // The log-only policy is IPv4-only for iptables (apply-audit iptables), so only the
    // IPv4 state is backed up / restored there.
    const backupScript = [
      'set -e',
      'umask 077',
      `mkdir -p ${shq(BACKUP_DIR)}`,
      `chmod 700 ${shq(BACKUP_DIR)}`,
      ...(host.backend === 'nftables'
        ? [`if [ -f /etc/nftables.conf ]; then cp /etc/nftables.conf ${shq(`${backupPath}.conf`)} || true; fi`]
        : []),
      scopedBackupSnippet(host.backend, backupPath),
      `test -s ${shq(backupPath)}`,
      // Persist the current (enforced) policy before the log-only one replaces it, so a reboot
      // during the session comes back with the enforced policy. The log-only policy itself is
      // never persisted (the host scripts refuse to persist it).
      persistSnippet(host.backend, 'persist')
    ].join('\n');
    const backupResult = await sudo(backupScript);
    c.add(backupResult);
    if (backupResult.exitCode !== 0) {
      c.err('\nError: failed to back up current firewall rules; audit not started (no changes made)\n');
      return c.result(false, backupResult.exitCode);
    }

    // Step 3: Configure rsyslog to capture firewall log lines
    const logResult = await configureLogging(host, logFilePath, opts);
    c.add(logResult);
    if (logResult.exitCode !== 0) {
      c.err('\nError: failed to configure audit logging\n');
      return c.result(false, logResult.exitCode, { backupPath });
    }

    return c.result(true, 0, { backupPath, logFilePath });
  } catch (error: any) {
    c.err(`\nException: ${error.message}\n`);
    return c.result(false, 1);
  }
}

/**
 * Configure rsyslog to write kernel log lines containing FW-AUDIT (emitted by
 * nftables `log prefix` or iptables `-j LOG`) to logFilePath.
 */
async function configureLogging(host: AuditSshHost, logFilePath: string, opts: SshConnectionOptions): Promise<ExecResult> {
  // Property-based filter; "& stop" keeps these lines out of later rules.
  const line1 = `:msg, contains, "FW-AUDIT" ${logFilePath}`;
  const line2 = '& stop';
  const script = [
    'set -e',
    `mkdir -p "$(dirname ${shq(logFilePath)})"`,
    `touch ${shq(logFilePath)}`,
    `chmod 644 ${shq(logFilePath)}`,
    // rsyslog drops privileges to "syslog" on Debian/Ubuntu; let it write the file
    `if id syslog >/dev/null 2>&1; then chown syslog ${shq(logFilePath)} || true; fi`,
    'if ! command -v rsyslogd >/dev/null 2>&1; then',
    '  echo "warning: rsyslogd not found; FW-AUDIT lines will be collected from journald or the kernel log file instead" >&2',
    recordKernelLogOffsetsSnippet(logFilePath, 'missing'),
    '  exit 0',
    'fi',
    `mkdir -p "$(dirname ${shq(RSYSLOG_CONF)})"`,
    `printf '%s\\n' ${shq(line1)} ${shq(line2)} > ${shq(RSYSLOG_CONF)}`,
    `chmod 644 ${shq(RSYSLOG_CONF)}`,
    RSYSLOG_RESTART,
    // Self-test through the syslog socket: the drop-in matches on the message text, so a line
    // logged with `logger` lands in the audit file only when rsyslog has read the new configuration.
    'seg_mark="segmentra-selftest-$$-$(date +%s)"',
    'seg_state=inactive',
    'if command -v logger >/dev/null 2>&1; then',
    '  logger -t segmentra "FW-AUDIT selftest $seg_mark" 2>/dev/null || true',
    `  seg_i=0; while [ "$seg_i" -lt 6 ] && ! grep -q "$seg_mark" ${shq(logFilePath)} 2>/dev/null; do sleep 0.5; seg_i=$((seg_i+1)); done`,
    `  if grep -q "$seg_mark" ${shq(logFilePath)} 2>/dev/null; then seg_state=active; fi`,
    'fi',
    'if [ "$seg_state" = active ]; then',
    `  echo "rsyslog is writing FW-AUDIT lines to ${logFilePath}"`,
    'else',
    `  echo "warning: rsyslog did not pick up ${RSYSLOG_CONF}; FW-AUDIT lines will be collected from journald or the kernel log file instead" >&2`,
    'fi',
    recordKernelLogOffsetsSnippet(logFilePath, '$seg_state')
  ].join('\n');
  return runSshSudo(host, script, opts);
}

/**
 * Deploy log-only firewall policy. For nftables the policy only replaces
 * table inet segmentra; for iptables only the SEGMENTRA-IN/OUT(/FWD) chains (+ the
 * INPUT/OUTPUT(/FORWARD) jumps) are touched. Other tools' rules are left alone.
 */
export async function deployLogOnlyPolicy(
  host: AuditSshHost,
  policyText: string,
  policyFilePath: string,
  opts: SshConnectionOptions = {}
): Promise<AuditSessionResult> {
  const remoteUpload = `.segmentra-audit-${crypto.randomBytes(6).toString('hex')}.policy`; // in SSH user's home
  const c = collector(host);
  const sudo = (script: string, o: { args?: string[] } = {}) => runSshSudo(host, script, { ...opts, args: o.args });

  try {
    // Step 1: Write policy to local temp file
    await writeFile(policyFilePath, policyText, { encoding: 'utf8', mode: 0o600 });
    await promisify(fs.chmod)(policyFilePath, 0o600);

    // Step 2: Copy policy file to remote host
    const scpResult = await scpUpload(host, policyFilePath, remoteUpload, opts);
    c.add(scpResult);
    if (scpResult.exitCode !== 0) return c.result(false, scpResult.exitCode);

    // Step 3: Install to a root-owned location and apply (redirects run as root)
    // iptables: chain-scoped --noflush fragment + jumps (other tools' rules untouched);
    // the scoped backup of SEGMENTRA-IN/OUT(/FWD) is restored when the audit ends.
    const applyCmd =
      host.backend === 'nftables'
        ? `nft -f ${shq(AUDIT_POLICY_PATH)}`
        : segmentraIptablesCommand(['apply-audit', 'iptables', AUDIT_POLICY_PATH]);
    const script = [
      'set -e',
      `install -m 600 -o root "$1/${remoteUpload}" ${shq(AUDIT_POLICY_PATH)}`,
      `rm -f "$1/${remoteUpload}"`,
      applyCmd
    ].join('\n');
    const applyResult = await sudo(script, { args: ['segmentra', '"$HOME"'] });
    c.add(applyResult);
    if (applyResult.exitCode !== 0) {
      c.err('\nFirewall apply failed\n');
      return c.result(false, applyResult.exitCode);
    }

    return c.result(true, 0);
  } catch (error: any) {
    c.err(`\nException: ${error.message}\n`);
    return c.result(false, 1);
  }
}

/**
 * Restore Segmentra's pre-session state from the backup taken by startAuditSession.
 *
 * Scoped (see firewall-backup.ts): nftables restores only table inet segmentra in one
 * atomic `nft -f` transaction (never `flush ruleset`); iptables restores only
 * SEGMENTRA-IN/OUT(/FWD) and the INPUT/OUTPUT(/FORWARD) jumps (legacy full-table hosts: the filter
 * table). Backups taken by older versions (complete `nft list ruleset` / iptables-save
 * dumps) are accepted: only Segmentra's part of them is restored.
 * Returns success:false (exit 3) if the backup is missing, or if the restore fails
 * (the host then still runs the log-only policy).
 */
export async function restoreAuditSession(
  host: AuditSshHost,
  backupPath: string,
  opts: SshConnectionOptions = {}
): Promise<AuditSessionResult> {
  const c = collector(host);
  const sudo = (script: string, o: { args?: string[] } = {}) => runSshSudo(host, script, { ...opts, args: o.args });

  try {
    if (!backupPath || !isSafeAbsolutePath(backupPath)) {
      c.err(`Error: invalid or missing backup path "${backupPath ?? ''}"; firewall NOT restored\n`);
      return c.result(false, 1);
    }

    const restoreScript = [
      'umask 077',
      scopedRestoreSnippet(host.backend, backupPath),
      'seg_restore_rc=$?',
      // Boot configuration follows the restored state (only after a successful restore).
      'if [ "$seg_restore_rc" = 0 ]; then',
      persistSnippet(host.backend, 'persist'),
      'fi',
      'exit $seg_restore_rc'
    ].join('\n');
    const restoreResult = await sudo(restoreScript);
    c.add(restoreResult);
    if (restoreResult.exitCode !== 0) {
      c.err(
        restoreResult.exitCode === 3
          ? '\nError: audit backup not found on host; firewall NOT restored (log-only policy still active)\n'
          : '\nError: restoring firewall rules failed; log-only policy may still be active\n'
      );
      return c.result(false, restoreResult.exitCode);
    }
    c.out(`Restored firewall rules from ${backupPath}\n`);
    const persistence = parsePersistenceOutput(restoreResult.stdout);

    // Clean up audit policy file and rsyslog config
    const cleanupScript = [
      `rm -f ${shq(AUDIT_POLICY_PATH)} ${shq(RSYSLOG_CONF)}`,
      RSYSLOG_RESTART
    ].join('\n');
    const cleanupResult = await sudo(cleanupScript);
    c.add(cleanupResult);
    if (cleanupResult.exitCode !== 0) {
      c.err('\nWarning: cleanup of audit policy/rsyslog config failed\n');
    }

    return c.result(true, 0, persistence.status !== 'unknown' ? { persistence } : {});
  } catch (error: any) {
    c.err(`\nException: ${error.message}\n`);
    return c.result(false, 1);
  }
}

/**
 * Retrieve audit log file from remote server
 */
export async function retrieveAuditLogs(
  host: AuditSshHost,
  remoteLogPath: string,
  localLogPath: string,
  opts: SshConnectionOptions = {}
): Promise<AuditSessionResult> {
  const c = collector(host);
  try {
    if (!isSafeAbsolutePath(remoteLogPath)) {
      c.err(`Invalid log file path: ${remoteLogPath}\n`);
      return c.result(false, 1);
    }
    // Hosts without a working rsyslog drop-in: pull this session's lines from journald / the kernel log first.
    const fallback = await runSshSudo(host, collectKernelLogFallbackSnippet(remoteLogPath), opts);
    c.add(fallback);
    const scpResult = await scpDownload(host, remoteLogPath, localLogPath, opts);
    c.add(scpResult);
    if (scpResult.exitCode === 0 && fs.existsSync(localLogPath)) {
      const content = await readFile(localLogPath, 'utf8');
      c.out(`\nRetrieved ${content.length} bytes from ${remoteLogPath}\n`);
    }
    return c.result(scpResult.exitCode === 0, scpResult.exitCode);
  } catch (error: any) {
    c.err(`\nException: ${error.message}\n`);
    return c.result(false, 1);
  }
}
