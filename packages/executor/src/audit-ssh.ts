import crypto from 'node:crypto';
import fs from 'node:fs';
import { promisify } from 'node:util';
import {
  isSafeAbsolutePath,
  runSshCommand,
  scpDownload,
  scpUpload,
  shq,
  sudoSh,
  type ExecResult,
  type SshConnectionOptions
} from './ssh-options.js';
import { segmentraIptablesCommand } from './iptables-scripts.js';
import { SEGMENTRA_BACKUP_DIR, scopedBackupSnippet, scopedRestoreSnippet } from './firewall-backup.js';

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
  backend: 'nftables' | 'iptables';
}

export interface AuditSessionResult {
  hostname: string;
  success: boolean;
  exitCode: number;
  stdout: string;
  stderr: string;
  backupPath?: string;
  logFilePath?: string;
}

const BACKUP_DIR = SEGMENTRA_BACKUP_DIR;
const RSYSLOG_CONF = '/etc/rsyslog.d/99-segmentra-audit.conf';
const AUDIT_POLICY_PATH = '/etc/segmentra-audit.policy';
const RSYSLOG_RESTART =
  'systemctl restart rsyslog 2>/dev/null || service rsyslog restart 2>/dev/null || pkill -HUP rsyslogd 2>/dev/null || echo "warning: could not restart rsyslog" >&2';

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
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
  const backupPath = `${BACKUP_DIR}/${host.backend === 'nftables' ? 'nft' : 'iptables'}.audit-backup.${timestamp}`;
  const c = collector(host);
  const run = (cmd: string) => runSshCommand(host, cmd, opts);

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
      `test -s ${shq(backupPath)}`
    ].join('\n');
    const backupResult = await run(sudoSh(backupScript));
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
    '  echo "warning: rsyslogd not found; FW-AUDIT log lines will not be collected into the audit log file" >&2',
    '  exit 0',
    'fi',
    `mkdir -p "$(dirname ${shq(RSYSLOG_CONF)})"`,
    `printf '%s\\n' ${shq(line1)} ${shq(line2)} > ${shq(RSYSLOG_CONF)}`,
    `chmod 644 ${shq(RSYSLOG_CONF)}`,
    RSYSLOG_RESTART
  ].join('\n');
  return runSshCommand(host, sudoSh(script), opts);
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
  const run = (cmd: string) => runSshCommand(host, cmd, opts);

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
    const applyResult = await run(`sudo -n sh -c ${shq(script)} segmentra "$HOME"`);
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
  const run = (cmd: string) => runSshCommand(host, cmd, opts);

  try {
    if (!backupPath || !isSafeAbsolutePath(backupPath)) {
      c.err(`Error: invalid or missing backup path "${backupPath ?? ''}"; firewall NOT restored\n`);
      return c.result(false, 1);
    }

    const restoreScript = ['umask 077', scopedRestoreSnippet(host.backend, backupPath)].join('\n');
    const restoreResult = await run(sudoSh(restoreScript));
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

    // Clean up audit policy file and rsyslog config
    const cleanupScript = [
      `rm -f ${shq(AUDIT_POLICY_PATH)} ${shq(RSYSLOG_CONF)}`,
      RSYSLOG_RESTART
    ].join('\n');
    const cleanupResult = await run(sudoSh(cleanupScript));
    c.add(cleanupResult);
    if (cleanupResult.exitCode !== 0) {
      c.err('\nWarning: cleanup of audit policy/rsyslog config failed\n');
    }

    return c.result(true, 0);
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
