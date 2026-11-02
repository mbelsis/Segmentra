import { DMESG_STAMP_AWK, KERNEL_LINE, type AuditLogSource } from './audit-ssh.js';
import { runSshSudo, shq, type SshConnectionOptions } from './ssh-options.js';
import type { SshHostInfo } from './types.js';

export interface HostFirewallLogs {
  hostname: string;
  success: boolean;
  /** Raw kernel log lines, oldest first. */
  lines: string[];
  source: AuditLogSource | 'audit-file';
  error?: string;
}

const LINE_RE = 'FW-AUDIT|SEGMENTRA:';
/** Baseline reply and loopback packets of log-only sessions: thousands of lines that are not flows. */
const NOISE_RE = 'FW-AUDIT: ALLOW: (establish|loopback)';

/**
 * Read the newest firewall log lines of a host, read-only. Lines of enforced rules with logging on
 * ("SEGMENTRA: ...") and of log-only sessions ("FW-AUDIT: ..."). Log-only sessions divert their lines
 * to their own file through rsyslog, so without journald that file is read as well.
 */
export async function readHostFirewallLogs(host: SshHostInfo, limit: number, opts: SshConnectionOptions = {}): Promise<HostFirewallLogs> {
  const max = Math.max(1, Math.min(Math.trunc(limit) || 200, 1000));
  const script = [
    'seg_filter() { grep -E ' + shq(LINE_RE) + ' | grep -E ' + KERNEL_LINE + ' | grep -Ev ' + shq(NOISE_RE) + ' | tail -n ' + max + '; }',
    `seg_dmesg_new() { ${DMESG_STAMP_AWK}; }`,
    'seg_out=$(mktemp) || exit 1',
    'seg_src=none',
    'if command -v journalctl >/dev/null 2>&1; then',
    '  journalctl -k -q --no-pager -o short-iso -n 50000 2>/dev/null | seg_filter > "$seg_out"',
    '  if [ -s "$seg_out" ]; then seg_src=journald; fi',
    'fi',
    'if [ "$seg_src" = none ]; then',
    '  for seg_f in /var/log/kern.log /var/log/messages /var/log/syslog; do',
    '    [ -f "$seg_f" ] || continue',
    '    seg_src=kernel-log-file',
    '    tail -n 200000 "$seg_f" | seg_filter > "$seg_out"',
    '    if [ -s "$seg_out" ]; then break; fi',
    '  done',
    '  seg_a=$(ls -t /var/log/segmentra-test-*.log /var/log/segmentra-audit-*.log 2>/dev/null | head -n 1)',
    '  if [ -n "$seg_a" ] && grep -Eq ' + KERNEL_LINE + ' "$seg_a"; then',
    '    [ "$seg_src" = none ] && seg_src=audit-file',
    '    seg_filter < "$seg_a" >> "$seg_out"',
    '  fi',
    'fi',
    'if [ ! -s "$seg_out" ] && [ "$seg_src" = none ] && dmesg >/dev/null 2>&1 && awk \'BEGIN{strftime("%s",0)}\' >/dev/null 2>&1; then',
    '  seg_src=dmesg',
    '  dmesg | seg_filter | seg_dmesg_new 0 > "$seg_out"',
    'fi',
    'echo "segmentra-log-source: $seg_src"',
    'cat "$seg_out"',
    'rm -f "$seg_out"'
  ].join('\n');

  const result = await runSshSudo(host, script, opts);
  if (result.exitCode !== 0) {
    return { hostname: host.hostname, success: false, lines: [], source: 'none', error: (result.stderr || result.stdout || 'Failed to read firewall logs').trim() };
  }
  const all = result.stdout.split('\n').filter((l) => l.trim().length > 0);
  const marker = all.findIndex((l) => l.startsWith('segmentra-log-source: '));
  const source = (marker >= 0 ? all[marker].split(' ')[1] : 'none') as HostFirewallLogs['source'];
  return { hostname: host.hostname, success: true, lines: all.slice(marker + 1), source };
}
