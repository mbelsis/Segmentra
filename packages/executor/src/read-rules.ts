import crypto from 'node:crypto';
import type { SshHostInfo } from './types.js';
import { runSshCommand, shq, type SshConnectionOptions } from './ssh-options.js';

export interface ReadRulesResult {
  hostname: string;
  success: boolean;
  rulesText: string;
  rulesHash: string;
  backend: 'nftables' | 'iptables';
  error?: string;
  /**
   * False when Segmentra's table (nft) or SEGMENTRA-IN chain / INPUT+OUTPUT jumps
   * (iptables, IPv4) are missing from the live ruleset. Set only on success.
   */
  segmentraPresent?: boolean;
}

/**
 * Read current firewall rules from a host via SSH and compute the drift hash.
 * Supports key and password auth. rulesText is the full ruleset (for display);
 * rulesHash covers only Segmentra's own table/chains (see hashLiveRuleset).
 */
export async function readHostFirewallRules(host: SshHostInfo, opts: SshConnectionOptions = {}): Promise<ReadRulesResult> {
  const authMethod = host.authMethod ?? (host.privateKeyPath ? 'key' : host.password ? 'password' : 'key');
  if (authMethod === 'key' && !host.privateKeyPath) {
    throw new Error('read_rules_requires_private_key');
  }
  if (authMethod === 'password' && !host.password) {
    throw new Error('read_rules_requires_password');
  }

  const run = (cmd: string) => runSshCommand(host, cmd, opts);

  // Detect backend if auto
  let backend: 'nftables' | 'iptables' = host.backend === 'iptables' ? 'iptables' : 'nftables';
  if (host.backend === 'auto') {
    const detectResult = await run('command -v nft >/dev/null 2>&1 && echo nft || echo iptables');
    if (detectResult.exitCode !== 0) {
      return {
        hostname: host.hostname,
        success: false,
        rulesText: '',
        rulesHash: '',
        backend,
        error: detectResult.stderr || 'Failed to detect firewall backend'
      };
    }
    backend = detectResult.stdout.trim() === 'nft' ? 'nftables' : 'iptables';
  }

  const result = await run(liveRulesReadCommand(backend));

  if (result.exitCode !== 0) {
    return {
      hostname: host.hostname,
      success: false,
      rulesText: '',
      rulesHash: '',
      backend,
      error: (result.stderr || result.stdout || 'Failed to read firewall rules').trim()
    };
  }

  return {
    hostname: host.hostname,
    success: true,
    rulesText: result.stdout, // Full ruleset, kept for display
    rulesHash: hashLiveRuleset(backend, result.stdout),
    backend,
    segmentraPresent: extractSegmentraState(backend, result.stdout).present
  };
}

/** Prefix of drift hashes that cover only Segmentra's own state. */
export const LIVE_HASH_VERSION_PREFIX = 'v2:';

/** Separator between the iptables-save and ip6tables-save sections of a live read. */
export const IP6TABLES_SECTION_MARKER = '# ---- segmentra: ip6tables-save ----';

/**
 * Remote command printing the full live ruleset (run as the SSH user, uses sudo -n):
 * `nft list ruleset`, or `iptables-save` followed by `ip6tables-save` (when available)
 * after IP6TABLES_SECTION_MARKER. Exit status is that of nft / iptables-save.
 */
export function liveRulesReadCommand(backend: 'nftables' | 'iptables'): string {
  if (backend === 'nftables') return 'sudo -n nft list ruleset 2>&1';
  const script =
    `iptables-save 2>&1 || exit $?; ` +
    `if command -v ip6tables-save >/dev/null 2>&1; then echo '${IP6TABLES_SECTION_MARKER}'; ip6tables-save 2>/dev/null || true; fi`;
  return `sudo -n sh -c ${shq(script)}`;
}

function extractNftTable(text: string): string | null {
  const lines = text.split(/\r?\n/);
  const start = lines.findIndex((l) => /^table inet segmentra \{\s*$/.test(l));
  if (start === -1) return null;
  const out: string[] = [];
  for (let i = start; i < lines.length; i++) {
    out.push(lines[i]);
    if (i > start && /^\}\s*$/.test(lines[i])) break;
  }
  return out.join('\n');
}

function iptablesSegmentraLines(section: string): { lines: string[]; chain: boolean; jumpIn: boolean; jumpOut: boolean } {
  const all = section.split(/\r?\n/).map((l) => l.trim());
  // Only the filter table section
  const lines: string[] = [];
  let inFilter = false;
  let chain = false;
  let jumpIn = false;
  let jumpOut = false;
  for (const l of all) {
    if (l.startsWith('*')) { inFilter = l === '*filter'; continue; }
    if (!inFilter) continue;
    if (/^:SEGMENTRA-IN\s/.test(l)) chain = true;
    if (/^-A (SEGMENTRA-IN|SEGMENTRA-OUT) /.test(l)) lines.push(l.replace(/\s+/g, ' '));
    if (/^-A INPUT (.* )?-j SEGMENTRA-IN$/.test(l)) jumpIn = true;
    if (/^-A OUTPUT (.* )?-j SEGMENTRA-OUT$/.test(l)) jumpOut = true;
  }
  return { lines, chain, jumpIn, jumpOut };
}

/**
 * Extract Segmentra's own state from a live read (see liveRulesReadCommand):
 * nftables → the `table inet segmentra` block (counters/handles stripped);
 * iptables → the SEGMENTRA-IN/OUT rules plus whether the INPUT/OUTPUT jumps
 * exist, for IPv4 and (when present) IPv6. Rules of other tools (Docker,
 * Kubernetes, fail2ban, ...) are ignored. `present` is false when the table /
 * chain / jumps are missing.
 */
export function extractSegmentraState(backend: 'nftables' | 'iptables', text: string): { present: boolean; normalized: string } {
  if (backend === 'nftables') {
    const table = extractNftTable(text);
    if (table === null) return { present: false, normalized: 'nft:table-missing' };
    const normalized = table
      .replace(/^\s*#.*$/gm, '')
      .replace(/\s*# handle \d+/g, '')
      .replace(/counter packets \d+ bytes \d+/g, 'counter')
      .replace(/\s+/g, ' ')
      .trim();
    return { present: true, normalized };
  }
  const [v4text, v6text] = text.split(IP6TABLES_SECTION_MARKER);
  const parts: string[] = [];
  let present = false;
  for (const [fam, sec] of [['v4', v4text], ['v6', v6text]] as const) {
    if (sec === undefined) continue;
    const st = iptablesSegmentraLines(sec);
    if (fam === 'v4') present = st.chain && st.jumpIn && st.jumpOut;
    parts.push(`[${fam}] chain=${st.chain ? 1 : 0} jump_in=${st.jumpIn ? 1 : 0} jump_out=${st.jumpOut ? 1 : 0}`, ...st.lines);
  }
  return { present, normalized: parts.join('\n') };
}

/**
 * Normalize a live ruleset for drift hashing: only Segmentra's own state is
 * kept (see extractSegmentraState), so changes by other tools are not drift.
 */
export function normalizeRulesText(text: string, backend: 'nftables' | 'iptables'): string {
  return extractSegmentraState(backend, text).normalized;
}

/**
 * Drift hash of a live read (`nft list ruleset` / liveRulesReadCommand output),
 * identical to readHostFirewallRules().rulesHash. Prefixed with "v2:" so hashes
 * of the older full-ruleset scheme are distinguishable.
 */
export function hashLiveRuleset(backend: 'nftables' | 'iptables', text: string): string {
  return LIVE_HASH_VERSION_PREFIX + crypto.createHash('sha256').update(normalizeRulesText(text, backend), 'utf8').digest('hex');
}
