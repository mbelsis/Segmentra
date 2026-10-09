/**
 * Inventory discovery helpers: a TCP reachability probe and a single read-only
 * SSH command that collects basic host facts (hostname, OS, firewall tooling,
 * sudo capability). Nothing is changed on the remote host.
 */
import net from 'node:net';

import { runSshCommand, type SshConnectionOptions, type SshTarget } from './ssh-options.js';

export const DEFAULT_PROBE_TIMEOUT_MS = 1500;

/** Resolve true if a TCP connection to ip:port completes within timeoutMs. Never rejects. */
export function probeTcpPort(ip: string, port: number, timeoutMs = DEFAULT_PROBE_TIMEOUT_MS): Promise<boolean> {
  return new Promise((resolve) => {
    let settled = false;
    const socket = new net.Socket();
    const done = (ok: boolean) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(ok);
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => done(true));
    socket.once('timeout', () => done(false));
    socket.once('error', () => done(false));
    try {
      socket.connect(port, ip);
    } catch {
      done(false);
    }
  });
}

/** Run `worker` over `items` with at most `concurrency` in flight. Results keep input order. */
export async function mapWithConcurrency<T, R>(items: T[], concurrency: number, worker: (item: T, index: number) => Promise<R>): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  const lanes = Array.from({ length: Math.max(1, Math.min(concurrency, items.length)) }, async () => {
    while (true) {
      const i = next++;
      if (i >= items.length) return;
      results[i] = await worker(items[i], i);
    }
  });
  await Promise.all(lanes);
  return results;
}

/**
 * sudo capability found by discovery, tested with the credential's configured method:
 *  - nopasswd:          `sudo -n` works (no password needed);
 *  - password:          sudo works with the credential's sudo password (login or separate);
 *  - password_required: sudo asks for a password, but the credential is set to "sudo without password";
 *  - password_rejected: sudo rejected the credential's sudo password;
 *  - tty_required:      sudoers requires a terminal (Defaults requiretty);
 *  - none:              no usable sudo (e.g. not in sudoers).
 */
export type DiscoverySudo = 'nopasswd' | 'password' | 'password_required' | 'password_rejected' | 'tty_required' | 'none';

const DISCOVERY_SUDO_VALUES: DiscoverySudo[] = ['nopasswd', 'password', 'password_required', 'password_rejected', 'tty_required', 'none'];

export interface DiscoveredHostFacts {
  hostname: string;
  osId: string | null;
  osPrettyName: string | null;
  hasNft: boolean;
  hasIptablesRestore: boolean;
  /** Discovery keeps selection automatic; privileged readiness detects active managers. */
  hasFirewallManager: boolean;
  sudo: DiscoverySudo;
}

export type DiscoveryLoginFailure = 'auth_failed' | 'timeout' | 'host_key_mismatch' | 'connection_failed' | 'unexpected_output';

export type DiscoverHostResult =
  | { ok: true; facts: DiscoveredHostFacts }
  | { ok: false; failure: DiscoveryLoginFailure; message: string };

const MARKER = 'SEGMENTRA_DISCOVERY_V1';

/**
 * Read-only fact collection script. When the credential has a sudo password, it is sent as
 * the first line of stdin (never argv) and only used to test `sudo -k -S sh -c 'exit 0'`.
 */
function discoveryScript(trySudoPassword: boolean): string {
  return [
    'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH; export PATH',
    `echo ${MARKER}`,
    'echo "HOSTNAME=$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null)"',
    'if [ -r /etc/os-release ]; then',
    '  echo "OS_ID=$(sed -n \'s/^ID=//p\' /etc/os-release | head -n1 | tr -d \'"\\047\')"',
    '  echo "OS_PRETTY=$(sed -n \'s/^PRETTY_NAME=//p\' /etc/os-release | head -n1 | tr -d \'"\\047\')"',
    'fi',
    'if command -v nft >/dev/null 2>&1; then echo NFT=1; else echo NFT=0; fi',
    'if command -v iptables-restore >/dev/null 2>&1; then echo IPTR=1; else echo IPTR=0; fi',
    'if command -v firewall-cmd >/dev/null 2>&1 || command -v ufw >/dev/null 2>&1; then echo MANAGER=1; else echo MANAGER=0; fi',
    "seg_e=$(sudo -n sh -c 'exit 0' 2>&1 </dev/null) && seg_s=nopasswd || seg_s=",
    'if [ -z "$seg_s" ]; then',
    '  case "$seg_e" in *tty*) seg_s=tty_required ;; esac',
    'fi',
    ...(trySudoPassword
      ? [
          'if [ -z "$seg_s" ]; then',
          "  IFS= read -r SEGPW || SEGPW=",
          "  seg_e=$(printf '%s\\n' \"$SEGPW\" | sudo -k -S -p '' sh -c 'exit 0' 2>&1) && seg_s=password",
          '  unset SEGPW',
          '  if [ -z "$seg_s" ]; then',
          '    case "$seg_e" in',
          '      *tty*) seg_s=tty_required ;;',
          '      *"incorrect password"*|*"try again"*|*"no password was provided"*) seg_s=password_rejected ;;',
          '      *) seg_s=none ;;',
          '    esac',
          '  fi',
          'fi'
        ]
      : [
          'if [ -z "$seg_s" ]; then',
          '  case "$seg_e" in *"password is required"*) seg_s=password_required ;; *) seg_s=none ;; esac',
          'fi'
        ]),
    'echo "SUDO=$seg_s"',
    'exit 0'
  ].join('\n');
}

function classifyFailure(exitCode: number, stderr: string, timedOut?: boolean): { failure: DiscoveryLoginFailure; message: string } {
  const msg = stderr.trim().split('\n').filter(Boolean).slice(-1)[0] ?? `exit code ${exitCode}`;
  if (timedOut || /timed out/i.test(stderr)) return { failure: 'timeout', message: 'timeout' };
  if (/REMOTE HOST IDENTIFICATION HAS CHANGED|Host key verification failed/i.test(stderr)) {
    return { failure: 'host_key_mismatch', message: 'host key mismatch (known_hosts has a different key for this address)' };
  }
  if (/Permission denied|Authentication failed|Too many authentication failures/i.test(stderr) || exitCode === 5) {
    return { failure: 'auth_failed', message: 'auth failed' };
  }
  return { failure: 'connection_failed', message: msg.slice(0, 300) };
}

/** Log in once over SSH and collect host facts with a single read-only command. */
export async function discoverHostOverSsh(target: SshTarget, opts: SshConnectionOptions = {}): Promise<DiscoverHostResult> {
  const trySudoPassword = target.sudoPassword !== undefined && target.sudoPassword !== null;
  const r = await runSshCommand(target, discoveryScript(trySudoPassword), {
    ...opts,
    timeoutMs: opts.timeoutMs ?? 30_000,
    input: trySudoPassword ? `${target.sudoPassword}\n` : undefined
  });
  if (r.exitCode !== 0 || !r.stdout.includes(MARKER)) {
    if (r.exitCode === 0) return { ok: false, failure: 'unexpected_output', message: 'unexpected output from discovery command' };
    const f = classifyFailure(r.exitCode, r.stderr, r.timedOut);
    if (f.failure === 'auth_failed' && target.keyPassphrase) f.message = 'auth failed (key rejected or wrong key passphrase)';
    return { ok: false, ...f };
  }
  const kv = new Map<string, string>();
  for (const line of r.stdout.slice(r.stdout.indexOf(MARKER)).split('\n')) {
    const m = line.match(/^([A-Z_]+)=(.*)$/);
    if (m && !kv.has(m[1])) kv.set(m[1], m[2].trim());
  }
  const sudo = kv.get('SUDO');
  return {
    ok: true,
    facts: {
      hostname: kv.get('HOSTNAME') ?? '',
      osId: kv.get('OS_ID') || null,
      osPrettyName: kv.get('OS_PRETTY') || null,
      hasNft: kv.get('NFT') === '1',
      hasIptablesRestore: kv.get('IPTR') === '1',
      hasFirewallManager: kv.get('MANAGER') === '1',
      sudo: DISCOVERY_SUDO_VALUES.includes(sudo as DiscoverySudo) ? (sudo as DiscoverySudo) : 'none'
    }
  };
}
