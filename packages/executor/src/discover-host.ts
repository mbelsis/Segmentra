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

export type DiscoverySudo = 'nopasswd' | 'password' | 'none';

export interface DiscoveredHostFacts {
  hostname: string;
  osId: string | null;
  osPrettyName: string | null;
  hasNft: boolean;
  hasIptablesRestore: boolean;
  sudo: DiscoverySudo;
}

export type DiscoveryLoginFailure = 'auth_failed' | 'timeout' | 'host_key_mismatch' | 'connection_failed' | 'unexpected_output';

export type DiscoverHostResult =
  | { ok: true; facts: DiscoveredHostFacts }
  | { ok: false; failure: DiscoveryLoginFailure; message: string };

const MARKER = 'SEGMENTRA_DISCOVERY_V1';

/**
 * Read-only fact collection script. When password auth is used, the password is
 * sent on stdin (never argv) and only used to test `sudo -S true`.
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
    trySudoPassword
      ? 'if sudo -n true >/dev/null 2>&1; then echo SUDO=nopasswd; elif IFS= read -r SEGPW && printf \'%s\\n\' "$SEGPW" | sudo -S -p \'\' true >/dev/null 2>&1; then echo SUDO=password; else echo SUDO=none; fi'
      : 'if sudo -n true >/dev/null 2>&1; then echo SUDO=nopasswd; else echo SUDO=none; fi',
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
  const usePassword = (target.authMethod ?? (target.privateKeyPath ? 'key' : 'password')) === 'password';
  const r = await runSshCommand(target, discoveryScript(usePassword), {
    ...opts,
    timeoutMs: opts.timeoutMs ?? 30_000,
    input: usePassword ? `${target.password ?? ''}\n` : undefined
  });
  if (r.exitCode !== 0 || !r.stdout.includes(MARKER)) {
    if (r.exitCode === 0) return { ok: false, failure: 'unexpected_output', message: 'unexpected output from discovery command' };
    return { ok: false, ...classifyFailure(r.exitCode, r.stderr, r.timedOut) };
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
      sudo: sudo === 'nopasswd' || sudo === 'password' ? sudo : 'none'
    }
  };
}
