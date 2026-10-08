/**
 * Shared SSH/SCP helpers: option building (host key verification, timeouts,
 * key or password auth), shell quoting, and child-process execution with an
 * overall timeout.
 */
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { isIP } from 'node:net';

export interface SshTarget {
  hostname?: string;
  ip: string;
  port: number;
  username: string;
  authMethod?: 'key' | 'password';
  privateKeyPath?: string;
  password?: string;
}

export interface SshConnectionOptions {
  /**
   * Explicit known_hosts file. If it exists, host keys are verified strictly
   * (StrictHostKeyChecking=yes). If it does not exist yet it is created and
   * populated on first connect (accept-new).
   * Defaults to env SEGMENTRA_KNOWN_HOSTS, then ~/.ssh/known_hosts (accept-new).
   */
  knownHostsPath?: string;
  /** Overall per-command timeout in ms (default 5 minutes, env SEGMENTRA_SSH_COMMAND_TIMEOUT_MS). */
  timeoutMs?: number;
}

export interface ExecResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  timedOut?: boolean;
}

export const DEFAULT_SSH_COMMAND_TIMEOUT_MS = 5 * 60 * 1000;

/** POSIX single-quote shell escaping. Safe for any string, including nested use. */
export function shq(value: string | number): string {
  return `'${String(value).replace(/'/g, `'\\''`)}'`;
}

function defaultTimeout(): number {
  const env = Number(process.env.SEGMENTRA_SSH_COMMAND_TIMEOUT_MS);
  return Number.isFinite(env) && env > 0 ? env : DEFAULT_SSH_COMMAND_TIMEOUT_MS;
}

function ensureDir(dir: string): void {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
}

/** Resolve the known_hosts file and checking mode. */
export function resolveKnownHosts(explicitPath?: string): { path: string; strict: boolean } {
  if (explicitPath) {
    if (fs.existsSync(explicitPath)) return { path: explicitPath, strict: true };
    ensureDir(path.dirname(explicitPath));
    return { path: explicitPath, strict: false };
  }
  const envPath = process.env.SEGMENTRA_KNOWN_HOSTS;
  if (envPath) {
    ensureDir(path.dirname(envPath));
    return { path: envPath, strict: false };
  }
  const sshDir = path.join(os.homedir(), '.ssh');
  ensureDir(sshDir);
  return { path: path.join(sshDir, 'known_hosts'), strict: false };
}

const USER_RE = /^[A-Za-z0-9._][A-Za-z0-9._-]{0,63}$/;
const HOSTNAME_RE = /^[A-Za-z0-9]([A-Za-z0-9.-]{0,252})$/;

function validateTarget(host: SshTarget): void {
  if (!USER_RE.test(String(host.username ?? ''))) throw new Error(`Invalid SSH username for host ${host.hostname ?? host.ip}`);
  const ip = String(host.ip ?? '');
  if (!isIP(ip) && !HOSTNAME_RE.test(ip)) throw new Error(`Invalid SSH address for host ${host.hostname ?? ip}`);
  const port = Number(host.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error(`Invalid SSH port for host ${host.hostname ?? ip}`);
}

function authMethod(host: SshTarget): 'key' | 'password' {
  return host.authMethod ?? (host.privateKeyPath ? 'key' : host.password ? 'password' : 'key');
}

/** Common -o options + auth options shared by ssh and scp. */
export function buildCommonSshOptions(host: SshTarget, knownHostsPath?: string): string[] {
  validateTarget(host);
  const kh = resolveKnownHosts(knownHostsPath);
  const opts = [
    '-o', `UserKnownHostsFile=${kh.path}`,
    '-o', `StrictHostKeyChecking=${kh.strict ? 'yes' : 'accept-new'}`,
    '-o', 'LogLevel=ERROR',
    '-o', 'ConnectTimeout=15',
    '-o', 'ServerAliveInterval=15',
    '-o', 'ServerAliveCountMax=4'
  ];
  if (authMethod(host) === 'key') {
    if (!host.privateKeyPath) throw new Error(`Missing privateKeyPath for host ${host.hostname ?? host.ip}`);
    opts.push('-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-i', host.privateKeyPath);
  } else {
    if (!host.password) throw new Error(`Missing password for host ${host.hostname ?? host.ip}`);
    opts.push(
      '-o', 'PubkeyAuthentication=no',
      '-o', 'PreferredAuthentications=password,keyboard-interactive'
    );
  }
  return opts;
}

/** Full ssh argv (without the remote command). */
export function buildSshArgs(host: SshTarget, knownHostsPath?: string): string[] {
  return [...buildCommonSshOptions(host, knownHostsPath), '-p', String(host.port), `${host.username}@${host.ip}`];
}

/** scp argv prefix (without source/destination). */
export function buildScpArgs(host: SshTarget, knownHostsPath?: string): string[] {
  return [...buildCommonSshOptions(host, knownHostsPath), '-P', String(host.port)];
}

const SAFE_REMOTE_PATH_RE = /^[A-Za-z0-9_./-]+$/;

/** user@host:path spec for scp. Remote path must be a plain safe path. */
export function scpRemoteSpec(host: SshTarget, remotePath: string): string {
  if (!SAFE_REMOTE_PATH_RE.test(remotePath) || remotePath.split('/').includes('..') || remotePath.startsWith('-')) {
    throw new Error(`Unsafe remote path: ${remotePath}`);
  }
  const addr = isIP(host.ip) === 6 ? `[${host.ip}]` : host.ip;
  return `${host.username}@${addr}:${remotePath}`;
}

/** True if `p` is a plain absolute path made of safe characters (no "..") */
export function isSafeAbsolutePath(p: string): boolean {
  return typeof p === 'string' && p.startsWith('/') && SAFE_REMOTE_PATH_RE.test(p) && !p.split('/').includes('..');
}

/**
 * Spawn a process, collect output, and kill it if it exceeds timeoutMs.
 * Never rejects; spawn errors resolve with exitCode 1.
 */
export function spawnWithTimeout(
  cmd: string,
  args: string[],
  opts: { env?: NodeJS.ProcessEnv; timeoutMs?: number; input?: string } = {}
): Promise<ExecResult> {
  const timeoutMs = opts.timeoutMs ?? defaultTimeout();
  return new Promise((resolve) => {
    let stdout = '';
    let stderr = '';
    let settled = false;
    let timedOut = false;
    const finish = (r: ExecResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (killTimer) clearTimeout(killTimer);
      resolve(r);
    };
    let killTimer: NodeJS.Timeout | undefined;
    const child = spawn(cmd, args, {
      env: opts.env ?? process.env,
      stdio: [opts.input !== undefined ? 'pipe' : 'ignore', 'pipe', 'pipe']
    });
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGTERM');
      killTimer = setTimeout(() => child.kill('SIGKILL'), 5000);
    }, timeoutMs);

    child.stdout?.on('data', (d) => { stdout += d.toString(); });
    child.stderr?.on('data', (d) => { stderr += d.toString(); });
    child.on('error', (err) => finish({ exitCode: 1, stdout, stderr: stderr + err.message, timedOut }));
    child.on('close', (code) => {
      if (timedOut) {
        finish({ exitCode: 124, stdout, stderr: stderr + `\nCommand timed out after ${timeoutMs}ms\n`, timedOut: true });
      } else {
        finish({ exitCode: code ?? 1, stdout, stderr });
      }
    });
    if (opts.input !== undefined && child.stdin) {
      child.stdin.on('error', () => { /* ignore EPIPE */ });
      child.stdin.end(opts.input);
    }
  });
}

/** Wrap a command for password auth (sshpass -e, password passed via env, not argv). */
function withAuth(host: SshTarget, tool: 'ssh' | 'scp', args: string[]): { cmd: string; args: string[]; env: NodeJS.ProcessEnv } {
  if (authMethod(host) === 'password') {
    return { cmd: 'sshpass', args: ['-e', tool, ...args], env: { ...process.env, SSHPASS: host.password ?? '' } };
  }
  const env = { ...process.env };
  delete env.SSHPASS;
  return { cmd: tool, args, env };
}

/**
 * sshpass has a known race with ssh's password prompt (the password can be
 * discarded when ssh flushes the tty), producing a spurious auth failure.
 * Authentication failures mean nothing ran remotely, so retrying once is safe.
 */
async function withPasswordRetry(host: SshTarget, fn: () => Promise<ExecResult>): Promise<ExecResult> {
  const r = await fn();
  if (authMethod(host) === 'password' && r.exitCode === 255 && /Permission denied/i.test(r.stderr) && !r.stdout) {
    await new Promise((res) => setTimeout(res, 500));
    return fn();
  }
  return r;
}

/** Run a remote command over a fresh SSH connection. */
export function runSshCommand(
  host: SshTarget,
  command: string,
  opts: SshConnectionOptions & { input?: string } = {}
): Promise<ExecResult> {
  let args: string[];
  try {
    args = buildSshArgs(host, opts.knownHostsPath);
  } catch (e: any) {
    return Promise.resolve({ exitCode: 1, stdout: '', stderr: e.message });
  }
  const w = withAuth(host, 'ssh', [...args, command]);
  return withPasswordRetry(host, () => spawnWithTimeout(w.cmd, w.args, { env: w.env, timeoutMs: opts.timeoutMs, input: opts.input }));
}

/** Upload a local file to the remote host. */
export function scpUpload(host: SshTarget, localPath: string, remotePath: string, opts: SshConnectionOptions = {}): Promise<ExecResult> {
  let args: string[];
  try {
    args = [...buildScpArgs(host, opts.knownHostsPath), '--', localPath, scpRemoteSpec(host, remotePath)];
  } catch (e: any) {
    return Promise.resolve({ exitCode: 1, stdout: '', stderr: e.message });
  }
  const w = withAuth(host, 'scp', args);
  return withPasswordRetry(host, () => spawnWithTimeout(w.cmd, w.args, { env: w.env, timeoutMs: opts.timeoutMs }));
}

/** Download a remote file to a local path. */
export function scpDownload(host: SshTarget, remotePath: string, localPath: string, opts: SshConnectionOptions = {}): Promise<ExecResult> {
  let args: string[];
  try {
    args = [...buildScpArgs(host, opts.knownHostsPath), '--', scpRemoteSpec(host, remotePath), localPath];
  } catch (e: any) {
    return Promise.resolve({ exitCode: 1, stdout: '', stderr: e.message });
  }
  const w = withAuth(host, 'scp', args);
  return withPasswordRetry(host, () => spawnWithTimeout(w.cmd, w.args, { env: w.env, timeoutMs: opts.timeoutMs }));
}

/** `sudo sh -c '<script>'` with proper quoting. */
export function sudoSh(script: string): string {
  return `sudo -n sh -c ${shq(script)}`;
}
