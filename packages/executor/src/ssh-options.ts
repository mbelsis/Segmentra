/**
 * Shared SSH/SCP helpers: option building (host key verification, timeouts,
 * key or password auth), shell quoting, child-process execution with an overall
 * timeout, and privilege escalation (sudo with or without a password).
 *
 * Secrets never appear in argv or on disk:
 *  - login password: `sshpass -e` (SSHPASS in the child's environment);
 *  - key passphrase: OpenSSH askpass (SSH_ASKPASS=<helper>, SSH_ASKPASS_REQUIRE=force);
 *    the helper prints SEGMENTRA_ASKPASS_SECRET from the child's environment, so the
 *    key file on disk stays encrypted and the decrypted key only exists inside ssh;
 *  - sudo password: first line of the remote command's stdin, read by `sudo -S`.
 * Every secret of the target is scrubbed from the stdout/stderr returned to callers.
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
  /** Passphrase of the private key (key auth only). Undefined = unencrypted key (BatchMode). */
  keyPassphrase?: string;
  /**
   * sudo password. Undefined = passwordless sudo (`sudo -n`, the historical behaviour).
   * When set, root commands run as `sudo -k -S -p '' sh -c ...` with the password on stdin.
   */
  sudoPassword?: string;
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
  /** Set by runSshSudo when sudo itself refused to run the command (see SudoErrorKind). */
  sudoError?: SudoErrorKind;
}

/**
 * Why sudo refused to run a command:
 *  - password_required: passwordless sudo was used, but the host asks for a password;
 *  - wrong_password:    the configured sudo password was rejected;
 *  - tty_required:      sudoers has `Defaults requiretty` for this account;
 *  - not_permitted:     the account may not run `sh` as root via sudo.
 */
export type SudoErrorKind = 'password_required' | 'wrong_password' | 'tty_required' | 'not_permitted';

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
    if (host.keyPassphrase !== undefined && host.keyPassphrase !== '') {
      // BatchMode=yes would disable the passphrase prompt (and so askpass). Instead allow
      // public-key auth only, so the askpass helper is never asked for anything but the
      // key passphrase, and give up after one wrong passphrase.
      opts.push(
        '-o', 'IdentitiesOnly=yes',
        '-o', 'PreferredAuthentications=publickey',
        '-o', 'PasswordAuthentication=no',
        '-o', 'KbdInteractiveAuthentication=no',
        '-o', 'NumberOfPasswordPrompts=1',
        '-i', host.privateKeyPath
      );
    } else {
      opts.push('-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-i', host.privateKeyPath);
    }
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
  opts: { env?: NodeJS.ProcessEnv; timeoutMs?: number; input?: string; detached?: boolean } = {}
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
      stdio: [opts.input !== undefined ? 'pipe' : 'ignore', 'pipe', 'pipe'],
      // New session without a controlling terminal: OpenSSH < 8.4 (no SSH_ASKPASS_REQUIRE)
      // then uses SSH_ASKPASS instead of /dev/tty for the key passphrase.
      detached: opts.detached ?? false
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

const ASKPASS_SECRET_ENV = 'SEGMENTRA_ASKPASS_SECRET';
const ASKPASS_SCRIPT = [
  '#!/bin/sh',
  '# Segmentra SSH_ASKPASS helper: answers key passphrase prompts only, with the secret',
  '# passed in the environment of the ssh/scp/ssh-keygen child process. Contains no secret.',
  'case "$1" in',
  `  *assphrase*) printf '%s\\n' "$${ASKPASS_SECRET_ENV}" ;;`,
  '  *) exit 1 ;;',
  'esac',
  ''
].join('\n');
let askpassPath: string | null = null;

/**
 * Path of the askpass helper script (created once per process in a private 0700
 * directory under SEGMENTRA_ASKPASS_DIR or the OS temp dir). It never contains a secret.
 */
export function askpassHelperPath(): string {
  if (askpassPath && fs.existsSync(askpassPath)) return askpassPath;
  const base = process.env.SEGMENTRA_ASKPASS_DIR || os.tmpdir();
  ensureDir(base);
  const dir = fs.mkdtempSync(path.join(base, 'segmentra-askpass-'));
  fs.chmodSync(dir, 0o700);
  const p = path.join(dir, 'askpass.sh');
  fs.writeFileSync(p, ASKPASS_SCRIPT, { mode: 0o700 });
  fs.chmodSync(p, 0o700);
  askpassPath = p;
  process.once('exit', () => {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
  });
  return p;
}

/** Environment for a child that must decrypt a key with `passphrase` through askpass. */
export function askpassEnv(passphrase: string, base: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...base };
  delete env.SSHPASS;
  env.SSH_ASKPASS = askpassHelperPath();
  env.SSH_ASKPASS_REQUIRE = 'force';
  // OpenSSH < 8.4 only uses SSH_ASKPASS when DISPLAY is set and there is no tty.
  if (!env.DISPLAY) env.DISPLAY = 'segmentra:0';
  env[ASKPASS_SECRET_ENV] = passphrase;
  return env;
}

function usesAskpass(host: SshTarget): boolean {
  return authMethod(host) === 'key' && host.keyPassphrase !== undefined && host.keyPassphrase !== '';
}

/**
 * Wrap a command for the configured auth: password auth via sshpass -e (password in the
 * env, not argv); passphrase-protected keys via askpass (passphrase in the env).
 */
function withAuth(host: SshTarget, tool: 'ssh' | 'scp', args: string[]): { cmd: string; args: string[]; env: NodeJS.ProcessEnv; detached: boolean } {
  if (authMethod(host) === 'password') {
    const env: NodeJS.ProcessEnv = { ...process.env, SSHPASS: host.password ?? '' };
    delete env[ASKPASS_SECRET_ENV];
    return { cmd: 'sshpass', args: ['-e', tool, ...args], env, detached: false };
  }
  if (usesAskpass(host)) {
    return { cmd: tool, args, env: askpassEnv(host.keyPassphrase!), detached: true };
  }
  const env = { ...process.env };
  delete env.SSHPASS;
  delete env[ASKPASS_SECRET_ENV];
  return { cmd: tool, args, env, detached: false };
}

/** Replace every secret of `host` in `text` (output returned to callers / stored in logs). */
export function scrubSecrets(host: SshTarget, text: string): string {
  let out = text;
  for (const secret of [host.sudoPassword, host.password, host.keyPassphrase]) {
    if (secret && secret.length >= 3 && out.includes(secret)) out = out.split(secret).join('********');
  }
  return out;
}

function scrubResult(host: SshTarget, r: ExecResult): ExecResult {
  return { ...r, stdout: scrubSecrets(host, r.stdout), stderr: scrubSecrets(host, r.stderr) };
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
  // Non-root login shells on Debian-family hosts don't have the sbin directories in PATH, so
  // `command -v nft` / `iptables` lookups would fail even though the tools are installed.
  // (Commands run through sudo use sudo's secure_path and are unaffected.)
  const remoteCommand = `${REMOTE_PATH_PREFIX}${command}`;
  const w = withAuth(host, 'ssh', [...args, remoteCommand]);
  return withPasswordRetry(host, () =>
    spawnWithTimeout(w.cmd, w.args, { env: w.env, timeoutMs: opts.timeoutMs, input: opts.input, detached: w.detached })
  ).then((r) => scrubResult(host, r));
}

/** Prepended to every remote command: make the standard admin tool directories available. */
export const REMOTE_PATH_PREFIX = 'PATH="$PATH:/usr/local/sbin:/usr/sbin:/sbin"; export PATH; ';

/** Upload a local file to the remote host. */
export function scpUpload(host: SshTarget, localPath: string, remotePath: string, opts: SshConnectionOptions = {}): Promise<ExecResult> {
  let args: string[];
  try {
    args = [...buildScpArgs(host, opts.knownHostsPath), '--', localPath, scpRemoteSpec(host, remotePath)];
  } catch (e: any) {
    return Promise.resolve({ exitCode: 1, stdout: '', stderr: e.message });
  }
  const w = withAuth(host, 'scp', args);
  return withPasswordRetry(host, () =>
    spawnWithTimeout(w.cmd, w.args, { env: w.env, timeoutMs: opts.timeoutMs, detached: w.detached })
  ).then((r) => scrubResult(host, r));
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
  return withPasswordRetry(host, () =>
    spawnWithTimeout(w.cmd, w.args, { env: w.env, timeoutMs: opts.timeoutMs, detached: w.detached })
  ).then((r) => scrubResult(host, r));
}

/**
 * `sudo -n sh -c '<script>'` (passwordless sudo) with proper quoting. Kept for callers that
 * build commands without a target; anything executed on a target should use runSshSudo,
 * which honours the target's sudo password.
 */
export function sudoSh(script: string): string {
  return `sudo -n sh -c ${shq(script)}`;
}

/** True when root commands on `host` need the sudo password (SshTarget.sudoPassword set). */
export function usesSudoPassword(host: Pick<SshTarget, 'sudoPassword'>): boolean {
  return host.sudoPassword !== undefined && host.sudoPassword !== null;
}

/**
 * Remote command running `script` as root through sudo, honouring the host's sudo mode:
 *  - passwordless: `sudo -n sh -c '<script>' [args]`
 *  - password:     `sudo -k -S -p '' sh -c '<script>' [args]` — the password is the first
 *    line of stdin (see runSshSudo). -k makes sudo ignore cached credentials, so it ALWAYS
 *    reads that line and it can never reach the script's stdin; `-p ''` keeps the prompt out
 *    of the output.
 * `args` are raw shell words appended after the script (e.g. `segmentra "$HOME"` to pass
 * $1 = the SSH user's home directory, expanded by the user's shell before sudo).
 * Unless `keepStdin` is set the root script starts with `exec </dev/null`, so even on a host
 * where sudo did not ask for the password (NOPASSWD), the password line is discarded.
 */
export function sudoCommand(host: Pick<SshTarget, 'sudoPassword'>, script: string, opts: { args?: string[]; keepStdin?: boolean } = {}): string {
  const body = opts.keepStdin ? script : `exec </dev/null\n${script}`;
  const tail = opts.args?.length ? ` ${opts.args.join(' ')}` : '';
  return usesSudoPassword(host)
    ? `sudo -k -S -p '' sh -c ${shq(body)}${tail}`
    : `sudo -n sh -c ${shq(body)}${tail}`;
}

/**
 * Classify sudo refusals from a command's output. Only sudo's own messages are matched
 * (lines starting with "sudo:" or sudo's "Sorry, try again."), not the script's output.
 */
export function classifySudoError(stderr: string, passwordMode: boolean): SudoErrorKind | undefined {
  const text = stderr.toLowerCase();
  if (/sudo: (sorry, )?(a terminal is required|you must have a tty|no tty present)/.test(text)) return 'tty_required';
  if (/sudo: \d+ incorrect password attempts?|sorry, try again\.|sudo: incorrect password|sudo: no password was provided/.test(text)) {
    return passwordMode ? 'wrong_password' : 'password_required';
  }
  if (/sudo: a password is required/.test(text)) return passwordMode ? 'wrong_password' : 'password_required';
  if (/is not in the sudoers file|is not allowed to execute|may not run sudo|sudo: .*not allowed to run sudo/.test(text)) return 'not_permitted';
  return undefined;
}

/** Human-readable explanation of a sudo refusal (appended to stderr by runSshSudo). */
export function sudoErrorMessage(kind: SudoErrorKind, username: string): string {
  switch (kind) {
    case 'password_required':
      return `Error: sudo on this host requires a password for "${username}", but the SSH credential is set to "sudo without password". Set the credential's privilege escalation to "sudo with the login password" or "sudo with a separate password", or allow passwordless sudo for this account.`;
    case 'wrong_password':
      return `Error: sudo rejected the configured sudo password for "${username}" (incorrect password). Update the SSH credential's sudo password.`;
    case 'tty_required':
      return `Error: sudo on this host requires a terminal (sudoers "Defaults requiretty"). Disable it for the Segmentra account, e.g. add "Defaults:${username} !requiretty" to a file in /etc/sudoers.d/.`;
    case 'not_permitted':
      return `Error: "${username}" is not allowed to run "sh" as root via sudo. Segmentra needs full sudo rights (ALL) for this account, with or without a password.`;
  }
}

/**
 * Run `script` as root on `host` through sudo (see sudoCommand). With a sudo password the
 * password is written as the first line of the child's stdin, followed by `opts.input` (then
 * set keepStdin to let the script read it). Sudo refusals are reported in `sudoError` and
 * explained on the last stderr line; the password never appears in argv or in the output.
 */
export async function runSshSudo(
  host: SshTarget,
  script: string,
  opts: SshConnectionOptions & { input?: string; args?: string[]; keepStdin?: boolean } = {}
): Promise<ExecResult> {
  const passwordMode = usesSudoPassword(host);
  const input = passwordMode ? `${host.sudoPassword}\n${opts.input ?? ''}` : opts.input;
  const command = sudoCommand(host, script, { args: opts.args, keepStdin: opts.keepStdin ?? opts.input !== undefined });
  const r = await runSshCommand(host, command, { knownHostsPath: opts.knownHostsPath, timeoutMs: opts.timeoutMs, input });
  if (r.exitCode === 0 || r.exitCode === 255 || r.timedOut) return r;
  const kind = classifySudoError(r.stderr, passwordMode);
  if (!kind) return r;
  return { ...r, sudoError: kind, stderr: `${r.stderr.replace(/\s*$/, '')}\n${sudoErrorMessage(kind, host.username)}\n` };
}

export interface PrivateKeyCheck {
  ok: boolean;
  /** True when the key is encrypted (needs a passphrase). */
  encrypted?: boolean;
  /** OpenSSH public key derived from the private key (on success). */
  publicKey?: string;
  /** 'invalid_key' (not a private key ssh can read) | 'passphrase_required' | 'wrong_passphrase'. */
  error?: 'invalid_key' | 'passphrase_required' | 'wrong_passphrase';
}

/**
 * Check that `pem` is a private key OpenSSH can load and, for an encrypted key, that
 * `passphrase` decrypts it (`ssh-keygen -y`). The (still encrypted) key is written to a 0600
 * file in a private temp dir that is removed afterwards; the passphrase is handed to
 * ssh-keygen through askpass (environment), never argv.
 */
export async function checkPrivateKey(pem: string, passphrase?: string): Promise<PrivateKeyCheck> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'segmentra-keycheck-'));
  const file = path.join(dir, 'key');
  try {
    fs.writeFileSync(file, pem.endsWith('\n') ? pem : `${pem}\n`, { mode: 0o600 });
    const plainEnv: NodeJS.ProcessEnv = { ...process.env };
    for (const k of ['SSH_ASKPASS', 'SSH_ASKPASS_REQUIRE', ASKPASS_SECRET_ENV, 'SSHPASS']) delete plainEnv[k];
    const plain = await spawnWithTimeout('ssh-keygen', ['-y', '-f', file], { env: plainEnv, timeoutMs: 15_000, detached: true });
    if (plain.exitCode === 0) return { ok: true, encrypted: false, publicKey: plain.stdout.trim() };
    const msg = plain.stderr.toLowerCase();
    if (!/passphrase|incorrect|bad decrypt|decrypt/.test(msg)) return { ok: false, error: 'invalid_key' };
    if (!passphrase) return { ok: false, encrypted: true, error: 'passphrase_required' };
    const r = await spawnWithTimeout('ssh-keygen', ['-y', '-f', file], { env: askpassEnv(passphrase), timeoutMs: 15_000, detached: true });
    if (r.exitCode === 0) return { ok: true, encrypted: true, publicKey: r.stdout.trim() };
    return { ok: false, encrypted: true, error: 'wrong_passphrase' };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}
