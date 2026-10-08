import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { pool } from '../db/pool.js';
import { readSecretPlaintext } from './secrets.js';

export type SshSudoMode = 'NOPASSWD' | 'LOGIN_PASSWORD' | 'SUDO_PASSWORD';

/**
 * How root commands are run on the host:
 *  - NOPASSWD: `sudo -n` (passwordless sudo);
 *  - PASSWORD: `sudo -k -S` with `password` on stdin (the login password for LOGIN_PASSWORD
 *    credentials, the separate sudo password for SUDO_PASSWORD credentials).
 */
export type MaterializedSudo = { mode: 'NOPASSWD'; password?: undefined } | { mode: 'PASSWORD'; password: string };

type MaterializedCommon = {
  username: string;
  sudo: MaterializedSudo;
  cleanup: () => void;
};

export type MaterializedSshCredential =
  | (MaterializedCommon & {
      authMethod: 'key';
      /** 0600 temp file with the key exactly as stored (still encrypted when it has a passphrase). */
      privateKeyPath: string;
      /** Key passphrase (decrypted in memory only; handed to ssh via askpass). */
      keyPassphrase?: string;
      password?: undefined;
    })
  | (MaterializedCommon & {
      authMethod: 'password';
      password: string;
      privateKeyPath?: undefined;
      keyPassphrase?: undefined;
    });

/**
 * The SSH auth / privilege escalation fields of a materialized credential, in the shape the
 * executor's host objects (SshHostInfo, SshHost, AuditSshHost, SshTarget) expect. Spread it
 * into the host object: `{ hostname, ip, port, ...sshAuthFields(cred), backend }`.
 */
export function sshAuthFields(cred: MaterializedSshCredential): {
  username: string;
  authMethod: 'key' | 'password';
  privateKeyPath?: string;
  password?: string;
  keyPassphrase?: string;
  sudoPassword?: string;
} {
  return {
    username: cred.username,
    authMethod: cred.authMethod,
    privateKeyPath: cred.authMethod === 'key' ? cred.privateKeyPath : undefined,
    password: cred.authMethod === 'password' ? cred.password : undefined,
    keyPassphrase: cred.authMethod === 'key' ? cred.keyPassphrase : undefined,
    sudoPassword: cred.sudo.mode === 'PASSWORD' ? cred.sudo.password : undefined
  };
}

/**
 * Load the SSH credential to use for a host. A HOST-scoped credential wins over
 * the newest GLOBAL credential. Returns null when no credential is configured.
 */
export async function loadSshCredential(hostId?: string | null): Promise<any | null> {
  if (hostId) {
    const hostRes = await pool.query(
      `SELECT * FROM ssh_credentials WHERE scope_type='HOST' AND scope_id=$1 ORDER BY created_at DESC LIMIT 1`,
      [hostId]
    );
    if (hostRes.rows[0]) return hostRes.rows[0];
  }
  const globalRes = await pool.query(
    `SELECT * FROM ssh_credentials WHERE scope_type='GLOBAL' ORDER BY created_at DESC LIMIT 1`
  );
  return globalRes.rows[0] ?? null;
}

async function readText(secretId: string): Promise<string> {
  return (await readSecretPlaintext(secretId)).toString('utf8');
}

/** Resolve the credential's sudo mode (login password is only available for PASSWORD auth). */
async function materializeSudo(cred: any, loginPassword: string | undefined): Promise<MaterializedSudo> {
  const mode = String(cred.sudo_mode ?? 'NOPASSWD').toUpperCase() as SshSudoMode;
  if (mode === 'LOGIN_PASSWORD') {
    if (loginPassword === undefined) throw new Error('sudo_login_password_requires_password_auth');
    return { mode: 'PASSWORD', password: loginPassword };
  }
  if (mode === 'SUDO_PASSWORD') {
    if (!cred.sudo_password_secret_id) throw new Error('missing_sudo_password_secret');
    return { mode: 'PASSWORD', password: await readText(cred.sudo_password_secret_id) };
  }
  return { mode: 'NOPASSWD' };
}

/**
 * Decrypt a credential row into something the executor can use. Key credentials are
 * written (as stored, i.e. still encrypted if they have a passphrase) to a 0600 temp file;
 * passwords, the key passphrase and the sudo password stay in memory. Always call
 * cleanup() in a finally block.
 */
export async function materializeSshCredential(cred: any, dir?: string): Promise<MaterializedSshCredential> {
  const authMethod = String(cred.auth_method ?? 'KEY').toUpperCase();

  if (authMethod === 'PASSWORD') {
    if (!cred.password_secret_id) throw new Error('missing_ssh_password_secret');
    const password = await readText(cred.password_secret_id);
    const sudo = await materializeSudo(cred, password);
    return { authMethod: 'password', username: cred.username, password, sudo, cleanup: () => {} };
  }

  if (!cred.private_key_secret_id) throw new Error('missing_ssh_private_key_secret');
  const keyPem = await readText(cred.private_key_secret_id);
  const keyPassphrase = cred.passphrase_secret_id ? await readText(cred.passphrase_secret_id) : undefined;
  const sudo = await materializeSudo(cred, undefined);
  const keyDir = dir ?? fs.mkdtempSync(path.join(os.tmpdir(), 'segmentra-key-'));
  const keyPath = path.join(keyDir, `ssh_key_${cred.id ?? 'cred'}_${process.pid}_${Date.now()}`);
  fs.writeFileSync(keyPath, keyPem.endsWith('\n') ? keyPem : `${keyPem}\n`, { encoding: 'utf8', mode: 0o600 });

  return {
    authMethod: 'key',
    username: cred.username,
    privateKeyPath: keyPath,
    keyPassphrase: keyPassphrase || undefined,
    sudo,
    cleanup: () => {
      try {
        if (fs.existsSync(keyPath)) fs.unlinkSync(keyPath);
        if (!dir) fs.rmSync(keyDir, { recursive: true, force: true });
      } catch {
        // Best-effort cleanup.
      }
    }
  };
}

/** Convenience: load + materialize, or throw missing_ssh_credential. */
export async function getSshCredentialForHost(hostId?: string | null, dir?: string): Promise<MaterializedSshCredential> {
  const cred = await loadSshCredential(hostId);
  if (!cred) throw new Error('missing_ssh_credential');
  return materializeSshCredential(cred, dir);
}
