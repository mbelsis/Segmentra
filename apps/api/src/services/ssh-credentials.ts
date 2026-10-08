import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { pool } from '../db/pool.js';
import { readSecretPlaintext } from './secrets.js';

export type MaterializedSshCredential =
  | { authMethod: 'key'; username: string; privateKeyPath: string; password?: undefined; cleanup: () => void }
  | { authMethod: 'password'; username: string; password: string; privateKeyPath?: undefined; cleanup: () => void };

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

/**
 * Decrypt a credential row into something the executor can use. Key credentials are
 * written to a 0600 temp file; always call cleanup() in a finally block.
 */
export async function materializeSshCredential(cred: any, dir?: string): Promise<MaterializedSshCredential> {
  const authMethod = String(cred.auth_method ?? 'KEY').toUpperCase();

  if (authMethod === 'PASSWORD') {
    if (!cred.password_secret_id) throw new Error('missing_ssh_password_secret');
    const password = (await readSecretPlaintext(cred.password_secret_id)).toString('utf8');
    return { authMethod: 'password', username: cred.username, password, cleanup: () => {} };
  }

  if (!cred.private_key_secret_id) throw new Error('missing_ssh_private_key_secret');
  const keyPem = (await readSecretPlaintext(cred.private_key_secret_id)).toString('utf8');
  const keyDir = dir ?? fs.mkdtempSync(path.join(os.tmpdir(), 'segmentra-key-'));
  const keyPath = path.join(keyDir, `ssh_key_${cred.id ?? 'cred'}_${process.pid}_${Date.now()}`);
  fs.writeFileSync(keyPath, keyPem, { encoding: 'utf8', mode: 0o600 });

  return {
    authMethod: 'key',
    username: cred.username,
    privateKeyPath: keyPath,
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
