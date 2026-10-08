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

export type CredentialResolvedVia = 'ASSIGNED' | 'HOST' | 'TAG' | 'VLAN' | 'GLOBAL';

/**
 * LATERAL subquery picking the effective credential for the host row aliased `h`.
 * Order: explicit assignment (hosts.ssh_credential_id) -> HOST -> TAG (any tag of the host)
 * -> VLAN (the host's VLAN) -> GLOBAL; within a level the highest priority, then the newest.
 * NONE-scoped credentials are only reachable through an explicit assignment.
 * Columns: cred_id, resolved_via, resolved_scope_name (tag name / "VLAN <tag> (<name>)").
 */
export const EFFECTIVE_CREDENTIAL_LATERAL = `
  SELECT x.cred_id, x.via AS resolved_via, x.scope_name AS resolved_scope_name
    FROM (
      SELECT h.ssh_credential_id AS cred_id, 0 AS rank, 'ASSIGNED'::text AS via, NULL::text AS scope_name
       WHERE h.ssh_credential_id IS NOT NULL
      UNION ALL
      SELECT c.id, 1, 'HOST', NULL FROM ssh_credentials c WHERE c.scope_type = 'HOST' AND c.scope_id = h.id
      UNION ALL
      SELECT c.id, 2, 'TAG', t.name
        FROM host_tags ht
        JOIN tags t ON t.id = ht.tag_id
        JOIN ssh_credentials c ON c.scope_type = 'TAG' AND c.scope_id = ht.tag_id
       WHERE ht.host_id = h.id
      UNION ALL
      SELECT c.id, 3, 'VLAN', 'VLAN ' || v.vlan_tag || ' (' || v.name || ')'
        FROM ssh_credentials c JOIN vlans v ON v.id = c.scope_id
       WHERE c.scope_type = 'VLAN' AND c.scope_id = h.vlan_id
      UNION ALL
      SELECT c.id, 4, 'GLOBAL', NULL FROM ssh_credentials c WHERE c.scope_type = 'GLOBAL'
    ) x
    JOIN ssh_credentials rc ON rc.id = x.cred_id
   ORDER BY x.rank, rc.priority DESC, rc.created_at DESC, rc.id
   LIMIT 1`;

/** Non-secret summary of the credential a host would use (safe for every role). */
export type EffectiveCredential = {
  id: string;
  name: string;
  authMethod: string;
  sudoMode: string;
  scopeType: string;
  /** Why it was chosen: explicit assignment or the scope level that matched. */
  via: CredentialResolvedVia;
  /** Tag name or "VLAN <tag> (<name>)" for TAG/VLAN matches. */
  scopeName: string | null;
};

/** Effective credential per host id, in one query. Hosts without any usable credential are absent. */
export async function effectiveCredentialsForHosts(hostIds: string[]): Promise<Map<string, EffectiveCredential>> {
  const out = new Map<string, EffectiveCredential>();
  if (hostIds.length === 0) return out;
  const { rows } = await pool.query(
    `SELECT h.id AS host_id, c.id, c.name, c.auth_method, c.sudo_mode, c.scope_type, ec.resolved_via, ec.resolved_scope_name
       FROM hosts h
       CROSS JOIN LATERAL (${EFFECTIVE_CREDENTIAL_LATERAL}) ec
       JOIN ssh_credentials c ON c.id = ec.cred_id
      WHERE h.id = ANY($1::uuid[])`,
    [hostIds]
  );
  for (const r of rows) {
    out.set(String(r.host_id), {
      id: String(r.id),
      name: r.name,
      authMethod: r.auth_method,
      sudoMode: r.sudo_mode ?? 'NOPASSWD',
      scopeType: r.scope_type,
      via: r.resolved_via,
      scopeName: r.resolved_scope_name ?? null
    });
  }
  return out;
}

/**
 * Load the SSH credential row to use for a host (see EFFECTIVE_CREDENTIAL_LATERAL for the
 * order). Without a host id only GLOBAL credentials are considered. The row carries two extra
 * columns, resolved_via and resolved_scope_name. Returns null when nothing applies.
 */
export async function loadSshCredential(hostId?: string | null): Promise<any | null> {
  if (hostId) {
    const { rows } = await pool.query(
      `SELECT c.*, ec.resolved_via, ec.resolved_scope_name
         FROM hosts h
         CROSS JOIN LATERAL (${EFFECTIVE_CREDENTIAL_LATERAL}) ec
         JOIN ssh_credentials c ON c.id = ec.cred_id
        WHERE h.id = $1`,
      [hostId]
    );
    if (rows[0]) return rows[0];
    // Unknown host id: fall through to the global default (previous behaviour).
    const { rows: known } = await pool.query(`SELECT 1 FROM hosts WHERE id = $1`, [hostId]);
    if (known[0]) return null;
  }
  const globalRes = await pool.query(
    `SELECT *, 'GLOBAL'::text AS resolved_via, NULL::text AS resolved_scope_name
       FROM ssh_credentials WHERE scope_type='GLOBAL' ORDER BY priority DESC, created_at DESC, id LIMIT 1`
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
