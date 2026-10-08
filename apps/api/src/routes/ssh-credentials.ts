import { Router } from 'express';
import { z } from 'zod';
import { checkPrivateKey, type PrivateKeyCheck } from '@segmentra/executor';

import { pool } from '../db/pool.js';
import { requireAuth, requireRole } from '../middleware/auth.js';
import { createSecret, readSecretPlaintext } from '../services/secrets.js';

export const sshCredentialsRouter = Router();
sshCredentialsRouter.use(requireAuth, requireRole('admin'));

/**
 * Public view of a credential row: secret ids are replaced by booleans so no secret material
 * (or handle to it) leaves the API. scope_name is the tag name, "VLAN <tag> (<name>)" or the
 * hostname the credential is scoped to (NULL when that object no longer exists).
 */
const PUBLIC_SELECT = `SELECT c.id, c.name, c.username, c.auth_method, c.sudo_mode, c.scope_type, c.scope_id, c.priority, c.created_at,
  (c.passphrase_secret_id IS NOT NULL) AS has_passphrase,
  (c.sudo_password_secret_id IS NOT NULL) AS has_sudo_password,
  CASE c.scope_type
    WHEN 'TAG' THEN (SELECT t.name FROM tags t WHERE t.id = c.scope_id)
    WHEN 'VLAN' THEN (SELECT 'VLAN ' || v.vlan_tag || ' (' || v.name || ')' FROM vlans v WHERE v.id = c.scope_id)
    WHEN 'HOST' THEN (SELECT h.hostname FROM hosts h WHERE h.id = c.scope_id)
  END AS scope_name,
  (SELECT count(*)::int FROM hosts h WHERE h.ssh_credential_id = c.id) AS assigned_host_count,
  (SELECT count(*)::int FROM discovery_targets dt WHERE dt.ssh_credential_id = c.id) AS discovery_target_count
  FROM ssh_credentials c`;

async function publicRow(id: string) {
  const { rows } = await pool.query(`${PUBLIC_SELECT} WHERE c.id=$1`, [id]);
  return rows[0];
}

sshCredentialsRouter.get('/', async (_req, res) => {
  const { rows } = await pool.query(`${PUBLIC_SELECT} ORDER BY c.created_at DESC`);
  res.json({ sshCredentials: rows });
});

/**
 * Remove secrets that no credential row references any more (best effort: a secret still
 * referenced elsewhere is kept). Works on a pool or a client inside a transaction.
 */
async function deleteUnreferencedSecrets(db: { query: (...args: any[]) => Promise<any> }, ids: Array<string | null | undefined>, inTransaction: boolean) {
  for (const sid of [...new Set(ids.filter(Boolean) as string[])]) {
    const { rows: shared } = await db.query(
      `SELECT 1 FROM ssh_credentials
        WHERE private_key_secret_id = $1 OR passphrase_secret_id = $1 OR password_secret_id = $1 OR sudo_password_secret_id = $1
        LIMIT 1`,
      [sid]
    );
    if (shared[0]) continue;
    if (inTransaction) await db.query('SAVEPOINT del_secret');
    try {
      await db.query(`DELETE FROM secret_store WHERE id = $1`, [sid]);
    } catch {
      if (inTransaction) await db.query('ROLLBACK TO SAVEPOINT del_secret');
    }
  }
}

const scopeTypeSchema = z.enum(['GLOBAL', 'TAG', 'VLAN', 'HOST', 'NONE']);
type ScopeType = z.infer<typeof scopeTypeSchema>;

/**
 * Validate a scope: TAG/VLAN/HOST need an existing tag/VLAN/host id, GLOBAL/NONE take none.
 * Returns the normalised scope id or an error body.
 */
async function checkScope(scopeType: ScopeType, scopeId: string | null | undefined): Promise<{ scopeId: string | null } | { error: string; message: string }> {
  if (scopeType === 'GLOBAL' || scopeType === 'NONE') return { scopeId: null };
  if (!scopeId) return { error: 'scope_id_required', message: `Choose the ${scopeType.toLowerCase()} this credential applies to.` };
  const table = scopeType === 'TAG' ? 'tags' : scopeType === 'VLAN' ? 'vlans' : 'hosts';
  const { rows } = await pool.query(`SELECT 1 FROM ${table} WHERE id = $1`, [scopeId]);
  if (!rows[0]) return { error: 'scope_not_found', message: `The selected ${scopeType.toLowerCase()} does not exist.` };
  return { scopeId };
}

const sudoModeSchema = z.enum(['NOPASSWD', 'LOGIN_PASSWORD', 'SUDO_PASSWORD']);

const baseCredentialSchema = z.object({
  name: z.string().min(1),
  username: z.string().min(1),
  scopeType: scopeTypeSchema.default('GLOBAL'),
  scopeId: z.string().uuid().optional().nullable(),
  priority: z.number().int().min(-1000).max(1000).default(0),
  sudoMode: sudoModeSchema.default('NOPASSWD'),
  sudoPassword: z.string().min(1).max(1024).optional()
});

const keyCredentialSchema = baseCredentialSchema.extend({
  authMethod: z.literal('KEY').default('KEY'),
  privateKeyPem: z.string().min(1),
  passphrase: z.string().max(1024).optional()
});

const passwordCredentialSchema = baseCredentialSchema.extend({
  authMethod: z.literal('PASSWORD'),
  password: z.string().min(1)
});

const createSchema = z.union([keyCredentialSchema, passwordCredentialSchema]);

/** Secrets containing a line break cannot be fed to sudo -S / askpass line by line. */
function hasLineBreak(v?: string | null): boolean {
  return typeof v === 'string' && /[\r\n]/.test(v);
}

/** Validate the auth method / sudo mode combination. Returns an error body or null. */
function sudoModeProblem(authMethod: string, sudoMode: string, hasSudoPassword: boolean): { error: string; message: string } | null {
  if (sudoMode === 'LOGIN_PASSWORD' && authMethod !== 'PASSWORD') {
    return { error: 'invalid_sudo_mode', message: '"sudo with the login password" requires password authentication; use "sudo with a separate password" for key credentials.' };
  }
  if (sudoMode === 'SUDO_PASSWORD' && !hasSudoPassword) {
    return { error: 'sudo_password_required', message: 'A sudo password is required for "sudo with a separate password".' };
  }
  return null;
}

function keyProblem(check: PrivateKeyCheck): { error: string; message: string } | null {
  if (check.ok) return null;
  const message =
    check.error === 'passphrase_required'
      ? 'The private key is encrypted: enter its passphrase.'
      : check.error === 'wrong_passphrase'
        ? 'The passphrase does not decrypt this private key.'
        : 'The private key could not be read (paste the full OpenSSH or PEM private key, including the BEGIN/END lines).';
  return { error: 'invalid_key_or_passphrase', message };
}

sshCredentialsRouter.post('/', async (req, res) => {
  const parsed = createSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });
  const b = parsed.data;

  if (hasLineBreak(b.sudoPassword) || (b.authMethod === 'KEY' && hasLineBreak(b.passphrase)) || (b.authMethod === 'PASSWORD' && b.sudoMode === 'LOGIN_PASSWORD' && hasLineBreak(b.password))) {
    return res.status(400).json({ error: 'invalid_body', message: 'Passwords and passphrases must not contain line breaks.' });
  }
  const modeProblem = sudoModeProblem(b.authMethod, b.sudoMode, !!b.sudoPassword);
  if (modeProblem) return res.status(400).json(modeProblem);
  const scope = await checkScope(b.scopeType, b.scopeId);
  if ('error' in scope) return res.status(400).json(scope);

  // Validate the key (and passphrase) before storing anything.
  let passphrase: string | undefined;
  if (b.authMethod === 'KEY') {
    const check = await checkPrivateKey(b.privateKeyPem.trim(), b.passphrase || undefined);
    const problem = keyProblem(check);
    if (problem) return res.status(400).json(problem);
    // A passphrase for an unencrypted key is not needed (and would only disable BatchMode).
    passphrase = check.encrypted ? b.passphrase : undefined;
  }

  const keySecret = b.authMethod === 'KEY'
    ? await createSecret({ name: `${b.name}_key`, type: 'SSH_KEY', plaintext: Buffer.from(b.privateKeyPem, 'utf8') })
    : null;
  const passphraseSecret = passphrase
    ? await createSecret({ name: `${b.name}_passphrase`, type: 'SSH_KEY_PASSPHRASE', plaintext: Buffer.from(passphrase, 'utf8') })
    : null;
  const passwordSecret = b.authMethod === 'PASSWORD'
    ? await createSecret({ name: `${b.name}_password`, type: 'SSH_PASSWORD', plaintext: Buffer.from(b.password, 'utf8') })
    : null;
  const sudoSecret = b.sudoMode === 'SUDO_PASSWORD' && b.sudoPassword
    ? await createSecret({ name: `${b.name}_sudo_password`, type: 'SUDO_PASSWORD', plaintext: Buffer.from(b.sudoPassword, 'utf8') })
    : null;

  const { rows } = await pool.query(
    `INSERT INTO ssh_credentials
      (name, username, auth_method, private_key_secret_id, passphrase_secret_id, password_secret_id,
       sudo_mode, sudo_password_secret_id, scope_type, scope_id, priority)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
     RETURNING id`,
    [b.name, b.username, b.authMethod, keySecret?.id ?? null, passphraseSecret?.id ?? null, passwordSecret?.id ?? null,
      b.sudoMode, sudoSecret?.id ?? null, b.scopeType, scope.scopeId, b.priority]
  );
  await pool.query(
    `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), $2, $3, $4, $5)`,
    [req.auth!.username, 'SSH_CREDENTIAL_CREATE', 'ssh_credential', rows[0].id, JSON.stringify({
      name: b.name, username: b.username, scopeType: b.scopeType, scopeId: scope.scopeId, priority: b.priority,
      authMethod: b.authMethod, sudoMode: b.sudoMode, hasPassphrase: !!passphraseSecret
    })]
  );

  res.status(201).json({ sshCredential: await publicRow(rows[0].id) });
});

const updateSchema = z.object({
  name: z.string().min(1).optional(),
  username: z.string().min(1).optional(),
  /** Changing the scope: send scopeType (+ scopeId for TAG/VLAN/HOST). scopeId alone keeps the type. */
  scopeType: scopeTypeSchema.optional(),
  scopeId: z.string().uuid().optional().nullable(),
  priority: z.number().int().min(-1000).max(1000).optional(),
  sudoMode: sudoModeSchema.optional(),
  /** New sudo password (SUDO_PASSWORD mode). Omit to keep the stored one. */
  sudoPassword: z.string().min(1).max(1024).optional(),
  /** PASSWORD credentials: new login password. Omit to keep the stored one. */
  password: z.string().min(1).max(1024).optional(),
  /** KEY credentials: new key passphrase; null or '' removes it (only for an unencrypted key). */
  passphrase: z.string().max(1024).nullable().optional()
});

sshCredentialsRouter.put('/:id', async (req, res) => {
  const parsed = updateSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });
  const b = parsed.data;
  if (!z.string().uuid().safeParse(req.params.id).success) return res.status(404).json({ error: 'not_found' });

  const { rows: existingRows } = await pool.query(`SELECT * FROM ssh_credentials WHERE id=$1`, [req.params.id]);
  const cur = existingRows[0];
  if (!cur) return res.status(404).json({ error: 'not_found' });
  const authMethod = String(cur.auth_method ?? 'KEY').toUpperCase();

  if (b.password !== undefined && authMethod !== 'PASSWORD') {
    return res.status(400).json({ error: 'invalid_body', message: 'A login password only applies to password credentials (add a new credential to replace a key).' });
  }
  if (hasLineBreak(b.sudoPassword) || hasLineBreak(b.passphrase) || hasLineBreak(b.password)) {
    return res.status(400).json({ error: 'invalid_body', message: 'Passwords and passphrases must not contain line breaks.' });
  }
  if (b.passphrase !== undefined && authMethod !== 'KEY') {
    return res.status(400).json({ error: 'invalid_body', message: 'A key passphrase only applies to key credentials.' });
  }

  const sudoMode = b.sudoMode ?? String(cur.sudo_mode ?? 'NOPASSWD');
  const keepSudoSecret = sudoMode === 'SUDO_PASSWORD' && !b.sudoPassword && !!cur.sudo_password_secret_id;
  const modeProblem = sudoModeProblem(authMethod, sudoMode, !!b.sudoPassword || keepSudoSecret);
  if (modeProblem) return res.status(400).json(modeProblem);

  const scopeChanged = b.scopeType !== undefined || b.scopeId !== undefined;
  const scopeType = (b.scopeType ?? cur.scope_type) as ScopeType;
  // Only a changed scope is validated (an untouched TAG/VLAN/HOST scope may point at a deleted object).
  const scope = scopeChanged
    ? await checkScope(scopeType, b.scopeId !== undefined ? b.scopeId : (b.scopeType === undefined || b.scopeType === cur.scope_type ? cur.scope_id : null))
    : { scopeId: cur.scope_id as string | null };
  if ('error' in scope) return res.status(400).json(scope);

  // Passphrase change: validate against the stored key first.
  let passphraseSecretId: string | null | undefined; // undefined = unchanged
  if (b.passphrase !== undefined && authMethod === 'KEY') {
    const pem = (await readSecretPlaintext(cur.private_key_secret_id)).toString('utf8');
    const check = await checkPrivateKey(pem.trim(), b.passphrase || undefined);
    const problem = keyProblem(check);
    if (problem) return res.status(400).json(problem);
    passphraseSecretId = check.encrypted && b.passphrase
      ? (await createSecret({ name: `${cur.name}_passphrase`, type: 'SSH_KEY_PASSPHRASE', plaintext: Buffer.from(b.passphrase, 'utf8') })).id
      : null;
  }

  // New login password: stored as a new secret (legacy discovered copies may share the old one).
  const passwordSecretId = b.password
    ? (await createSecret({ name: `${b.name ?? cur.name}_password`, type: 'SSH_PASSWORD', plaintext: Buffer.from(b.password, 'utf8') })).id
    : null;

  let sudoSecretId: string | null;
  if (sudoMode !== 'SUDO_PASSWORD') sudoSecretId = null;
  else if (b.sudoPassword) {
    sudoSecretId = (await createSecret({ name: `${b.name ?? cur.name}_sudo_password`, type: 'SUDO_PASSWORD', plaintext: Buffer.from(b.sudoPassword, 'utf8') })).id;
  } else sudoSecretId = cur.sudo_password_secret_id;

  const { rows } = await pool.query(
    `UPDATE ssh_credentials
     SET name = COALESCE($2, name),
         username = COALESCE($3, username),
         scope_type = $4,
         scope_id = $5,
         sudo_mode = $6,
         sudo_password_secret_id = $7,
         passphrase_secret_id = CASE WHEN $8::boolean THEN $9::uuid ELSE passphrase_secret_id END,
         priority = COALESCE($10, priority),
         password_secret_id = COALESCE($11::uuid, password_secret_id)
     WHERE id=$1
     RETURNING id`,
    [req.params.id, b.name ?? null, b.username ?? null, scopeType, scope.scopeId,
      sudoMode, sudoSecretId, passphraseSecretId !== undefined, passphraseSecretId ?? null, b.priority ?? null, passwordSecretId]
  );
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });
  // Secrets replaced by this update (unless another credential row still shares them).
  await deleteUnreferencedSecrets(pool, [
    passwordSecretId ? cur.password_secret_id : null,
    sudoSecretId !== cur.sudo_password_secret_id ? cur.sudo_password_secret_id : null,
    passphraseSecretId !== undefined && passphraseSecretId !== cur.passphrase_secret_id ? cur.passphrase_secret_id : null
  ], false);
  await pool.query(
    `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), $2, $3, $4, $5)`,
    [req.auth!.username, 'SSH_CREDENTIAL_UPDATE', 'ssh_credential', rows[0].id, JSON.stringify({
      name: b.name, username: b.username, sudoMode, priority: b.priority,
      ...(scopeChanged ? { scopeType, scopeId: scope.scopeId, previousScopeType: cur.scope_type, previousScopeId: cur.scope_id } : {}),
      passwordChanged: !!passwordSecretId, sudoPasswordChanged: !!b.sudoPassword, passphraseChanged: passphraseSecretId !== undefined
    })]
  );
  res.json({ sshCredential: await publicRow(rows[0].id) });
});

/**
 * Delete a credential. Refused (409) while a discovery target set uses it (FK RESTRICT), a host
 * is explicitly assigned to it or an enforcement point uses it, so nothing silently switches credentials. Secrets that
 * no other credential row shares are removed with it.
 */
sshCredentialsRouter.delete('/:id', async (req, res) => {
  if (!z.string().uuid().safeParse(req.params.id).success) return res.status(404).json({ error: 'not_found' });
  const { rows: curRows } = await pool.query(`SELECT * FROM ssh_credentials WHERE id=$1`, [req.params.id]);
  const cur = curRows[0];
  if (!cur) return res.status(404).json({ error: 'not_found' });

  const { rows: profiles } = await pool.query(
    `SELECT DISTINCT p.name FROM discovery_targets t JOIN discovery_profiles p ON p.id = t.profile_id
      WHERE t.ssh_credential_id = $1 ORDER BY p.name`,
    [cur.id]
  );
  if (profiles.length) {
    return res.status(409).json({
      error: 'credential_in_use_by_discovery',
      message: `This credential is used by discovery profile(s) ${profiles.map((p: any) => `"${p.name}"`).join(', ')}. Remove it from their target sets first.`,
      profiles: profiles.map((p: any) => p.name)
    });
  }
  const { rows: hosts } = await pool.query(
    `SELECT hostname FROM hosts WHERE ssh_credential_id = $1 ORDER BY hostname LIMIT 20`,
    [cur.id]
  );
  if (hosts.length) {
    return res.status(409).json({
      error: 'credential_assigned_to_hosts',
      message: `This credential is assigned to host(s) ${hosts.map((h: any) => h.hostname).join(', ')}. Change their SSH credential (Inventory → edit host) first.`,
      hosts: hosts.map((h: any) => h.hostname)
    });
  }

  const { rows: eps } = await pool.query(
    `SELECT name FROM enforcement_points WHERE ssh_credential_id = $1 ORDER BY name LIMIT 20`,
    [cur.id]
  );
  if (eps.length) {
    return res.status(409).json({
      error: 'credential_used_by_enforcement_points',
      message: `This credential is used by enforcement point(s) ${eps.map((e: any) => e.name).join(', ')}. Change their credential first.`,
      enforcementPoints: eps.map((e: any) => e.name)
    });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`DELETE FROM ssh_credentials WHERE id=$1`, [cur.id]);
    await deleteUnreferencedSecrets(client,
      [cur.private_key_secret_id, cur.passphrase_secret_id, cur.password_secret_id, cur.sudo_password_secret_id], true);
    await client.query('COMMIT');
  } catch (e: any) {
    await client.query('ROLLBACK').catch(() => {});
    if (e?.code === '23503') {
      return res.status(409).json({ error: 'credential_in_use', message: 'This credential is still referenced (e.g. by a discovery target set) and cannot be deleted.' });
    }
    throw e;
  } finally {
    client.release();
  }

  await pool.query(
    `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), $2, $3, $4, $5)`,
    [req.auth!.username, 'SSH_CREDENTIAL_DELETE', 'ssh_credential', cur.id, JSON.stringify({
      name: cur.name, username: cur.username, scopeType: cur.scope_type, scopeId: cur.scope_id
    })]
  );
  res.json({ ok: true });
});
