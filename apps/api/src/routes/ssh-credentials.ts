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
 * (or handle to it) leaves the API.
 */
const PUBLIC_COLUMNS = `id, name, username, auth_method, sudo_mode, scope_type, scope_id, created_at,
  (passphrase_secret_id IS NOT NULL) AS has_passphrase,
  (sudo_password_secret_id IS NOT NULL) AS has_sudo_password`;

async function publicRow(id: string) {
  const { rows } = await pool.query(`SELECT ${PUBLIC_COLUMNS} FROM ssh_credentials WHERE id=$1`, [id]);
  return rows[0];
}

sshCredentialsRouter.get('/', async (_req, res) => {
  const { rows } = await pool.query(`SELECT ${PUBLIC_COLUMNS} FROM ssh_credentials ORDER BY created_at DESC`);
  res.json({ sshCredentials: rows });
});

const sudoModeSchema = z.enum(['NOPASSWD', 'LOGIN_PASSWORD', 'SUDO_PASSWORD']);

const baseCredentialSchema = z.object({
  name: z.string().min(1),
  username: z.string().min(1),
  scopeType: z.enum(['GLOBAL', 'TAG', 'VLAN', 'HOST']).default('GLOBAL'),
  scopeId: z.string().uuid().optional().nullable(),
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
       sudo_mode, sudo_password_secret_id, scope_type, scope_id)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
     RETURNING id`,
    [b.name, b.username, b.authMethod, keySecret?.id ?? null, passphraseSecret?.id ?? null, passwordSecret?.id ?? null,
      b.sudoMode, sudoSecret?.id ?? null, b.scopeType, b.scopeId ?? null]
  );
  await pool.query(
    `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), $2, $3, $4, $5)`,
    [req.auth!.username, 'SSH_CREDENTIAL_CREATE', 'ssh_credential', rows[0].id, JSON.stringify({
      name: b.name, username: b.username, scopeType: b.scopeType, authMethod: b.authMethod,
      sudoMode: b.sudoMode, hasPassphrase: !!passphraseSecret
    })]
  );

  res.status(201).json({ sshCredential: await publicRow(rows[0].id) });
});

const updateSchema = z.object({
  name: z.string().min(1).optional(),
  username: z.string().min(1).optional(),
  scopeType: z.enum(['GLOBAL', 'TAG', 'VLAN', 'HOST']).optional(),
  scopeId: z.string().uuid().optional().nullable(),
  sudoMode: sudoModeSchema.optional(),
  /** New sudo password (SUDO_PASSWORD mode). Omit to keep the stored one. */
  sudoPassword: z.string().min(1).max(1024).optional(),
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

  if (hasLineBreak(b.sudoPassword) || hasLineBreak(b.passphrase)) {
    return res.status(400).json({ error: 'invalid_body', message: 'Passwords and passphrases must not contain line breaks.' });
  }
  if (b.passphrase !== undefined && authMethod !== 'KEY') {
    return res.status(400).json({ error: 'invalid_body', message: 'A key passphrase only applies to key credentials.' });
  }

  const sudoMode = b.sudoMode ?? String(cur.sudo_mode ?? 'NOPASSWD');
  const keepSudoSecret = sudoMode === 'SUDO_PASSWORD' && !b.sudoPassword && !!cur.sudo_password_secret_id;
  const modeProblem = sudoModeProblem(authMethod, sudoMode, !!b.sudoPassword || keepSudoSecret);
  if (modeProblem) return res.status(400).json(modeProblem);

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

  let sudoSecretId: string | null;
  if (sudoMode !== 'SUDO_PASSWORD') sudoSecretId = null;
  else if (b.sudoPassword) {
    sudoSecretId = (await createSecret({ name: `${b.name ?? cur.name}_sudo_password`, type: 'SUDO_PASSWORD', plaintext: Buffer.from(b.sudoPassword, 'utf8') })).id;
  } else sudoSecretId = cur.sudo_password_secret_id;

  const { rows } = await pool.query(
    `UPDATE ssh_credentials
     SET name = COALESCE($2, name),
         username = COALESCE($3, username),
         scope_type = COALESCE($4, scope_type),
         scope_id = COALESCE($5, scope_id),
         sudo_mode = $6,
         sudo_password_secret_id = $7,
         passphrase_secret_id = CASE WHEN $8::boolean THEN $9::uuid ELSE passphrase_secret_id END
     WHERE id=$1
     RETURNING id`,
    [req.params.id, b.name ?? null, b.username ?? null, b.scopeType ?? null, b.scopeId ?? null,
      sudoMode, sudoSecretId, passphraseSecretId !== undefined, passphraseSecretId ?? null]
  );
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });
  await pool.query(
    `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), $2, $3, $4, $5)`,
    [req.auth!.username, 'SSH_CREDENTIAL_UPDATE', 'ssh_credential', rows[0].id, JSON.stringify({
      name: b.name, username: b.username, scopeType: b.scopeType, sudoMode,
      sudoPasswordChanged: !!b.sudoPassword, passphraseChanged: passphraseSecretId !== undefined
    })]
  );
  res.json({ sshCredential: await publicRow(rows[0].id) });
});
