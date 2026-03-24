import { Router } from 'express';
import { z } from 'zod';
import { pool } from '../db/pool.js';
import { requireAuth, requireRole } from '../middleware/auth.js';
import { createSecret } from '../services/secrets.js';
export const sshCredentialsRouter = Router();
sshCredentialsRouter.use(requireAuth, requireRole('admin'));
sshCredentialsRouter.get('/', async (_req, res) => {
    const { rows } = await pool.query(`SELECT id, name, username, auth_method, private_key_secret_id, passphrase_secret_id, password_secret_id, scope_type, scope_id, created_at
     FROM ssh_credentials
     ORDER BY created_at DESC`);
    res.json({ sshCredentials: rows });
});
const baseCredentialSchema = z.object({
    name: z.string().min(1),
    username: z.string().min(1),
    scopeType: z.enum(['GLOBAL', 'TAG', 'VLAN', 'HOST']).default('GLOBAL'),
    scopeId: z.string().uuid().optional().nullable()
});
const keyCredentialSchema = baseCredentialSchema.extend({
    authMethod: z.literal('KEY').default('KEY'),
    privateKeyPem: z.string().min(1),
    passphrase: z.string().optional()
});
const passwordCredentialSchema = baseCredentialSchema.extend({
    authMethod: z.literal('PASSWORD'),
    password: z.string().min(1)
});
const createSchema = z.union([keyCredentialSchema, passwordCredentialSchema]);
sshCredentialsRouter.post('/', async (req, res) => {
    const parsed = createSchema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: 'invalid_body' });
    const b = parsed.data;
    const keySecret = b.authMethod === 'KEY'
        ? await createSecret({
            name: `${b.name}_key`,
            type: 'SSH_KEY',
            plaintext: Buffer.from(b.privateKeyPem, 'utf8')
        })
        : null;
    const passphraseSecret = b.authMethod === 'KEY' && b.passphrase
        ? await createSecret({
            name: `${b.name}_passphrase`,
            type: 'SSH_KEY',
            plaintext: Buffer.from(b.passphrase, 'utf8')
        })
        : null;
    const passwordSecret = b.authMethod === 'PASSWORD'
        ? await createSecret({
            name: `${b.name}_password`,
            type: 'SSH_PASSWORD',
            plaintext: Buffer.from(b.password, 'utf8')
        })
        : null;
    const { rows } = await pool.query(`INSERT INTO ssh_credentials
      (name, username, auth_method, private_key_secret_id, passphrase_secret_id, password_secret_id, scope_type, scope_id)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
     RETURNING *`, [b.name, b.username, b.authMethod, keySecret?.id ?? null, passphraseSecret?.id ?? null, passwordSecret?.id ?? null, b.scopeType, b.scopeId ?? null]);
    await pool.query(`INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), $2, $3, $4, $5)`, [req.auth.username, 'SSH_CREDENTIAL_CREATE', 'ssh_credential', rows[0].id, JSON.stringify({ name: b.name, username: b.username, scopeType: b.scopeType, authMethod: b.authMethod })]);
    res.status(201).json({ sshCredential: rows[0] });
});
sshCredentialsRouter.put('/:id', async (req, res) => {
    const parsed = baseCredentialSchema.partial().safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: 'invalid_body' });
    const b = parsed.data;
    const { rows } = await pool.query(`UPDATE ssh_credentials
     SET name = COALESCE($2, name),
         username = COALESCE($3, username),
         scope_type = COALESCE($4, scope_type),
         scope_id = COALESCE($5, scope_id)
     WHERE id=$1
     RETURNING *`, [req.params.id, b.name ?? null, b.username ?? null, b.scopeType ?? null, b.scopeId ?? null]);
    if (!rows[0])
        return res.status(404).json({ error: 'not_found' });
    res.json({ sshCredential: rows[0] });
});
