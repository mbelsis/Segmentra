import { Router } from 'express';
import { z } from 'zod';
import bcrypt from 'bcrypt';
import { timingSafeEqual } from 'node:crypto';

import { env } from '../lib/env.js';
import { pool } from '../db/pool.js';
import { signJwt } from '../services/jwt.js';
import { requireAuth, requireRole } from '../middleware/auth.js';
import { createSecret } from '../services/secrets.js';
import { hashPassword } from '../services/password.js';

export const adminRouter = Router();

adminRouter.get('/roles', requireAuth, requireRole('admin'), async (_req, res) => {
  const { rows } = await pool.query('SELECT id, name, description FROM roles ORDER BY name ASC');
  res.json({ roles: rows });
});

const bootstrapSchema = z.object({
  token: z.string().min(1),
  username: z.string().min(1).default('bootstrap_admin'),
  password: z.string().min(12).refine(value => Buffer.byteLength(value, 'utf8') <= 72, 'Password must be at most 72 UTF-8 bytes')
});

// One-time bootstrap for fresh installs: creates a local admin user record so LDAP settings
// and group mappings can be configured. Disable by omitting SEGMENTRA_BOOTSTRAP_TOKEN.
// Rate limited: 3 attempts per IP per 15 minutes to prevent brute-force of the token.
const bootstrapAttempts = new Map<string, { count: number; resetAt: number }>();
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of bootstrapAttempts) {
    if (entry.resetAt <= now) bootstrapAttempts.delete(ip);
  }
}, 5 * 60 * 1000).unref();
adminRouter.post('/bootstrap', async (req, res) => {
  if (!env.SEGMENTRA_BOOTSTRAP_TOKEN) return res.status(404).json({ error: 'not_enabled' });

  // Rate limiting
  const ip = req.ip || 'unknown';
  const now = Date.now();
  const entry = bootstrapAttempts.get(ip);
  if (entry && entry.resetAt > now && entry.count >= 3) {
    return res.status(429).json({ error: 'too_many_attempts', message: 'Try again later' });
  }
  if (!entry || entry.resetAt <= now) {
    bootstrapAttempts.set(ip, { count: 1, resetAt: now + 15 * 60 * 1000 });
  } else {
    entry.count++;
  }

  const parsed = bootstrapSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });
  const suppliedToken = Buffer.from(parsed.data.token);
  const expectedToken = Buffer.from(env.SEGMENTRA_BOOTSTRAP_TOKEN);
  if (suppliedToken.length !== expectedToken.length || !timingSafeEqual(suppliedToken, expectedToken)) {
    return res.status(403).json({ error: 'forbidden' });
  }

  const passwordHash = await hashPassword(parsed.data.password);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // Serialize first-user creation across API processes before checking initialization.
    await client.query('LOCK TABLE users IN EXCLUSIVE MODE');
    const existingUsers = await client.query('SELECT COUNT(*)::int AS c FROM users');
    if (existingUsers.rows[0]?.c > 0) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'already_initialized' });
    }

    const userRes = await client.query(
      `INSERT INTO users (username, display_name, is_active, password_hash)
       VALUES ($1, $2, true, $3)
       RETURNING id, username`,
      [parsed.data.username, 'Bootstrap Admin', passwordHash]
    );

    const roleRes = await client.query(`SELECT id FROM roles WHERE name='admin' LIMIT 1`);
    if (!roleRes.rows[0]?.id) {
      throw new Error("missing role 'admin' (seed roles first)");
    }

    await client.query(`INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)`, [
      userRes.rows[0].id,
      roleRes.rows[0].id
    ]);

    await client.query('COMMIT');

    const token = signJwt({ sub: userRes.rows[0].username, roles: ['admin'] });
    return res.json({ token, user: userRes.rows[0] });
  } catch (e) {
    await client.query('ROLLBACK');
    // eslint-disable-next-line no-console
    console.error(e);
    return res.status(500).json({ error: 'bootstrap_failed' });
  } finally {
    client.release();
  }
});

adminRouter.get('/ldap-settings', requireAuth, requireRole('admin'), async (_req, res) => {
  const { rows } = await pool.query(
    `SELECT id, enabled, url, bind_dn, base_dn, user_filter, group_filter, use_ldaps, created_at
     FROM ldap_settings
     ORDER BY created_at DESC
     LIMIT 1`
  );
  res.json({ ldapSettings: rows[0] ?? null });
});

const putLdapSchema = z.object({
  enabled: z.boolean(),
  url: z.string().min(1),
  bindDn: z.string().optional(),
  // Omitted (or empty string) = keep the existing bind password; null = clear it.
  bindPassword: z.string().nullable().optional(),
  baseDn: z.string().min(1),
  userFilter: z.string().optional(),
  groupFilter: z.string().optional(),
  useLdaps: z.boolean().default(true)
});

adminRouter.put('/ldap-settings', requireAuth, requireRole('admin'), async (req, res) => {
  const parsed = putLdapSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });

  const s = parsed.data;
  let bindPasswordSecretId: string | null = null;
  if (s.bindPassword === undefined || s.bindPassword === '') {
    // Keep the existing bind password (settings are versioned: copy it from the latest row)
    const latest = await pool.query(
      `SELECT bind_password_secret_id FROM ldap_settings ORDER BY created_at DESC LIMIT 1`
    );
    bindPasswordSecretId = latest.rows[0]?.bind_password_secret_id ?? null;
  } else if (s.bindPassword) {
    const secret = await createSecret({
      name: `ldap_bind_${new Date().toISOString()}`,
      type: 'LDAP_BIND',
      plaintext: Buffer.from(s.bindPassword, 'utf8')
    });
    bindPasswordSecretId = secret.id;
  }

  const { rows } = await pool.query(
    `INSERT INTO ldap_settings
      (enabled, url, bind_dn, bind_password_secret_id, base_dn, user_filter, group_filter, use_ldaps)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
     RETURNING id, enabled, url, bind_dn, base_dn, user_filter, group_filter, use_ldaps, created_at`,
    [
      s.enabled,
      s.url,
      s.bindDn ?? null,
      bindPasswordSecretId,
      s.baseDn,
      s.userFilter ?? null,
      s.groupFilter ?? null,
      s.useLdaps
    ]
  );
  res.json({ ldapSettings: rows[0] });
});

const groupMapSchema = z.object({
  adGroupDn: z.string().min(1),
  roleName: z.enum(['viewer', 'operator', 'approver', 'admin'])
});

adminRouter.post('/ad-group-role-map', requireAuth, requireRole('admin'), async (req, res) => {
  const parsed = groupMapSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });
  const { adGroupDn, roleName } = parsed.data;

  const roleRes = await pool.query(`SELECT id FROM roles WHERE name=$1`, [roleName]);
  if (!roleRes.rows[0]?.id) return res.status(400).json({ error: 'unknown_role' });

  const { rows } = await pool.query(
    `INSERT INTO ad_group_role_map (ad_group_dn, role_id)
     VALUES ($1, $2)
     RETURNING id, ad_group_dn, role_id`,
    [adGroupDn, roleRes.rows[0].id]
  );
  res.json({ map: rows[0] });
});

adminRouter.get('/ad-group-role-map', requireAuth, requireRole('admin'), async (_req, res) => {
  const { rows } = await pool.query(
    `SELECT m.id, m.ad_group_dn, r.name AS role_name
     FROM ad_group_role_map m JOIN roles r ON r.id = m.role_id
     ORDER BY m.ad_group_dn ASC, r.name ASC`
  );
  res.json({ maps: rows });
});

adminRouter.delete('/ad-group-role-map/:id', requireAuth, requireRole('admin'), async (req, res) => {
  if (!z.string().uuid().safeParse(req.params.id).success) return res.status(400).json({ error: 'invalid_id' });
  const { rowCount } = await pool.query(`DELETE FROM ad_group_role_map WHERE id=$1`, [req.params.id]);
  if (!rowCount) return res.status(404).json({ error: 'not_found' });
  res.json({ ok: true });
});

adminRouter.get('/executor-setting', requireAuth, requireRole('admin'), async (_req, res) => {
  const { rows } = await pool.query(
    `SELECT value FROM system_settings WHERE key='deployment_executor'`
  );
  const executor = rows[0]?.value ?? 'ansible';
  res.json({ executor });
});

const executorSettingSchema = z.object({
  executor: z.enum(['ansible', 'ssh'])
});

adminRouter.put('/executor-setting', requireAuth, requireRole('admin'), async (req, res) => {
  const parsed = executorSettingSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });

  const { rows } = await pool.query(
    `INSERT INTO system_settings (key, value, updated_at)
     VALUES ('deployment_executor', $1, now())
     ON CONFLICT (key) DO UPDATE SET value=$1, updated_at=now()
     RETURNING value`,
    [parsed.data.executor]
  );
  res.json({ executor: rows[0].value });
});

adminRouter.get('/management-vlan-setting', requireAuth, requireRole('admin'), async (_req, res) => {
  const { rows } = await pool.query(
    `SELECT value FROM system_settings WHERE key='management_vlan_id'`
  );
  const vlanId = rows[0]?.value || null;
  
  if (vlanId) {
    const vlanRes = await pool.query(`SELECT id, vlan_tag, name, subnet FROM vlans WHERE id=$1`, [vlanId]);
    res.json({ managementVlan: vlanRes.rows[0] || null });
  } else {
    res.json({ managementVlan: null });
  }
});

const managementVlanSettingSchema = z.object({
  vlanId: z.string().uuid().nullable()
});

adminRouter.put('/management-vlan-setting', requireAuth, requireRole('admin'), async (req, res) => {
  const parsed = managementVlanSettingSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });

  // Validate VLAN exists if provided
  if (parsed.data.vlanId) {
    const vlanCheck = await pool.query(`SELECT id FROM vlans WHERE id=$1`, [parsed.data.vlanId]);
    if (!vlanCheck.rows[0]) {
      return res.status(404).json({ error: 'vlan_not_found' });
    }
  }

  const value = parsed.data.vlanId || '';
  const { rows } = await pool.query(
    `INSERT INTO system_settings (key, value, updated_at)
     VALUES ('management_vlan_id', $1, now())
     ON CONFLICT (key) DO UPDATE SET value=$1, updated_at=now()
     RETURNING value`,
    [value]
  );

  if (rows[0].value) {
    const vlanRes = await pool.query(`SELECT id, vlan_tag, name, subnet FROM vlans WHERE id=$1`, [rows[0].value]);
    res.json({ managementVlan: vlanRes.rows[0] || null });
  } else {
    res.json({ managementVlan: null });
  }
});

// === Local User Management ===

type Queryable = { query: (text: string, params?: any[]) => Promise<any> };

/** Serialize changes that could affect the set of active admins (prevents two admins demoting each other concurrently). */
async function lockAdminChanges(client: Queryable) {
  await client.query(`SELECT pg_advisory_xact_lock(hashtext('segmentra:admin-users'))`);
}

async function countActiveAdmins(client: Queryable): Promise<number> {
  const { rows } = await client.query(
    `SELECT COUNT(DISTINCT u.id)::int AS c
     FROM users u
     JOIN user_roles ur ON ur.user_id = u.id
     JOIN roles r ON r.id = ur.role_id
     WHERE r.name = 'admin' AND u.is_active = true`
  );
  return rows[0]?.c ?? 0;
}

// List all users with their roles
adminRouter.get('/users', requireAuth, requireRole('admin'), async (_req, res) => {
  const { rows } = await pool.query(
    `SELECT u.id, u.username, u.display_name, u.email, u.is_active, u.created_at, u.last_login_at,
       (SELECT array_agg(r.name ORDER BY r.name) FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = u.id) as roles,
       CASE WHEN u.password_hash IS NOT NULL THEN 'local' ELSE 'ldap' END as auth_type
     FROM users u ORDER BY u.username ASC`
  );
  res.json({ users: rows });
});

// Get single user
adminRouter.get('/users/:id', requireAuth, requireRole('admin'), async (req, res) => {
  const { rows } = await pool.query(
    `SELECT u.id, u.username, u.display_name, u.email, u.is_active, u.created_at, u.last_login_at,
       (SELECT array_agg(r.name ORDER BY r.name) FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = u.id) as roles,
       CASE WHEN u.password_hash IS NOT NULL THEN 'local' ELSE 'ldap' END as auth_type
     FROM users u WHERE u.id = $1`,
    [req.params.id]
  );
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });
  res.json({ user: rows[0] });
});

const createUserSchema = z.object({
  username: z.string().min(1).max(100),
  displayName: z.string().min(1).max(200),
  email: z.string().email().optional().nullable(),
  password: z.string().min(8),
  roles: z.array(z.enum(['viewer', 'operator', 'approver', 'admin'])).min(1),
  isActive: z.boolean().default(true),
});

// Create local user
adminRouter.post('/users', requireAuth, requireRole('admin'), async (req, res) => {
  const parsed = createUserSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body', details: parsed.error.issues });
  const b = parsed.data;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Check username uniqueness
    const existing = await client.query('SELECT id FROM users WHERE username = $1', [b.username]);
    if (existing.rows.length > 0) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'username_taken', message: `Username "${b.username}" is already in use.` });
    }

    const passwordHash = await bcrypt.hash(b.password, 10);
    const userRes = await client.query(
      `INSERT INTO users (username, display_name, email, password_hash, is_active)
       VALUES ($1, $2, $3, $4, $5) RETURNING id, username, display_name, email, is_active, created_at`,
      [b.username, b.displayName, b.email ?? null, passwordHash, b.isActive]
    );
    const userId = userRes.rows[0].id;

    // Assign roles
    for (const roleName of b.roles) {
      const roleRes = await client.query('SELECT id FROM roles WHERE name = $1', [roleName]);
      if (roleRes.rows[0]) {
        await client.query(
          'INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
          [userId, roleRes.rows[0].id]
        );
      }
    }

    await client.query(
      `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
       VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), 'USER_CREATE', 'user', $2, $3)`,
      [req.auth!.username, userId, JSON.stringify({ username: b.username, roles: b.roles })]
    );

    await client.query('COMMIT');
    res.status(201).json({ user: { ...userRes.rows[0], roles: b.roles } });
  } catch (e: any) {
    await client.query('ROLLBACK').catch(() => {});
    if (e?.code === '23505') {
      return res.status(409).json({ error: 'username_taken', message: `Username "${b.username}" is already in use.` });
    }
    throw e;
  } finally {
    client.release();
  }
});

const updateUserSchema = z.object({
  displayName: z.string().min(1).max(200).optional(),
  // omitted = keep; null or '' = clear
  email: z.union([z.string().email(), z.literal('').transform(() => null), z.null()]).optional(),
  isActive: z.boolean().optional(),
  roles: z.array(z.enum(['viewer', 'operator', 'approver', 'admin'])).min(1).optional(),
});

// Update user
adminRouter.put('/users/:id', requireAuth, requireRole('admin'), async (req, res) => {
  const parsed = updateUserSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body', details: parsed.error.issues });
  const b = parsed.data;

  const isSelf = req.auth!.userId === req.params.id;
  if (isSelf && b.isActive === false) {
    return res.status(409).json({ error: 'cannot_deactivate_self', message: 'You cannot deactivate your own account.' });
  }
  if (isSelf && b.roles && !b.roles.includes('admin')) {
    return res.status(409).json({ error: 'cannot_remove_own_admin', message: 'You cannot remove the admin role from your own account.' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await lockAdminChanges(client);

    // email: omitted = keep, null = clear
    const { rows } = await client.query(
      `UPDATE users SET
         display_name = COALESCE($2, display_name),
         email = CASE WHEN $5::boolean THEN $3 ELSE email END,
         is_active = COALESCE($4, is_active)
       WHERE id = $1 RETURNING id, username, display_name, email, is_active`,
      [req.params.id, b.displayName ?? null, b.email ?? null, b.isActive ?? null, b.email !== undefined]
    );
    if (!rows[0]) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'not_found' });
    }

    // Update roles if provided
    if (b.roles) {
      await client.query('DELETE FROM user_roles WHERE user_id = $1', [req.params.id]);
      await client.query(
        `INSERT INTO user_roles (user_id, role_id)
         SELECT $1, id FROM roles WHERE name = ANY($2::text[])
         ON CONFLICT DO NOTHING`,
        [req.params.id, b.roles]
      );
    }

    if ((b.isActive === false || b.roles) && (await countActiveAdmins(client)) === 0) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'last_admin', message: 'This change would leave no active admin. Promote or activate another admin first.' });
    }

    await client.query(
      `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
       VALUES ($1, 'USER_UPDATE', 'user', $2, $3)`,
      [req.auth!.userId, req.params.id, JSON.stringify({ changes: b })]
    );

    await client.query('COMMIT');
    res.json({ user: rows[0] });
  } catch (e: any) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }
});

// Reset password
adminRouter.post('/users/:id/reset-password', requireAuth, requireRole('admin'), async (req, res) => {
  const bodySchema = z.object({ newPassword: z.string().min(8) });
  const parsed = bodySchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body', message: 'Password must be at least 8 characters.' });

  const target = await pool.query('SELECT (password_hash IS NULL AND directory_subject IS NOT NULL) AS is_directory FROM users WHERE id = $1', [req.params.id]);
  if (!target.rows[0]) return res.status(404).json({ error: 'not_found' });
  // Setting a password on a directory (LDAP) user would turn it into a local account that
  // keeps working even after it is disabled or removed from its groups in the directory.
  if (target.rows[0].is_directory) {
    return res.status(409).json({
      error: 'ldap_user_password',
      message: 'This user signs in through LDAP/Active Directory. Change the password in the directory instead.'
    });
  }

  const passwordHash = await bcrypt.hash(parsed.data.newPassword, 10);
  const { rowCount } = await pool.query(
    'UPDATE users SET password_hash = $2 WHERE id = $1',
    [req.params.id, passwordHash]
  );
  if (!rowCount) return res.status(404).json({ error: 'not_found' });

  await pool.query(
    `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), 'USER_PASSWORD_RESET', 'user', $2, $3)`,
    [req.auth!.username, req.params.id, JSON.stringify({ resetBy: req.auth!.username })]
  );

  res.json({ ok: true, message: 'Password reset successfully.' });
});

// Delete user
adminRouter.delete('/users/:id', requireAuth, requireRole('admin'), async (req, res) => {
  // Prevent self-deletion
  if (req.auth!.userId === req.params.id) {
    return res.status(400).json({ error: 'cannot_delete_self', message: 'You cannot delete your own account.' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await lockAdminChanges(client);

    const { rowCount } = await client.query('DELETE FROM users WHERE id = $1', [req.params.id]);
    if (!rowCount) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'not_found' });
    }

    if ((await countActiveAdmins(client)) === 0) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'last_admin', message: 'You cannot delete the last active admin.' });
    }

    await client.query(
      `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
       VALUES ($1, 'USER_DELETE', 'user', $2, $3)`,
      [req.auth!.userId, req.params.id, JSON.stringify({ deletedBy: req.auth!.username })]
    );
    await client.query('COMMIT');
    res.json({ ok: true });
  } catch (e: any) {
    await client.query('ROLLBACK').catch(() => {});
    if (e?.code === '23503') {
      return res.status(409).json({
        error: 'user_in_use',
        message: 'This user is referenced by policies, deployments or audit records and cannot be deleted. Deactivate the user instead.'
      });
    }
    throw e;
  } finally {
    client.release();
  }
});
