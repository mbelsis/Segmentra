import { Router } from 'express';
import { z } from 'zod';

import { env } from '../lib/env.js';
import { pool } from '../db/pool.js';
import { signJwt } from '../services/jwt.js';
import { requireAuth, requireRole } from '../middleware/auth.js';
import { createSecret } from '../services/secrets.js';

export const adminRouter = Router();

adminRouter.get('/roles', requireAuth, requireRole('admin'), async (_req, res) => {
  const { rows } = await pool.query('SELECT id, name, description FROM roles ORDER BY name ASC');
  res.json({ roles: rows });
});

const bootstrapSchema = z.object({
  token: z.string().min(1),
  username: z.string().min(1).default('bootstrap_admin')
});

// One-time bootstrap for fresh installs: creates a local admin user record so LDAP settings
// and group mappings can be configured. Disable by omitting SEGMENTRA_BOOTSTRAP_TOKEN.
adminRouter.post('/bootstrap', async (req, res) => {
  if (!env.SEGMENTRA_BOOTSTRAP_TOKEN) return res.status(404).json({ error: 'not_enabled' });
  const parsed = bootstrapSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });
  if (parsed.data.token !== env.SEGMENTRA_BOOTSTRAP_TOKEN) {
    return res.status(403).json({ error: 'forbidden' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const existingUsers = await client.query('SELECT COUNT(*)::int AS c FROM users');
    if (existingUsers.rows[0]?.c > 0) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'already_initialized' });
    }

    const userRes = await client.query(
      `INSERT INTO users (username, display_name, is_active)
       VALUES ($1, $2, true)
       RETURNING id, username`,
      [parsed.data.username, 'Bootstrap Admin']
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
  bindPassword: z.string().optional(),
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
  if (s.bindPassword) {
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


