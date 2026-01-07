import { Router } from 'express';

import { z } from 'zod';

import { signJwt } from '../services/jwt.js';
import { requireAuth } from '../middleware/auth.js';
import { ldapLogin } from '../services/ldap.js';
import { pool } from '../db/pool.js';

export const authRouter = Router();

const loginSchema = z.object({
  username: z.string().min(1),
  password: z.string().min(1)
});

authRouter.post('/login', async (req, res) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });

  const { username, password } = parsed.data;

  try {
    const ldap = await ldapLogin({ username, password });

    // Map AD groups -> Segmentra roles
    const { rows: roleRows } = await pool.query(
      `SELECT r.name
       FROM ad_group_role_map m
       JOIN roles r ON r.id = m.role_id
       WHERE m.ad_group_dn = ANY($1::text[])`,
      [ldap.groups]
    );
    const roles = roleRows.map((r) => r.name);
    if (roles.length === 0) return res.status(403).json({ error: 'no_mapped_roles' });

    // Upsert user
    const userRes = await pool.query(
      `INSERT INTO users (username, display_name, email, directory_subject, last_login_at)
       VALUES ($1, $2, $3, $4, now())
       ON CONFLICT (username)
       DO UPDATE SET display_name=EXCLUDED.display_name,
                     email=EXCLUDED.email,
                     directory_subject=EXCLUDED.directory_subject,
                     last_login_at=now()
       RETURNING id, username, display_name, email`,
      [username, ldap.displayName, ldap.email, String(ldap.directorySubject)]
    );

    // Sync user_roles
    await pool.query(`DELETE FROM user_roles WHERE user_id=$1`, [userRes.rows[0].id]);
    const roleIdsRes = await pool.query(`SELECT id, name FROM roles WHERE name = ANY($1::text[])`, [
      roles
    ]);
    for (const rr of roleIdsRes.rows) {
      await pool.query(`INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)`, [
        userRes.rows[0].id,
        rr.id
      ]);
    }

    const token = signJwt({ sub: username, roles });
    return res.json({ token, user: userRes.rows[0], roles });
  } catch (e: any) {
    const msg = String(e?.message ?? e);
    if (msg === 'ldap_not_configured') return res.status(503).json({ error: 'ldap_not_configured' });
    if (msg === 'invalid_credentials') return res.status(401).json({ error: 'invalid_credentials' });
    // eslint-disable-next-line no-console
    console.error(e);
    return res.status(500).json({ error: 'login_failed' });
  }
});

authRouter.post('/logout', async (_req, res) => {
  // JWT is stateless in v1; client drops token
  return res.json({ ok: true });
});

authRouter.get('/me', requireAuth, async (req, res) => {
  const { rows } = await pool.query(`SELECT id, username, display_name, email FROM users WHERE username=$1`, [
    req.auth!.username
  ]);
  return res.json({ user: rows[0] ?? null, roles: req.auth!.roles });
});


