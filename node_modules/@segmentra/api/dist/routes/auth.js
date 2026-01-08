import { Router } from 'express';
import { z } from 'zod';
import { signJwt } from '../services/jwt.js';
import { requireAuth } from '../middleware/auth.js';
import { ldapLogin } from '../services/ldap.js';
import { verifyPassword, hashPassword } from '../services/password.js';
import { pool } from '../db/pool.js';
export const authRouter = Router();
const loginSchema = z.object({
    username: z.string().min(1),
    password: z.string().min(1)
});
authRouter.post('/login', async (req, res) => {
    const parsed = loginSchema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: 'invalid_body' });
    const { username, password } = parsed.data;
    // First, try local authentication (users with password_hash)
    const localUserRes = await pool.query(`SELECT u.id, u.username, u.display_name, u.email, u.password_hash, u.is_active
     FROM users u
     WHERE u.username=$1 AND u.password_hash IS NOT NULL`, [username]);
    if (localUserRes.rows.length > 0) {
        const user = localUserRes.rows[0];
        if (!user.is_active) {
            return res.status(403).json({ error: 'account_disabled' });
        }
        const passwordValid = await verifyPassword(password, user.password_hash);
        if (!passwordValid) {
            return res.status(401).json({ error: 'invalid_credentials' });
        }
        // Update last login
        await pool.query(`UPDATE users SET last_login_at=now() WHERE id=$1`, [user.id]);
        // Get user roles
        const roleRows = await pool.query(`SELECT r.name
       FROM user_roles ur
       JOIN roles r ON r.id = ur.role_id
       WHERE ur.user_id=$1`, [user.id]);
        const roles = roleRows.rows.map((r) => r.name);
        if (roles.length === 0) {
            return res.status(403).json({ error: 'no_roles_assigned' });
        }
        const token = signJwt({ sub: username, roles });
        return res.json({ token, user: { id: user.id, username: user.username, display_name: user.display_name, email: user.email }, roles });
    }
    // If no local user, try LDAP authentication
    try {
        const ldap = await ldapLogin({ username, password });
        // Map AD groups -> Segmentra roles
        const { rows: roleRows } = await pool.query(`SELECT r.name
       FROM ad_group_role_map m
       JOIN roles r ON r.id = m.role_id
       WHERE m.ad_group_dn = ANY($1::text[])`, [ldap.groups]);
        const roles = roleRows.map((r) => r.name);
        if (roles.length === 0)
            return res.status(403).json({ error: 'no_mapped_roles' });
        // Upsert user
        const userRes = await pool.query(`INSERT INTO users (username, display_name, email, directory_subject, last_login_at)
       VALUES ($1, $2, $3, $4, now())
       ON CONFLICT (username)
       DO UPDATE SET display_name=EXCLUDED.display_name,
                     email=EXCLUDED.email,
                     directory_subject=EXCLUDED.directory_subject,
                     last_login_at=now()
       RETURNING id, username, display_name, email`, [username, ldap.displayName, ldap.email, String(ldap.directorySubject)]);
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
    }
    catch (e) {
        const msg = String(e?.message ?? e);
        if (msg === 'ldap_not_configured')
            return res.status(503).json({ error: 'ldap_not_configured' });
        if (msg === 'invalid_credentials')
            return res.status(401).json({ error: 'invalid_credentials' });
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
        req.auth.username
    ]);
    return res.json({ user: rows[0] ?? null, roles: req.auth.roles });
});
const changePasswordSchema = z.object({
    currentPassword: z.string().min(1),
    newPassword: z.string().min(8)
});
authRouter.post('/change-password', requireAuth, async (req, res) => {
    const parsed = changePasswordSchema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: 'invalid_body' });
    const { currentPassword, newPassword } = parsed.data;
    const username = req.auth.username;
    // Check if user has a local password (password_hash)
    const userRes = await pool.query(`SELECT id, password_hash FROM users WHERE username=$1`, [username]);
    if (userRes.rows.length === 0) {
        return res.status(404).json({ error: 'user_not_found' });
    }
    const user = userRes.rows[0];
    // If user doesn't have a password_hash, they're LDAP-only and can't change password here
    if (!user.password_hash) {
        return res.status(400).json({ error: 'ldap_user_cannot_change_password' });
    }
    // Verify current password
    const passwordValid = await verifyPassword(currentPassword, user.password_hash);
    if (!passwordValid) {
        return res.status(401).json({ error: 'invalid_current_password' });
    }
    // Hash and update new password
    const newPasswordHash = await hashPassword(newPassword);
    await pool.query(`UPDATE users SET password_hash=$1 WHERE id=$2`, [newPasswordHash, user.id]);
    return res.json({ ok: true });
});
