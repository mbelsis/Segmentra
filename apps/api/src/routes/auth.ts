import { Router } from 'express';

import { z } from 'zod';

import { sessionClaims, signJwt } from '../services/jwt.js';
import { requireAuth } from '../middleware/auth.js';
import { canonicalLdapUsername, ldapLogin } from '../services/ldap.js';
import { verifyPassword, hashPassword, burnPasswordCheck } from '../services/password.js';
import { pool } from '../db/pool.js';

export const authRouter = Router();

const loginSchema = z.object({
  username: z.string().min(1),
  password: z.string().min(1)
});

// Simple in-memory rate limiter for FAILED login attempts (per client IP).
// Keyed on req.ip, which honours the TRUST_PROXY setting when running behind a reverse proxy.
const failedLogins = new Map<string, { count: number; resetAt: number }>();
const MAX_FAILED_LOGINS = 10; // per window
const LOGIN_WINDOW_MS = 15 * 60 * 1000; // 15 minutes

function isRateLimited(ip: string): boolean {
  const entry = failedLogins.get(ip);
  if (!entry) return false;
  if (Date.now() > entry.resetAt) {
    failedLogins.delete(ip);
    return false;
  }
  return entry.count >= MAX_FAILED_LOGINS;
}

function recordFailedLogin(ip: string) {
  const now = Date.now();
  const entry = failedLogins.get(ip);
  if (!entry || now > entry.resetAt) {
    failedLogins.set(ip, { count: 1, resetAt: now + LOGIN_WINDOW_MS });
  } else {
    entry.count++;
  }
}

function resetFailedLogins(ip: string) {
  failedLogins.delete(ip);
}

// Periodically prune expired entries so the map can't grow without bound
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of failedLogins) {
    if (now > entry.resetAt) failedLogins.delete(ip);
  }
}, 5 * 60 * 1000).unref();

// Generic error message to prevent username/account enumeration
const GENERIC_LOGIN_ERROR = 'Invalid username or password';

authRouter.post('/login', async (req, res) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });

  // Rate limiting (only failed attempts count)
  const clientIp = req.ip || req.socket.remoteAddress || 'unknown';
  if (isRateLimited(clientIp)) {
    return res.status(429).json({ error: 'too_many_attempts', message: 'Too many failed login attempts. Please try again in 15 minutes.' });
  }

  const { username, password } = parsed.data;
  const fail = () => {
    recordFailedLogin(clientIp);
    return res.status(401).json({ error: 'invalid_credentials', message: GENERIC_LOGIN_ERROR });
  };

  // First, try local authentication (users with password_hash)
  const localUserRes = await pool.query(
    `SELECT u.id, u.username, u.display_name, u.email, u.password_hash, u.is_active, u.token_version
     FROM users u
     WHERE u.username=$1 AND u.password_hash IS NOT NULL`,
    [username]
  );

  if (localUserRes.rows.length > 0) {
    const user = localUserRes.rows[0];

    // All failure cases return the same generic error to prevent enumeration. The password is checked
    // before is_active so a disabled account answers in the same time as a wrong password.
    const passwordValid = await verifyPassword(password, user.password_hash);
    if (!passwordValid || !user.is_active) {
      return fail();
    }

    // Update last login
    await pool.query(`UPDATE users SET last_login_at=now() WHERE id=$1`, [user.id]);

    // Get user roles
    const roleRows = await pool.query(
      `SELECT r.name
       FROM user_roles ur
       JOIN roles r ON r.id = ur.role_id
       WHERE ur.user_id=$1`,
      [user.id]
    );
    const roles = roleRows.rows.map((r) => r.name);
    if (roles.length === 0) {
      // No roles = can't use the app, but don't reveal account exists
      return fail();
    }

    resetFailedLogins(clientIp);
    const token = signJwt({ sub: user.username, roles, uid: user.id, tv: Number(user.token_version ?? 0) });
    return res.json({ token, user: { id: user.id, username: user.username, display_name: user.display_name, email: user.email }, roles });
  }

  // No local user with that name: spend the same bcrypt work as a real password check, so the response
  // time does not reveal which usernames exist locally (LDAP, when configured, adds its own latency).
  await burnPasswordCheck(password);

  // If no local user, try LDAP authentication
  let ldap: Awaited<ReturnType<typeof ldapLogin>>;
  try {
    ldap = await ldapLogin({ username, password });
  } catch (e: any) {
    // All LDAP failures return generic error — no enumeration
    // eslint-disable-next-line no-console
    console.error('[Auth] Login failed:', e.message);
    return fail();
  }

  // Directory usernames are case-insensitive: the account is stored under the canonical (lower-cased)
  // name and found case-insensitively, so "JDoe" and "jdoe" never become two Segmentra users.
  const canonicalUsername = canonicalLdapUsername(username);
  const directorySubject = String(ldap.directorySubject);

  // Map AD groups -> Segmentra roles. DNs are case-insensitive and may differ in spacing
  // around ',' / '=' (e.g. "CN=Admins, OU=Groups" vs "cn=admins,ou=groups"), so normalize both sides.
  const { rows: roleRows } = await pool.query(
    `SELECT DISTINCT r.name
     FROM ad_group_role_map m
     JOIN roles r ON r.id = m.role_id
     WHERE lower(regexp_replace(trim(m.ad_group_dn), '\\s*([,=])\\s*', '\\1', 'g')) IN (
       SELECT lower(regexp_replace(trim(g), '\\s*([,=])\\s*', '\\1', 'g')) FROM unnest($1::text[]) AS g
     )`,
    [ldap.groups]
  );
  const roles = roleRows.map((r) => r.name);

  const client = await pool.connect();
  let userRow: { id: string; username: string; display_name: string | null; email: string | null; token_version: number } | null = null;
  let outcome: 'ok' | 'no_roles' | 'local_collision' = 'ok';
  try {
    await client.query('BEGIN');
    // Existing account: by case-insensitive username (a local account first, so it is never shadowed; then the exact canonical name, then
    // the most recently used), else by directory subject (same directory user under another login name).
    const existingRes = await client.query(
      `SELECT id, username, password_hash
       FROM users
       WHERE lower(username) = $1
       ORDER BY (password_hash IS NOT NULL) DESC, (username = $1) DESC, last_login_at DESC NULLS LAST, created_at
       LIMIT 1
       FOR UPDATE`,
      [canonicalUsername]
    );
    let existing = existingRes.rows[0] as { id: string; username: string; password_hash: string | null } | undefined;
    if (!existing) {
      const bySubject = await client.query(
        `SELECT id, username, password_hash FROM users
         WHERE directory_subject = $1 AND password_hash IS NULL
         ORDER BY last_login_at DESC NULLS LAST LIMIT 1 FOR UPDATE`,
        [directorySubject]
      );
      existing = bySubject.rows[0];
    }

    if (existing?.password_hash) {
      // A local account with the same name (any case): never let a directory login take it over.
      outcome = 'local_collision';
    } else if (roles.length === 0) {
      // The user no longer maps to any role: revoke what an earlier login granted (roles and live tokens).
      outcome = 'no_roles';
      if (existing) {
        await client.query(`DELETE FROM user_roles WHERE user_id=$1`, [existing.id]);
        await client.query(`UPDATE users SET token_version = token_version + 1 WHERE id=$1`, [existing.id]);
      }
    } else {
      if (existing) {
        // Keep the account's name when it was found by subject under a different login name; otherwise
        // rewrite it to the canonical form. directory_subject is rewritten too (older releases stored a
        // mangled objectGUID string).
        const newName = existing.username.toLowerCase() === canonicalUsername ? canonicalUsername : existing.username;
        const upd = await client.query(
          `UPDATE users SET username=$2, display_name=$3, email=$4, directory_subject=$5, last_login_at=now()
           WHERE id=$1
           RETURNING id, username, display_name, email, token_version`,
          [existing.id, newName, ldap.displayName, ldap.email, directorySubject]
        );
        userRow = upd.rows[0];
      } else {
        const ins = await client.query(
          `INSERT INTO users (username, display_name, email, directory_subject, last_login_at)
           VALUES ($1, $2, $3, $4, now())
           RETURNING id, username, display_name, email, token_version`,
          [canonicalUsername, ldap.displayName, ldap.email, directorySubject]
        );
        userRow = ins.rows[0];
      }

      // Sync user_roles
      await client.query(`DELETE FROM user_roles WHERE user_id=$1`, [userRow!.id]);
      await client.query(
        `INSERT INTO user_roles (user_id, role_id) SELECT $1, id FROM roles WHERE name = ANY($2::text[])`,
        [userRow!.id, roles]
      );
    }
    await client.query('COMMIT');
  } catch (e: any) {
    await client.query('ROLLBACK').catch(() => {});
    if (e?.code === '23505') {
      // eslint-disable-next-line no-console
      console.error('[Auth] LDAP login failed: username collides with an existing account');
      return fail();
    }
    throw e;
  } finally {
    client.release();
  }

  if (outcome !== 'ok' || !userRow) {
    // eslint-disable-next-line no-console
    console.error(`[Auth] LDAP login refused for "${canonicalUsername}": ${outcome === 'no_roles' ? 'no mapped roles' : 'a local account with this name exists'}`);
    return fail();
  }

  // A deactivated directory user must not get a token
  const active = await pool.query(`SELECT is_active FROM users WHERE id=$1`, [userRow.id]);
  if (active.rows[0] && active.rows[0].is_active === false) {
    return fail();
  }

  resetFailedLogins(clientIp);
  const { token_version: ldapTv, ...ldapUser } = userRow;
  const token = signJwt({ sub: ldapUser.username, roles, uid: ldapUser.id, tv: Number(ldapTv ?? 0) });
  return res.json({ token, user: ldapUser, roles });
});

/**
 * Logout revokes the session server-side: with a valid token it bumps users.token_version, which
 * invalidates ALL of that user's tokens (every browser/session), not only this one. Without a (valid)
 * token it is a no-op, so a client can always call it before dropping its token.
 */
authRouter.post('/logout', async (req, res) => {
  const m = (req.header('authorization') ?? '').match(/^Bearer\s+(.+)$/i);
  const claims = m ? sessionClaims(m[1]) : null;
  if (claims) {
    await pool.query(
      `UPDATE users SET token_version = token_version + 1 WHERE id::text = $1 AND username = $2 AND token_version = $3`,
      [claims.uid, claims.sub, claims.tv]
    );
  }
  return res.json({ ok: true });
});

authRouter.get('/me', requireAuth, async (req, res) => {
  const { rows } = await pool.query(`SELECT id, username, display_name, email FROM users WHERE id=$1`, [
    req.auth!.userId
  ]);
  return res.json({ user: rows[0] ?? null, roles: req.auth!.roles });
});

const changePasswordSchema = z.object({
  currentPassword: z.string().min(1),
  newPassword: z.string().min(8)
});

authRouter.post('/change-password', requireAuth, async (req, res) => {
  const parsed = changePasswordSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });

  const { currentPassword, newPassword } = parsed.data;

  // Check if user has a local password (password_hash)
  const userRes = await pool.query(
    `SELECT id, username, password_hash FROM users WHERE id=$1`,
    [req.auth!.userId]
  );

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

  // Bumping token_version revokes every existing session of this user (a stolen token stops working);
  // the caller gets a fresh token so this session continues.
  const upd = await pool.query(
    `UPDATE users SET password_hash=$1, token_version = token_version + 1 WHERE id=$2 RETURNING token_version`,
    [newPasswordHash, user.id]
  );
  const token = signJwt({ sub: user.username, roles: req.auth!.roles, uid: user.id, tv: Number(upd.rows[0].token_version) });

  return res.json({ ok: true, token });
});


