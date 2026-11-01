import type { NextFunction, Request, Response } from 'express';

import { pool } from '../db/pool.js';
import { sessionClaims } from '../services/jwt.js';

export type AuthUser = {
  username: string;
  roles: string[];
  userId: string | null;
  /** users.token_version of the session (set by requireAuth). */
  tokenVersion?: number;
};

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    // eslint-disable-next-line @typescript-eslint/consistent-type-definitions
    interface Request {
      auth?: AuthUser;
    }
  }
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Validate the bearer token and load the user LIVE from the database: by id (claim `uid`), which must
 * still be active, carry the same username (`sub`) and the same token_version (`tv`). Bumping
 * users.token_version (password change / reset, logout) therefore revokes all of the user's tokens, and
 * a token never survives deleting and re-creating a user with the same name. Roles always come from the
 * database, never from the token. Tokens issued before uid/tv existed are rejected (one forced re-login).
 */
export function requireAuth(req: Request, res: Response, next: NextFunction) {
  const h = req.header('authorization') ?? '';
  const m = h.match(/^Bearer\s+(.+)$/i);
  if (!m) return res.status(401).json({ error: 'missing_token' });

  const claims = sessionClaims(m[1]);
  if (!claims || !UUID_RE.test(claims.uid)) return res.status(401).json({ error: 'invalid_token' });

  pool.query(
    `SELECT u.id, u.username, u.is_active, u.token_version,
            COALESCE(array_agg(r.name) FILTER (WHERE r.name IS NOT NULL), '{}') AS roles
     FROM users u
     LEFT JOIN user_roles ur ON ur.user_id = u.id
     LEFT JOIN roles r ON r.id = ur.role_id
     WHERE u.id = $1
     GROUP BY u.id`,
    [claims.uid]
  ).then(({ rows }) => {
    const u = rows[0];
    if (!u || u.username !== claims.sub || Number(u.token_version) !== claims.tv) {
      return res.status(401).json({ error: 'invalid_token' });
    }
    if (!u.is_active) return res.status(401).json({ error: 'user_disabled' });
    req.auth = { username: u.username, roles: u.roles, userId: u.id, tokenVersion: Number(u.token_version) };
    return next();
  }).catch(() => {
    return res.status(500).json({ error: 'auth_check_failed' });
  });
}

export function requireRole(...roles: string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.auth) return res.status(401).json({ error: 'missing_token' });
    const ok = req.auth.roles.some((r) => roles.includes(r));
    if (!ok) {
      // eslint-disable-next-line no-console
      console.warn(`[RBAC] Denied: user=${req.auth.username} roles=[${req.auth.roles}] needed=[${roles}] path=${req.method} ${req.originalUrl}`);
      return res.status(403).json({ error: 'forbidden' });
    }
    return next();
  };
}



