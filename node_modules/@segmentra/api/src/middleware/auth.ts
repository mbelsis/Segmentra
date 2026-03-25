import type { NextFunction, Request, Response } from 'express';

import { pool } from '../db/pool.js';
import { verifyJwt } from '../services/jwt.js';

export type AuthUser = {
  username: string;
  roles: string[];
  userId: string | null;
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

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  const h = req.header('authorization') ?? '';
  const m = h.match(/^Bearer\s+(.+)$/i);
  if (!m) return res.status(401).json({ error: 'missing_token' });

  try {
    const claims = verifyJwt(m[1]);
    // Re-validate user exists and is active, and get live roles from DB
    pool.query(
      `SELECT u.id, u.is_active,
              COALESCE(array_agg(r.name) FILTER (WHERE r.name IS NOT NULL), '{}') AS roles
       FROM users u
       LEFT JOIN user_roles ur ON ur.user_id = u.id
       LEFT JOIN roles r ON r.id = ur.role_id
       WHERE u.username = $1
       GROUP BY u.id`,
      [claims.sub]
    ).then(({ rows }) => {
      if (!rows[0] || !rows[0].is_active) {
        return res.status(401).json({ error: 'user_disabled' });
      }
      req.auth = { username: claims.sub, roles: rows[0].roles, userId: rows[0].id };
      return next();
    }).catch(() => {
      return res.status(500).json({ error: 'auth_check_failed' });
    });
  } catch {
    return res.status(401).json({ error: 'invalid_token' });
  }
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



