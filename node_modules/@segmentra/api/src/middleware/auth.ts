import type { NextFunction, Request, Response } from 'express';

import { verifyJwt } from '../services/jwt.js';

export type AuthUser = {
  username: string;
  roles: string[];
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
    req.auth = { username: claims.sub, roles: claims.roles };
    return next();
  } catch {
    return res.status(401).json({ error: 'invalid_token' });
  }
}

export function requireRole(...roles: string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.auth) return res.status(401).json({ error: 'missing_token' });
    const ok = req.auth.roles.some((r) => roles.includes(r));
    if (!ok) return res.status(403).json({ error: 'forbidden' });
    return next();
  };
}


