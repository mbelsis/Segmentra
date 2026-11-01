import jwt from 'jsonwebtoken';

import { env } from '../lib/env.js';

export type JwtClaims = {
  /** Username (informational; requireAuth checks it against the user row). */
  sub: string;
  roles: string[];
  /** User id (users.id). Tokens without it are rejected. */
  uid: string;
  /** users.token_version at issue time; bumped on password change/reset and logout to revoke sessions. */
  tv: number;
};

export function signJwt(claims: JwtClaims): string {
  return jwt.sign(claims, env.JWT_SECRET, { algorithm: 'HS256', expiresIn: '12h' });
}

export function verifyJwt(token: string): JwtClaims {
  return jwt.verify(token, env.JWT_SECRET, { algorithms: ['HS256'] }) as JwtClaims;
}

/** Claims of a verified token that carries the session fields (uid, tv); null otherwise. */
export function sessionClaims(token: string): JwtClaims | null {
  let claims: any;
  try {
    claims = verifyJwt(token);
  } catch {
    return null;
  }
  if (!claims || typeof claims.sub !== 'string' || typeof claims.uid !== 'string' || !Number.isInteger(claims.tv)) return null;
  return claims as JwtClaims;
}
