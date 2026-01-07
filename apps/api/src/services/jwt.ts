import jwt from 'jsonwebtoken';

import { env } from '../lib/env.js';

export type JwtClaims = {
  sub: string;
  roles: string[];
};

export function signJwt(claims: JwtClaims): string {
  return jwt.sign(claims, env.JWT_SECRET, { algorithm: 'HS256', expiresIn: '12h' });
}

export function verifyJwt(token: string): JwtClaims {
  return jwt.verify(token, env.JWT_SECRET, { algorithms: ['HS256'] }) as JwtClaims;
}


