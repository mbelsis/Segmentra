import jwt from 'jsonwebtoken';
import { env } from '../lib/env.js';
export function signJwt(claims) {
    return jwt.sign(claims, env.JWT_SECRET, { algorithm: 'HS256', expiresIn: '12h' });
}
export function verifyJwt(token) {
    return jwt.verify(token, env.JWT_SECRET, { algorithms: ['HS256'] });
}
