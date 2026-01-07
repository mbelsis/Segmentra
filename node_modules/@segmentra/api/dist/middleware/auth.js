import { verifyJwt } from '../services/jwt.js';
export function requireAuth(req, res, next) {
    const h = req.header('authorization') ?? '';
    const m = h.match(/^Bearer\s+(.+)$/i);
    if (!m)
        return res.status(401).json({ error: 'missing_token' });
    try {
        const claims = verifyJwt(m[1]);
        req.auth = { username: claims.sub, roles: claims.roles };
        return next();
    }
    catch {
        return res.status(401).json({ error: 'invalid_token' });
    }
}
export function requireRole(...roles) {
    return (req, res, next) => {
        if (!req.auth)
            return res.status(401).json({ error: 'missing_token' });
        const ok = req.auth.roles.some((r) => roles.includes(r));
        if (!ok)
            return res.status(403).json({ error: 'forbidden' });
        return next();
    };
}
