import { pool } from '../db/pool.js';
import { verifyJwt } from '../services/jwt.js';
export function requireAuth(req, res, next) {
    const h = req.header('authorization') ?? '';
    const m = h.match(/^Bearer\s+(.+)$/i);
    if (!m)
        return res.status(401).json({ error: 'missing_token' });
    try {
        const claims = verifyJwt(m[1]);
        // Re-validate user exists and is active, and get live roles from DB
        pool.query(`SELECT u.id, u.is_active,
              COALESCE(array_agg(r.name) FILTER (WHERE r.name IS NOT NULL), '{}') AS roles
       FROM users u
       LEFT JOIN user_roles ur ON ur.user_id = u.id
       LEFT JOIN roles r ON r.id = ur.role_id
       WHERE u.username = $1
       GROUP BY u.id`, [claims.sub]).then(({ rows }) => {
            if (!rows[0] || !rows[0].is_active) {
                return res.status(401).json({ error: 'user_disabled' });
            }
            req.auth = { username: claims.sub, roles: rows[0].roles, userId: rows[0].id };
            return next();
        }).catch(() => {
            return res.status(500).json({ error: 'auth_check_failed' });
        });
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
        if (!ok) {
            // eslint-disable-next-line no-console
            console.warn(`[RBAC] Denied: user=${req.auth.username} roles=[${req.auth.roles}] needed=[${roles}] path=${req.method} ${req.originalUrl}`);
            return res.status(403).json({ error: 'forbidden' });
        }
        return next();
    };
}
