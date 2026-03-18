import { Client } from 'ldapts';
import { pool } from '../db/pool.js';
import { readSecretPlaintext } from './secrets.js';
/** Escape special characters for LDAP filter injection prevention */
function escapeLdapFilter(value) {
    return value
        .replace(/\\/g, '\\5c')
        .replace(/\*/g, '\\2a')
        .replace(/\(/g, '\\28')
        .replace(/\)/g, '\\29')
        .replace(/\0/g, '\\00');
}
function interpolate(template, vars) {
    return template.replace(/\{\{(\w+)\}\}/g, (_, k) => escapeLdapFilter(vars[k] ?? ''));
}
export async function ldapLogin(params) {
    const settingsRes = await pool.query(`SELECT enabled, url, use_ldaps, bind_dn, bind_password_secret_id, base_dn, user_filter, group_filter
     FROM ldap_settings
     ORDER BY created_at DESC
     LIMIT 1`);
    const s = settingsRes.rows[0];
    if (!s?.enabled || !s.url || !s.base_dn) {
        throw new Error('ldap_not_configured');
    }
    // Enforce LDAPS-only if use_ldaps is set
    if (s.use_ldaps && !s.url.toLowerCase().startsWith('ldaps://')) {
        throw new Error('ldaps_required');
    }
    const client = new Client({ url: s.url });
    try {
        if (s.bind_dn) {
            const bindPw = s.bind_password_secret_id
                ? (await readSecretPlaintext(s.bind_password_secret_id)).toString('utf8')
                : '';
            await client.bind(s.bind_dn, bindPw);
        }
        const filter = interpolate(s.user_filter ?? '(sAMAccountName={{username}})', {
            username: params.username
        });
        const searchRes = await client.search(s.base_dn, {
            scope: 'sub',
            filter,
            attributes: ['dn', 'cn', 'displayName', 'mail', 'memberOf', 'objectGUID']
        });
        const entry = searchRes.searchEntries[0];
        if (!entry?.dn)
            throw new Error('invalid_credentials');
        // verify password by binding as the user
        await client.bind(entry.dn, params.password);
        const groups = [];
        if (Array.isArray(entry.memberOf))
            groups.push(...entry.memberOf);
        else if (typeof entry.memberOf === 'string')
            groups.push(entry.memberOf);
        // If memberOf isn't returned, fall back to a group search (optional)
        if (groups.length === 0 && s.group_filter) {
            const gf = interpolate(s.group_filter, { user_dn: entry.dn, username: params.username });
            const gRes = await client.search(s.base_dn, {
                scope: 'sub',
                filter: gf,
                attributes: ['dn']
            });
            for (const g of gRes.searchEntries) {
                if (g?.dn)
                    groups.push(g.dn);
            }
        }
        return {
            directorySubject: entry.objectGUID ?? entry.dn,
            dn: entry.dn,
            displayName: (entry.displayName ?? entry.cn ?? params.username),
            email: (entry.mail ?? null),
            groups
        };
    }
    finally {
        await client.unbind().catch(() => undefined);
    }
}
