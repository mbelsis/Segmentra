import type { ConnectionOptions } from 'node:tls';

import { Client } from 'ldapts';

import { pool } from '../db/pool.js';
import { readSecretPlaintext } from './secrets.js';

type LdapSettingsRow = {
  enabled: boolean;
  url: string | null;
  use_ldaps: boolean;
  start_tls: boolean | null;
  tls_ca_cert_secret_id: string | null;
  bind_dn: string | null;
  bind_password_secret_id: string | null;
  base_dn: string | null;
  user_filter: string | null;
  group_filter: string | null;
};

/** Escape special characters for LDAP filter injection prevention */
function escapeLdapFilter(value: string): string {
  return value
    .replace(/\\/g, '\\5c')
    .replace(/\*/g, '\\2a')
    .replace(/\(/g, '\\28')
    .replace(/\)/g, '\\29')
    .replace(/\0/g, '\\00');
}

function interpolate(template: string, vars: Record<string, string>): string {
  return template.replace(/\{\{(\w+)\}\}/g, (_, k) => escapeLdapFilter(vars[k] ?? ''));
}

/**
 * Canonical text form of an Active Directory objectGUID (16 raw bytes, the first three groups
 * little-endian), e.g. "3f2504e0-4f89-11d3-9a0c-0305e82c3301". Any other length is returned as hex.
 */
export function formatObjectGuid(value: unknown): string | null {
  const buf = Array.isArray(value) ? value[0] : value;
  if (!Buffer.isBuffer(buf) || buf.length === 0) return null;
  if (buf.length !== 16) return buf.toString('hex');
  const h = (i: number) => buf[i].toString(16).padStart(2, '0');
  const seq = (idx: number[]) => idx.map(h).join('');
  return [
    seq([3, 2, 1, 0]),
    seq([5, 4]),
    seq([7, 6]),
    seq([8, 9]),
    seq([10, 11, 12, 13, 14, 15])
  ].join('-');
}

/**
 * Directory usernames are case-insensitive (AD sAMAccountName, most uid schemas): Segmentra stores LDAP
 * users under the lower-cased, trimmed login name so "JDoe" and "jdoe" are one account.
 */
export function canonicalLdapUsername(username: string): string {
  return username.trim().toLowerCase();
}

function firstString(v: unknown): string | null {
  if (Array.isArray(v)) v = v[0];
  if (Buffer.isBuffer(v)) v = v.toString('utf8');
  return typeof v === 'string' && v.length > 0 ? v : null;
}

export async function ldapLogin(params: { username: string; password: string }) {
  const settingsRes = await pool.query<LdapSettingsRow>(
    `SELECT enabled, url, use_ldaps, start_tls, tls_ca_cert_secret_id, bind_dn, bind_password_secret_id,
            base_dn, user_filter, group_filter
     FROM ldap_settings
     ORDER BY created_at DESC
     LIMIT 1`
  );
  const s = settingsRes.rows[0];
  if (!s?.enabled || !s.url || !s.base_dn) {
    throw new Error('ldap_not_configured');
  }

  const isLdaps = s.url.toLowerCase().startsWith('ldaps://');
  // Enforce LDAPS-only if use_ldaps is set
  if (s.use_ldaps && !isLdaps) {
    throw new Error('ldaps_required');
  }

  const tlsOptions: ConnectionOptions = { minVersion: 'TLSv1.2' };
  if (s.tls_ca_cert_secret_id) {
    tlsOptions.ca = (await readSecretPlaintext(s.tls_ca_cert_secret_id)).toString('utf8');
  }

  if (!isLdaps && !s.start_tls) {
    // eslint-disable-next-line no-console
    console.warn('[LDAP] Connection is neither LDAPS nor StartTLS: bind passwords are sent in cleartext.');
  }

  const client = new Client({ url: s.url, tlsOptions: isLdaps ? tlsOptions : undefined });
  try {
    if (!isLdaps && s.start_tls) {
      await client.startTLS(tlsOptions);
    }

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
      attributes: ['dn', 'cn', 'displayName', 'mail', 'memberOf', 'objectGUID', 'entryUUID'],
      // objectGUID is binary: without this ldapts decodes it as UTF-8 and mangles it.
      explicitBufferAttributes: ['objectGUID']
    });
    const entries = searchRes.searchEntries.filter((e: any) => e?.dn);
    if (entries.length === 0) throw new Error('invalid_credentials');
    if (entries.length > 1) {
      // An ambiguous filter must never pick "the first" match: that could log a user in as someone else.
      throw new Error(`ldap_ambiguous_user: the user filter matched ${entries.length} entries`);
    }
    const entry = entries[0] as any;

    // verify password by binding as the user
    await client.bind(entry.dn, params.password);

    const groups: string[] = [];
    if (Array.isArray(entry.memberOf)) groups.push(...entry.memberOf);
    else if (typeof entry.memberOf === 'string') groups.push(entry.memberOf);

    // If memberOf isn't returned, fall back to a group search (optional)
    if (groups.length === 0 && s.group_filter) {
      const gf = interpolate(s.group_filter, { user_dn: entry.dn, username: params.username });
      const gRes = await client.search(s.base_dn, {
        scope: 'sub',
        filter: gf,
        attributes: ['dn']
      });
      for (const g of gRes.searchEntries as any[]) {
        if (g?.dn) groups.push(g.dn);
      }
    }

    return {
      directorySubject: formatObjectGuid(entry.objectGUID) ?? firstString(entry.entryUUID) ?? (entry.dn as string),
      dn: entry.dn as string,
      displayName: (firstString(entry.displayName) ?? firstString(entry.cn) ?? params.username) as string,
      email: firstString(entry.mail),
      groups
    };
  } finally {
    await client.unbind().catch(() => undefined);
  }
}
