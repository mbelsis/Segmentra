import { pool } from '../db/pool.js';
import { hostIpOnly, isValidCidr } from './ip-utils.js';

/**
 * Resolve a rule source (CIDR / HOST / TAG / VLAN) into concrete addresses, using the same
 * semantics as deployment compilation (routes/deployments.ts):
 *  - HOST: the host's mgmt_ip
 *  - TAG:  mgmt_ip of every enabled host carrying the tag
 *  - VLAN: mgmt_ip of every enabled host in the VLAN (or the VLAN subnet with vlanMode='subnet',
 *          falling back to member hosts when no subnet is set)
 * Returned values are IPs or CIDRs; an empty array means "matches nothing".
 */
export async function resolveSourceAddresses(
  sourceType: string,
  sourceValue: string,
  opts: { vlanMode?: 'hosts' | 'subnet' } = {}
): Promise<string[]> {
  const type = String(sourceType ?? '').toUpperCase();
  if (type === 'CIDR') {
    if (/^(any|\*)$/i.test(String(sourceValue ?? '').trim())) return ['0.0.0.0/0', '::/0'];
    return String(sourceValue ?? '')
      .split(',')
      .map((s) => s.trim())
      .filter((s) => s && isValidCidr(s));
  }
  if (type === 'HOST') {
    const { rows } = await pool.query(`SELECT mgmt_ip FROM hosts WHERE id = $1`, [sourceValue]);
    const ip = hostIpOnly(rows[0]?.mgmt_ip);
    return ip ? [ip] : [];
  }
  if (type === 'TAG') {
    const { rows } = await pool.query(
      `SELECT h.mgmt_ip FROM hosts h
         JOIN host_tags ht ON ht.host_id = h.id
        WHERE ht.tag_id = $1 AND h.mgmt_ip IS NOT NULL AND h.enabled = true
        ORDER BY h.hostname`,
      [sourceValue]
    );
    return rows.map((r: any) => hostIpOnly(r.mgmt_ip)).filter((x): x is string => !!x);
  }
  if (type === 'VLAN') {
    if (opts.vlanMode === 'subnet') {
      const { rows } = await pool.query(`SELECT subnet FROM vlans WHERE id = $1`, [sourceValue]);
      const subnet = rows[0]?.subnet ? String(rows[0].subnet) : null;
      if (subnet && isValidCidr(subnet)) return [subnet];
    }
    const { rows } = await pool.query(
      `SELECT mgmt_ip FROM hosts WHERE vlan_id = $1 AND mgmt_ip IS NOT NULL AND enabled = true ORDER BY hostname`,
      [sourceValue]
    );
    return rows.map((r: any) => hostIpOnly(r.mgmt_ip)).filter((x): x is string => !!x);
  }
  return [];
}

/** Cache wrapper for resolving many rules that share sources. */
export function createSourceResolver(opts: { vlanMode?: 'hosts' | 'subnet' } = {}) {
  const cache = new Map<string, Promise<string[]>>();
  return (sourceType: string, sourceValue: string): Promise<string[]> => {
    const key = `${sourceType}:${sourceValue}`;
    let p = cache.get(key);
    if (!p) {
      p = resolveSourceAddresses(sourceType, sourceValue, opts);
      cache.set(key, p);
    }
    return p;
  };
}
