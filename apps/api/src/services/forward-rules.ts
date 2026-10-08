import { pool } from '../db/pool.js';
import { hostIpOnly, isValidCidr } from './ip-utils.js';

/**
 * FORWARD rules (traffic routed THROUGH a host, e.g. an IoT/OT gateway) and the devices a
 * gateway protects. Shared by every place that builds compiler input (deployments, render,
 * policy testing, safety check, firewall learning) and by the troubleshoot simulator.
 *
 * Destination semantics:
 *  - CIDR:      the rule's destination_value (IP/CIDR)
 *  - HOST:      the host's mgmt_ip
 *  - IOT_ASSET: the IoT asset's ip_address
 *  - TAG:       mgmt_ip of every enabled host carrying the tag + ip_address of every enabled
 *               IoT asset carrying the tag
 *  - VLAN:      the VLAN subnet when set, otherwise the enabled hosts and IoT assets in the VLAN
 */

export const DESTINATION_TYPES = ['CIDR', 'TAG', 'VLAN', 'HOST', 'IOT_ASSET'] as const;
export type DestinationType = (typeof DESTINATION_TYPES)[number];

/** nft/compiler set name of a non-CIDR destination (distinct from the src_* source sets). */
export function destinationSetName(destinationType: string, destinationValue: string): string {
  const t = String(destinationType).toUpperCase() === 'IOT_ASSET' ? 'iot' : String(destinationType).toLowerCase();
  return `dst_${t}_${String(destinationValue).replace(/-/g, '')}`;
}

function cleanIps(values: unknown[]): string[] {
  const out: string[] = [];
  for (const v of values) {
    const ip = hostIpOnly(v);
    if (ip && isValidCidr(ip) && !out.includes(ip)) out.push(ip);
  }
  return out;
}

/** Resolve a FORWARD rule destination to concrete IPs/CIDRs (empty = matches nothing). */
export async function resolveDestinationAddresses(destinationType: string, destinationValue: string): Promise<string[]> {
  const type = String(destinationType ?? '').toUpperCase();
  const value = String(destinationValue ?? '').trim();
  if (type === 'CIDR') {
    if (/^(any|\*)$/i.test(value)) return ['0.0.0.0/0', '::/0'];
    return value.split(',').map((s) => s.trim()).filter((s) => s && isValidCidr(s));
  }
  if (type === 'HOST') {
    const { rows } = await pool.query(`SELECT mgmt_ip FROM hosts WHERE id = $1`, [value]);
    return cleanIps(rows.map((r: any) => r.mgmt_ip));
  }
  if (type === 'IOT_ASSET') {
    const { rows } = await pool.query(`SELECT ip_address FROM iot_assets WHERE id = $1`, [value]);
    return cleanIps(rows.map((r: any) => r.ip_address));
  }
  if (type === 'TAG') {
    const { rows } = await pool.query(
      // hosts.mgmt_ip is inet, iot_assets.ip_address is text: UNION needs one type.
      `SELECT host(h.mgmt_ip) AS ip FROM hosts h JOIN host_tags ht ON ht.host_id = h.id
        WHERE ht.tag_id = $1 AND h.mgmt_ip IS NOT NULL AND h.enabled = true
       UNION ALL
       SELECT ia.ip_address AS ip FROM iot_assets ia JOIN iot_asset_tags iat ON iat.asset_id = ia.id
        WHERE iat.tag_id = $1 AND ia.ip_address IS NOT NULL AND ia.enabled = true`,
      [value]
    );
    return cleanIps(rows.map((r: any) => r.ip));
  }
  if (type === 'VLAN') {
    const { rows: v } = await pool.query(`SELECT subnet FROM vlans WHERE id = $1`, [value]);
    const subnet = v[0]?.subnet ? String(v[0].subnet) : null;
    if (subnet && isValidCidr(subnet)) return [subnet];
    const { rows } = await pool.query(
      `SELECT host(mgmt_ip) AS ip FROM hosts WHERE vlan_id = $1 AND mgmt_ip IS NOT NULL AND enabled = true
       UNION ALL
       SELECT ip_address AS ip FROM iot_assets WHERE vlan_id = $1 AND ip_address IS NOT NULL AND enabled = true`,
      [value]
    );
    return cleanIps(rows.map((r: any) => r.ip));
  }
  return [];
}

/** Cache wrapper (same idea as createSourceResolver). */
export function createDestinationResolver() {
  const cache = new Map<string, Promise<string[]>>();
  return (destinationType: string, destinationValue: string): Promise<string[]> => {
    const key = `${destinationType}:${destinationValue}`;
    let p = cache.get(key);
    if (!p) {
      p = resolveDestinationAddresses(destinationType, destinationValue);
      cache.set(key, p);
    }
    return p;
  };
}

type RuleRow = { direction?: string | null; destination_type?: string | null; destination_value?: string | null };

/**
 * Resolve the destination sets of all FORWARD rule rows into `sets` (compiler input, mutated).
 * CIDR destinations need no set. Empty results are kept as empty sets: the compiler omits
 * rules that reference an empty set (they can never match).
 */
export async function addDestinationSets(rows: RuleRow[], sets: Record<string, string[]>): Promise<void> {
  for (const r of rows) {
    if (r.direction !== 'FORWARD' || !r.destination_type || r.destination_type === 'CIDR') continue;
    const name = destinationSetName(r.destination_type, String(r.destination_value ?? ''));
    if (sets[name]) continue;
    sets[name] = await resolveDestinationAddresses(r.destination_type, String(r.destination_value ?? ''));
  }
}

/** Destination fields of a compiler PolicyRule for a policy_rules row. */
export function compilerDestination(r: RuleRow): {
  destinationType: DestinationType | null;
  destinationValue: string | null;
  destination: { kind: 'CIDR' } | { kind: 'SET'; setName: string } | null;
} {
  if (r.direction !== 'FORWARD') return { destinationType: null, destinationValue: null, destination: null };
  const type = (r.destination_type ?? null) as DestinationType | null;
  const value = r.destination_value ?? null;
  if (!type || value === null) return { destinationType: type, destinationValue: value, destination: null }; // compiler rejects
  return {
    destinationType: type,
    destinationValue: value,
    destination: type === 'CIDR' ? { kind: 'CIDR' } : { kind: 'SET', setName: destinationSetName(type, value) }
  };
}

/**
 * Addresses of the IoT devices a gateway protects (enabled IoT assets assigned to the host on
 * the OT/IoT page). Forwarded traffic to them is default-deny unless a FORWARD rule allows it.
 * Values are passed to the compiler as stored (it rejects invalid addresses loudly rather than
 * silently leaving a device unprotected).
 */
export async function getProtectedDestinations(hostId: string): Promise<string[]> {
  const { rows } = await pool.query(
    `SELECT DISTINCT btrim(ia.ip_address) AS ip
       FROM iot_asset_gateways g
       JOIN iot_assets ia ON ia.id = g.asset_id
      WHERE g.host_id = $1 AND ia.enabled = true
        AND ia.ip_address IS NOT NULL AND btrim(ia.ip_address) <> ''
      ORDER BY 1`,
    [hostId]
  );
  return rows.map((r: any) => String(r.ip));
}

/** Gateways (host ids) protecting an IP address, i.e. enabled IoT assets with that address. */
export async function gatewaysProtecting(ip: string): Promise<Array<{ id: string; hostname: string; mgmt_ip: string | null; asset_id: string; asset_name: string }>> {
  const { rows } = await pool.query(
    `SELECT h.id, h.hostname, h.mgmt_ip, ia.id AS asset_id, ia.name AS asset_name
       FROM iot_assets ia
       JOIN iot_asset_gateways g ON g.asset_id = ia.id
       JOIN hosts h ON h.id = g.host_id
      WHERE ia.enabled = true AND split_part(btrim(ia.ip_address), '/', 1) = $1
      ORDER BY h.hostname`,
    [ip]
  );
  return rows;
}

/** For non-CIDR destinations: does the referenced tag / vlan / host / IoT asset exist? */
export async function destinationEntityExists(destinationType: string, destinationValue: string): Promise<boolean> {
  const table: Record<string, string> = { TAG: 'tags', VLAN: 'vlans', HOST: 'hosts', IOT_ASSET: 'iot_assets' };
  const t = table[String(destinationType)];
  if (!t) return true;
  const { rows } = await pool.query(`SELECT 1 FROM ${t} WHERE id = $1::uuid`, [destinationValue]);
  return rows.length > 0;
}
