import { pool } from '../db/pool.js';
import { cidrContains } from './ip-utils.js';
import { PROTOCOLS, servicesForRule } from './iot-protocols.js';

/**
 * IoT/OT protection coverage: for every enabled asset, is something actually protecting it, and what is allowed to reach it?
 * It is derived from what Segmentra recorded (gateway assignments, the last successful deployment of each gateway and the
 * FORWARD rules of that deployed version), not from a live check of the gateway.
 *
 *   NO_GATEWAY            no gateway is assigned
 *   NO_IP                 a gateway is assigned, but the asset has no IP address, so nothing can be enforced for it
 *   GATEWAY_NOT_DEPLOYED  no assigned gateway has a policy deployed
 *   PENDING_DEPLOY        some gateway was deployed before the assignment or the last change of the asset
 *   PROTECTED             every assigned gateway was deployed after the assignment (the asset is default-denied there)
 */
export type CoverageState = 'NO_GATEWAY' | 'NO_IP' | 'GATEWAY_NOT_DEPLOYED' | 'PENDING_DEPLOY' | 'PROTECTED';
export const COVERAGE_STATES: CoverageState[] = ['NO_GATEWAY', 'NO_IP', 'GATEWAY_NOT_DEPLOYED', 'PENDING_DEPLOY', 'PROTECTED'];

export type AllowedRule = {
  gateway: string; policySet: string; version: number; order: number; action: string; protocol: string; ports: string | null;
  services: string[]; cleartext: boolean; from: string;
};

export type CoverageAsset = {
  id: string; name: string; assetType: string; vendor: string | null; ip: string | null; zone: string | null; criticality: string;
  state: CoverageState;
  gateways: Array<{ id: string; hostname: string; assignedAt: string; deployedAt: string | null; status: 'not_deployed' | 'pending' | 'deployed' }>;
  rules: AllowedRule[];
  cleartextAllowed: string[];
};

export async function computeIotCoverage(): Promise<{ assets: CoverageAsset[]; summary: Record<CoverageState, number>; zones: Array<{ zone: string; assets: number } & Record<CoverageState, number>> }> {
  const q = async (sql: string, params: any[] = []) => (await pool.query(sql, params)).rows as any[];
  const assets = await q(
    `SELECT a.id, a.name, a.asset_type, a.vendor, a.ip_address, a.zone, a.criticality, a.vlan_id, a.updated_at,
            COALESCE((SELECT array_agg(iat.tag_id::text) FROM iot_asset_tags iat WHERE iat.asset_id = a.id), '{}') AS tag_ids
       FROM iot_assets a WHERE a.enabled = true ORDER BY a.name`
  );
  const links = await q(`SELECT g.asset_id, g.host_id, g.assigned_at, h.hostname FROM iot_asset_gateways g JOIN hosts h ON h.id = g.host_id`);
  const hostIds = [...new Set(links.map((l) => l.host_id))];

  // Last successful deployment of each gateway (a policy removed by the expiry action does not count) and its FORWARD rules.
  const last = hostIds.length
    ? await q(
        `SELECT DISTINCT ON (dh.host_id) dh.host_id, COALESCE(dh.finished_at, d.finished_at, d.created_at) AS at, dh.expiry_status,
                pv.id AS version_id, pv.version_number, ps.name AS policy_set
           FROM deployment_hosts dh JOIN deployments d ON d.id = dh.deployment_id
           JOIN policy_versions pv ON pv.id = d.policy_version_id JOIN policy_sets ps ON ps.id = pv.policy_set_id
          WHERE dh.status = 'SUCCEEDED' AND dh.host_id = ANY($1::uuid[])
          ORDER BY dh.host_id, COALESCE(dh.finished_at, d.finished_at, d.created_at) DESC`, [hostIds])
    : [];
  const lastBy = new Map(last.filter((l) => l.expiry_status !== 'REMOVED').map((l) => [l.host_id, l]));
  const versionIds = [...new Set([...lastBy.values()].map((l) => l.version_id))];
  const fwd = versionIds.length
    ? await q(`SELECT * FROM policy_rules WHERE direction = 'FORWARD' AND policy_version_id = ANY($1::uuid[]) ORDER BY order_index`, [versionIds])
    : [];
  const rulesByVersion = new Map<string, any[]>();
  for (const r of fwd) rulesByVersion.set(r.policy_version_id, [...(rulesByVersion.get(r.policy_version_id) ?? []), r]);

  const names = {
    tag: new Map((await q(`SELECT id::text, name FROM tags`)).map((r) => [r.id, r.name])),
    vlan: new Map((await q(`SELECT id::text, name FROM vlans`)).map((r) => [r.id, r.name])),
    host: new Map((await q(`SELECT id::text, hostname AS name FROM hosts`)).map((r) => [r.id, r.name])),
  };
  const fromLabel = (r: any) => (r.source_type === 'CIDR' ? String(r.source_value) : `${r.source_type.toLowerCase()} ${(names as any)[r.source_type.toLowerCase()]?.get(String(r.source_value)) ?? r.source_value}`);
  const destMatches = (r: any, a: any): boolean => {
    const v = String(r.destination_value ?? '');
    switch (r.destination_type) {
      case 'IOT_ASSET': return v === a.id;
      case 'TAG': return a.tag_ids.includes(v);
      case 'VLAN': return !!a.vlan_id && v === a.vlan_id;
      case 'CIDR': {
        if (!a.ip_address) return false;
        const ip = String(a.ip_address).split('/')[0];
        return v.split(',').map((x) => x.trim()).some((c) => /^(any|\*)$/i.test(c) || (c && safeContains(c, ip)));
      }
      default: return false;
    }
  };
  const safeContains = (cidr: string, ip: string) => { try { return cidrContains(cidr.includes('/') ? cidr : `${cidr}/${cidr.includes(':') ? 128 : 32}`, ip); } catch { return false; } };

  const out: CoverageAsset[] = assets.map((a) => {
    const gws = links.filter((l) => l.asset_id === a.id).map((l) => {
      const dep = lastBy.get(l.host_id);
      const deployedAt = dep ? new Date(dep.at) : null;
      const status: 'not_deployed' | 'pending' | 'deployed' = !deployedAt ? 'not_deployed'
        : deployedAt < new Date(l.assigned_at) || deployedAt < new Date(a.updated_at) ? 'pending' : 'deployed';
      return { id: l.host_id as string, hostname: l.hostname as string, assignedAt: new Date(l.assigned_at).toISOString(), deployedAt: deployedAt?.toISOString() ?? null, status };
    });
    const ip = String(a.ip_address ?? '').trim();
    const state: CoverageState = gws.length === 0 ? 'NO_GATEWAY' : !ip ? 'NO_IP'
      : gws.every((g) => g.status === 'not_deployed') ? 'GATEWAY_NOT_DEPLOYED'
        : gws.some((g) => g.status !== 'deployed') ? 'PENDING_DEPLOY' : 'PROTECTED';
    const rules: AllowedRule[] = [];
    for (const g of gws) {
      const dep = lastBy.get(g.id);
      if (!dep) continue;
      for (const r of rulesByVersion.get(dep.version_id) ?? []) {
        if (!destMatches(r, a)) continue;
        const services = servicesForRule(r.protocol, r.ports);
        rules.push({
          gateway: g.hostname, policySet: dep.policy_set, version: dep.version_number, order: Number(r.order_index), action: r.action,
          protocol: r.protocol, ports: r.ports || null, services: services.map((s) => s.name), cleartext: r.action === 'ALLOW' && services.some((s) => s.security === 'cleartext'),
          from: fromLabel(r),
        });
      }
    }
    const cleartextAllowed = [...new Set(rules.filter((r) => r.cleartext).flatMap((r) => servicesForRule(r.protocol, r.ports).filter((s) => s.security === 'cleartext').map((s) => s.name)))];
    return { id: a.id, name: a.name, assetType: a.asset_type, vendor: a.vendor, ip: ip || null, zone: a.zone, criticality: a.criticality, state, gateways: gws, rules, cleartextAllowed };
  });

  const summary = Object.fromEntries(COVERAGE_STATES.map((s) => [s, 0])) as Record<CoverageState, number>;
  const zoneMap = new Map<string, any>();
  for (const a of out) {
    summary[a.state] += 1;
    const z = a.zone || '(no zone)';
    const row = zoneMap.get(z) ?? { zone: z, assets: 0, ...Object.fromEntries(COVERAGE_STATES.map((s) => [s, 0])) };
    row.assets += 1; row[a.state] += 1; zoneMap.set(z, row);
  }
  return { assets: out, summary, zones: [...zoneMap.values()].sort((x, y) => x.zone.localeCompare(y.zone)) };
}

export const PROTOCOL_COUNT = PROTOCOLS.length;
