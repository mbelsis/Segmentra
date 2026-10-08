import { pool } from '../db/pool.js';
import { isValidCidr, isValidPortSpec } from './ip-utils.js';

export class TopologyValidationError extends Error {
  constructor(public code: string, message: string, public details?: unknown) {
    super(message);
    this.name = 'TopologyValidationError';
  }
}

const ENDPOINT_TYPES = new Set(['CIDR', 'TAG', 'VLAN', 'HOST']);
const PROTOCOLS = new Set(['tcp', 'udp', 'icmp', 'any']);
const DIRECTIONS = new Set(['IN', 'OUT', 'BOTH']);
const ACTIONS = new Set(['ALLOW', 'DENY']);

/** Re-validate stored flows (older rows may pre-date API validation). */
function validateFlow(flow: any): string | null {
  if (!ENDPOINT_TYPES.has(flow.source_type)) return 'invalid_source_type';
  if (!ENDPOINT_TYPES.has(flow.target_type)) return 'invalid_target_type';
  if (!PROTOCOLS.has(flow.protocol)) return 'invalid_protocol';
  if (!DIRECTIONS.has(flow.direction)) return 'invalid_direction';
  if (!ACTIONS.has(flow.action)) return 'invalid_action';
  if (flow.source_type === 'CIDR' && !isValidCidr(flow.source_value)) return 'invalid_source_cidr';
  if (flow.target_type === 'CIDR' && !isValidCidr(flow.target_value)) return 'invalid_target_cidr';
  if (flow.ports) {
    if (flow.protocol !== 'tcp' && flow.protocol !== 'udp') return 'ports_require_tcp_or_udp';
    if (!isValidPortSpec(flow.ports)) return 'invalid_ports';
  }
  return null;
}

/**
 * Turn a topology view into a single HOST_LIST policy set (DRAFT version).
 *
 * Flow semantics (source -> target):
 *  - direction IN:   enforce at the target — an inbound rule (remote = source) applied to the target's hosts.
 *  - direction OUT:  enforce at the source — an outbound rule (remote = target) applied to the source's hosts.
 *  - direction BOTH: both of the above.
 *
 * Hosts that enforce a rule (TAG members, VLAN members, or the HOST itself) are attached to the
 * HOST_LIST policy set via policy_set_hosts. CIDR endpoints are external and never attached.
 * Limitation: all rules live in one policy set, so every attached host receives every rule; an
 * inbound rule meant for the target is also present on source hosts (and vice-versa). Split the
 * topology into several views if per-endpoint isolation is required.
 */
export async function generatePoliciesFromTopology(
  topologyViewId: string,
  userId: string,
  policySetName?: string
): Promise<{ policySetId: string; versionId: string; rulesCreated: number; hostsAttached: number; warnings: string[] }> {
  // Get the topology view for naming
  const { rows: viewRows } = await pool.query(`SELECT name FROM topology_views WHERE id = $1`, [topologyViewId]);
  if (!viewRows[0]) throw new TopologyValidationError('not_found', 'Topology view not found');
  const viewName = viewRows[0].name || 'Topology';

  // Get all flows for this topology
  const { rows: flows } = await pool.query(
    `SELECT * FROM topology_flows WHERE topology_view_id = $1 ORDER BY created_at ASC`,
    [topologyViewId]
  );

  if (flows.length === 0) {
    throw new TopologyValidationError('no_flows', 'No flows defined in this topology view');
  }

  const invalid = flows
    .map((f: any) => ({ flowId: f.id, error: validateFlow(f) }))
    .filter((f: { error: string | null }) => f.error !== null);
  if (invalid.length > 0) {
    throw new TopologyValidationError('invalid_flows', 'One or more flows are invalid; fix or delete them first', invalid);
  }

  const warnings: string[] = [];
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Create a single policy set for the entire topology — scope HOST_LIST (most flexible)
    const setName = policySetName || `Topology: ${viewName}`;
    const { rows: ps } = await client.query(
      `INSERT INTO policy_sets (name, description, scope_type, created_by)
       VALUES ($1, $2, 'HOST_LIST', $3) RETURNING *`,
      [setName, `Generated from topology view "${viewName}" with ${flows.length} flows`, userId]
    );
    const policySetId = ps[0].id;

    // Create a single version with all rules
    const { rows: v } = await client.query(
      `INSERT INTO policy_versions (policy_set_id, version_number, status, change_summary, created_by, interface_scope_type)
       VALUES ($1, 1, 'DRAFT', $2, $3, 'ALL_INTERFACES') RETURNING *`,
      [policySetId, `Generated from topology: ${flows.length} flows decomposed into firewall rules`, userId]
    );
    const versionId = v[0].id;

    let ruleIndex = 0;

    // Helper: resolve entity name for comments
    async function entityLabel(type: string, value: string): Promise<string> {
      if (type === 'TAG') {
        const { rows } = await client.query(`SELECT name FROM tags WHERE id = $1`, [value]);
        return rows[0] ? `TAG:${rows[0].name}` : `TAG:${value}`;
      }
      if (type === 'VLAN') {
        const { rows } = await client.query(`SELECT name, vlan_tag FROM vlans WHERE id = $1`, [value]);
        return rows[0] ? `VLAN ${rows[0].vlan_tag}:${rows[0].name}` : `VLAN:${value}`;
      }
      if (type === 'HOST') {
        const { rows } = await client.query(`SELECT hostname FROM hosts WHERE id = $1`, [value]);
        return rows[0] ? `HOST:${rows[0].hostname}` : `HOST:${value}`;
      }
      return `${type}:${value}`;
    }

    // Helper: managed hosts that make up an endpoint (enforcement points for the rule)
    async function endpointHostIds(type: string, value: string): Promise<string[]> {
      if (type === 'HOST') {
        const { rows } = await client.query(`SELECT id FROM hosts WHERE id = $1`, [value]);
        return rows.map((r: any) => r.id);
      }
      if (type === 'TAG') {
        const { rows } = await client.query(`SELECT host_id AS id FROM host_tags WHERE tag_id = $1`, [value]);
        return rows.map((r: any) => r.id);
      }
      if (type === 'VLAN') {
        const { rows } = await client.query(`SELECT id FROM hosts WHERE vlan_id = $1`, [value]);
        return rows.map((r: any) => r.id);
      }
      return [];
    }

    const attachHosts = new Set<string>();

    for (const flow of flows) {
      const srcLabel = await entityLabel(flow.source_type, flow.source_value);
      const tgtLabel = await entityLabel(flow.target_type, flow.target_value);
      const ports = flow.ports ? String(flow.ports).trim() : null;
      const portDesc = ports ? `${flow.protocol.toUpperCase()}/${ports}` : flow.protocol.toUpperCase();
      const flowComment = flow.comment || `${srcLabel} → ${tgtLabel} (${portDesc})`;
      const logMode = flow.action === 'DENY' ? 'LOG' : 'NONE';

      if (flow.direction === 'IN' || flow.direction === 'BOTH') {
        // IN rule: traffic arriving at the target from the source
        await client.query(
          `INSERT INTO policy_rules (policy_version_id, order_index, direction, action, protocol, ports, source_type, source_value, log_mode, comment)
           VALUES ($1, $2, 'IN', $3, $4, $5, $6, $7, $8, $9)`,
          [versionId, ruleIndex++, flow.action, flow.protocol, ports, flow.source_type, flow.source_value,
           logMode, `IN: ${flowComment}`]
        );
        const ids = await endpointHostIds(flow.target_type, flow.target_value);
        if (flow.target_type !== 'CIDR' && ids.length === 0) {
          warnings.push(`No managed hosts found for target ${tgtLabel}; inbound rule has no enforcing host yet`);
        }
        ids.forEach((id) => attachHosts.add(id));
      }

      if (flow.direction === 'OUT' || flow.direction === 'BOTH') {
        // OUT rule: traffic leaving the source toward the target
        await client.query(
          `INSERT INTO policy_rules (policy_version_id, order_index, direction, action, protocol, ports, source_type, source_value, log_mode, comment)
           VALUES ($1, $2, 'OUT', $3, $4, $5, $6, $7, $8, $9)`,
          [versionId, ruleIndex++, flow.action, flow.protocol, ports, flow.target_type, flow.target_value,
           logMode, `OUT: ${flowComment}`]
        );
        const ids = await endpointHostIds(flow.source_type, flow.source_value);
        if (flow.source_type !== 'CIDR' && ids.length === 0) {
          warnings.push(`No managed hosts found for source ${srcLabel}; outbound rule has no enforcing host yet`);
        }
        ids.forEach((id) => attachHosts.add(id));
      }
    }

    for (const hostId of attachHosts) {
      await client.query(
        `INSERT INTO policy_set_hosts (policy_set_id, host_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
        [policySetId, hostId]
      );
    }
    if (attachHosts.size === 0) {
      warnings.push('No managed hosts were attached to the generated HOST_LIST policy set; add hosts before deploying');
    }

    await client.query(
      `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
       VALUES ($1, 'TOPOLOGY_GENERATE', 'topology_view', $2, $3)`,
      [userId, topologyViewId, JSON.stringify({ policySetId, versionId, rulesCreated: ruleIndex, flowCount: flows.length, hostsAttached: attachHosts.size })]
    );

    await client.query('COMMIT');
    return { policySetId, versionId, rulesCreated: ruleIndex, hostsAttached: attachHosts.size, warnings };
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}

export async function autoDiscoverTopology(): Promise<{
  nodes: Array<{ id: string; type: string; label: string; data: any }>;
  edges: Array<{ source: string; target: string; data: any }>;
}> {
  const nodes: Array<{ id: string; type: string; label: string; data: any }> = [];
  const edges: Array<{ source: string; target: string; data: any }> = [];

  // Get all tags with hosts
  const { rows: tags } = await pool.query(
    `SELECT t.id, t.name, COUNT(ht.host_id) as host_count
     FROM tags t LEFT JOIN host_tags ht ON ht.tag_id = t.id
     GROUP BY t.id, t.name HAVING COUNT(ht.host_id) > 0`
  );
  for (const tag of tags) {
    nodes.push({ id: `tag-${tag.id}`, type: 'TAG', label: tag.name, data: { hostCount: parseInt(tag.host_count) } });
  }

  // Get all VLANs with hosts
  const { rows: vlans } = await pool.query(
    `SELECT v.id, v.name, v.vlan_tag, v.subnet, COUNT(h.id) as host_count
     FROM vlans v LEFT JOIN hosts h ON h.vlan_id = v.id
     GROUP BY v.id, v.name, v.vlan_tag, v.subnet HAVING COUNT(h.id) > 0`
  );
  for (const vlan of vlans) {
    nodes.push({ id: `vlan-${vlan.id}`, type: 'VLAN', label: `VLAN ${vlan.vlan_tag}: ${vlan.name}`, data: { subnet: vlan.subnet, hostCount: parseInt(vlan.host_count) } });
  }

  // Discover connections from deployed policies
  const { rows: deployedRules } = await pool.query(
    `SELECT DISTINCT pr.source_type, pr.source_value, pr.direction, pr.action, pr.protocol, pr.ports,
            ps.scope_type, ps.scope_tag_id, ps.scope_vlan_id
     FROM policy_rules pr
     JOIN policy_versions pv ON pv.id = pr.policy_version_id
     JOIN policy_sets ps ON ps.id = pv.policy_set_id
     WHERE pv.status = 'DEPLOYED'`
  );

  for (const rule of deployedRules) {
    let targetNodeId = '';
    if (rule.scope_type === 'TAG' && rule.scope_tag_id) targetNodeId = `tag-${rule.scope_tag_id}`;
    else if (rule.scope_type === 'VLAN' && rule.scope_vlan_id) targetNodeId = `vlan-${rule.scope_vlan_id}`;
    else continue;

    let sourceNodeId = '';
    if (rule.source_type === 'TAG') sourceNodeId = `tag-${rule.source_value}`;
    else if (rule.source_type === 'VLAN') sourceNodeId = `vlan-${rule.source_value}`;
    else continue;

    edges.push({
      source: sourceNodeId,
      target: targetNodeId,
      data: { action: rule.action, protocol: rule.protocol, ports: rule.ports, direction: rule.direction },
    });
  }

  return { nodes, edges };
}
