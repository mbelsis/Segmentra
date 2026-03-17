import { pool } from '../db/pool.js';

export async function generatePoliciesFromTopology(
  topologyViewId: string,
  userId: string,
  policySetName?: string
): Promise<{ policySetId: string; versionId: string; rulesCreated: number }> {
  // Get the topology view for naming
  const { rows: viewRows } = await pool.query(`SELECT name FROM topology_views WHERE id = $1`, [topologyViewId]);
  const viewName = viewRows[0]?.name || 'Topology';

  // Get all flows for this topology
  const { rows: flows } = await pool.query(
    `SELECT * FROM topology_flows WHERE topology_view_id = $1 ORDER BY created_at ASC`,
    [topologyViewId]
  );

  if (flows.length === 0) {
    throw new Error('No flows defined in this topology view');
  }

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

    // Decompose flows into rules — each flow creates both IN and OUT rules
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
      return `${type}:${value}`;
    }

    for (const flow of flows) {
      const srcLabel = await entityLabel(flow.source_type, flow.source_value);
      const tgtLabel = await entityLabel(flow.target_type, flow.target_value);
      const portDesc = flow.ports ? `${flow.protocol.toUpperCase()}/${flow.ports}` : flow.protocol.toUpperCase();
      const flowComment = flow.comment || `${srcLabel} → ${tgtLabel} (${portDesc})`;

      // IN rule: traffic arriving at the target from the source
      await client.query(
        `INSERT INTO policy_rules (policy_version_id, order_index, direction, action, protocol, ports, source_type, source_value, log_mode, comment)
         VALUES ($1, $2, 'IN', $3, $4, $5, $6, $7, $8, $9)`,
        [versionId, ruleIndex++, flow.action, flow.protocol, flow.ports, flow.source_type, flow.source_value,
         flow.action === 'DENY' ? 'LOG' : 'NONE', `IN: ${flowComment}`]
      );

      // OUT rule: traffic leaving the source toward the target
      await client.query(
        `INSERT INTO policy_rules (policy_version_id, order_index, direction, action, protocol, ports, source_type, source_value, log_mode, comment)
         VALUES ($1, $2, 'OUT', $3, $4, $5, $6, $7, $8, $9)`,
        [versionId, ruleIndex++, flow.action, flow.protocol, flow.ports, flow.target_type, flow.target_value,
         flow.action === 'DENY' ? 'LOG' : 'NONE', `OUT: ${flowComment}`]
      );
    }

    await client.query(
      `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
       VALUES ($1, 'TOPOLOGY_GENERATE', 'topology_view', $2, $3)`,
      [userId, topologyViewId, JSON.stringify({ policySetId, versionId, rulesCreated: ruleIndex, flowCount: flows.length })]
    );

    await client.query('COMMIT');
    return { policySetId, versionId, rulesCreated: ruleIndex };
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
