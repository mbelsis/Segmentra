import { pool } from '../db/pool.js';

interface FlowDecomposition {
  policySetName: string;
  scopeType: string;
  scopeValue: string;
  rules: Array<{
    direction: string;
    action: string;
    protocol: string;
    ports: string | null;
    sourceType: string;
    sourceValue: string;
    comment: string;
  }>;
}

export async function decomposeFlowsIntoPolicies(topologyViewId: string): Promise<FlowDecomposition[]> {
  const { rows: flows } = await pool.query(
    `SELECT * FROM topology_flows WHERE topology_view_id = $1`,
    [topologyViewId]
  );

  // Group flows by source entity (each source gets a policy set)
  const policyMap = new Map<string, FlowDecomposition>();

  for (const flow of flows) {
    // Create rules on both sides of the flow
    const sourceKey = `${flow.source_type}:${flow.source_value}`;
    const targetKey = `${flow.target_type}:${flow.target_value}`;

    // Source-side: OUT rule
    if (!policyMap.has(sourceKey)) {
      policyMap.set(sourceKey, {
        policySetName: `Topology: ${flow.source_type} ${flow.source_value}`,
        scopeType: flow.source_type,
        scopeValue: flow.source_value,
        rules: [],
      });
    }
    policyMap.get(sourceKey)!.rules.push({
      direction: 'OUT',
      action: flow.action,
      protocol: flow.protocol,
      ports: flow.ports,
      sourceType: flow.target_type,
      sourceValue: flow.target_value,
      comment: flow.comment || `Visual topology flow to ${flow.target_type}:${flow.target_value}`,
    });

    // Target-side: IN rule
    if (!policyMap.has(targetKey)) {
      policyMap.set(targetKey, {
        policySetName: `Topology: ${flow.target_type} ${flow.target_value}`,
        scopeType: flow.target_type,
        scopeValue: flow.target_value,
        rules: [],
      });
    }
    policyMap.get(targetKey)!.rules.push({
      direction: 'IN',
      action: flow.action,
      protocol: flow.protocol,
      ports: flow.ports,
      sourceType: flow.source_type,
      sourceValue: flow.source_value,
      comment: flow.comment || `Visual topology flow from ${flow.source_type}:${flow.source_value}`,
    });
  }

  return Array.from(policyMap.values());
}

export async function generatePoliciesFromTopology(
  topologyViewId: string,
  userId: string
): Promise<{ policySetsCreated: number; versionsCreated: number; rulesCreated: number }> {
  const decompositions = await decomposeFlowsIntoPolicies(topologyViewId);

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    let policySetsCreated = 0;
    let versionsCreated = 0;
    let rulesCreated = 0;

    for (const decomp of decompositions) {
      // Determine scope
      let scopeTagId: string | null = null;
      let scopeVlanId: string | null = null;
      let scopeType = 'TAG';

      if (decomp.scopeType === 'TAG') {
        scopeTagId = decomp.scopeValue;
      } else if (decomp.scopeType === 'VLAN') {
        scopeVlanId = decomp.scopeValue;
        scopeType = 'VLAN';
      } else {
        scopeType = 'HOST_LIST';
      }

      // Create policy set
      const { rows: ps } = await client.query(
        `INSERT INTO policy_sets (name, description, scope_type, scope_tag_id, scope_vlan_id, created_by)
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
        [decomp.policySetName, 'Generated from visual topology', scopeType, scopeTagId, scopeVlanId, userId]
      );
      policySetsCreated++;

      // Create version
      const { rows: v } = await client.query(
        `INSERT INTO policy_versions (policy_set_id, version_number, status, change_summary, created_by)
         VALUES ($1, 1, 'DRAFT', 'Generated from visual topology design', $2) RETURNING *`,
        [ps[0].id, userId]
      );
      versionsCreated++;

      // Create rules
      for (let i = 0; i < decomp.rules.length; i++) {
        const rule = decomp.rules[i];
        await client.query(
          `INSERT INTO policy_rules (policy_version_id, order_index, direction, action, protocol, ports, source_type, source_value, log_mode, comment)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'NONE', $9)`,
          [v[0].id, i, rule.direction, rule.action, rule.protocol, rule.ports, rule.sourceType, rule.sourceValue, rule.comment]
        );
        rulesCreated++;
      }
    }

    await client.query(
      `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
       VALUES ($1, 'TOPOLOGY_GENERATE', 'topology_view', $2, $3)`,
      [userId, topologyViewId, JSON.stringify({ policySetsCreated, versionsCreated, rulesCreated })]
    );

    await client.query('COMMIT');
    return { policySetsCreated, versionsCreated, rulesCreated };
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
