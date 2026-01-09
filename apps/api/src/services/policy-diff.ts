import { compileHostPolicy } from '@segmentra/compiler';
import { pool } from '../db/pool.js';

export interface PolicyDiffRule {
  type: 'added' | 'removed' | 'modified';
  orderIndex: number;
  direction: string;
  action: string;
  protocol: string;
  ports?: string;
  sourceType: string;
  sourceValue: string;
  comment?: string;
}

export interface PolicyDiffResult {
  hostId: string;
  hostname: string;
  changes: {
    newAllows: PolicyDiffRule[];
    removedAllows: PolicyDiffRule[];
    newDenies: PolicyDiffRule[];
    removedDenies: PolicyDiffRule[];
  };
  summary: {
    totalNewAllows: number;
    totalRemovedAllows: number;
    totalNewDenies: number;
    totalRemovedDenies: number;
  };
}

/**
 * Compare two policy versions and generate a diff for sample hosts.
 * Returns semantic diff showing what rules were added/removed/modified.
 */
export async function comparePolicyVersions(params: {
  currentVersionId: string;
  candidateVersionId: string;
  hostIds: string[]; // Sample hosts to compare
}): Promise<PolicyDiffResult[]> {
  const results: PolicyDiffResult[] = [];

  // Get both policy versions
  const [currentPolicyRes, candidatePolicyRes] = await Promise.all([
    pool.query(
      `SELECT interface_scope_type, interface_scope_roles, interface_scope_names
       FROM policy_versions WHERE id=$1`,
      [params.currentVersionId]
    ),
    pool.query(
      `SELECT interface_scope_type, interface_scope_roles, interface_scope_names
       FROM policy_versions WHERE id=$1`,
      [params.candidateVersionId]
    )
  ]);

  if (!currentPolicyRes.rows[0] || !candidatePolicyRes.rows[0]) {
    throw new Error('Policy version not found');
  }

  const currentPolicy = currentPolicyRes.rows[0];
  const candidatePolicy = candidatePolicyRes.rows[0];

  // Get rules for both versions
  const [currentRulesRes, candidateRulesRes] = await Promise.all([
    pool.query(
      `SELECT order_index, direction, action, protocol, ports, source_type, source_value, comment
       FROM policy_rules
       WHERE policy_version_id=$1
       ORDER BY order_index ASC`,
      [params.currentVersionId]
    ),
    pool.query(
      `SELECT order_index, direction, action, protocol, ports, source_type, source_value, comment
       FROM policy_rules
       WHERE policy_version_id=$1
       ORDER BY order_index ASC`,
      [params.candidateVersionId]
    )
  ]);

  // Normalize rules for comparison (create signature)
  const normalizeRule = (r: any) => ({
    direction: r.direction || 'IN',
    action: r.action,
    protocol: r.protocol,
    ports: r.ports || null,
    sourceType: r.source_type,
    sourceValue: r.source_value,
    comment: r.comment || null
  });

  const currentRules = currentRulesRes.rows.map(normalizeRule);
  const candidateRules = candidateRulesRes.rows.map(normalizeRule);

  // Create rule signatures for comparison
  const ruleSignature = (r: ReturnType<typeof normalizeRule>) =>
    `${r.direction}|${r.action}|${r.protocol}|${r.ports || '*'}|${r.sourceType}|${r.sourceValue}`;

  const currentSignatures = new Set(currentRules.map(ruleSignature));
  const candidateSignatures = new Set(candidateRules.map(ruleSignature));

  // Find added and removed rules, preserving order_index
  const addedRules: Array<typeof candidateRules[0] & { orderIndex: number }> = [];
  const removedRules: Array<typeof currentRules[0] & { orderIndex: number }> = [];

  for (let i = 0; i < candidateRulesRes.rows.length; i++) {
    const rule = candidateRules[i];
    if (!currentSignatures.has(ruleSignature(rule))) {
      addedRules.push({ ...rule, orderIndex: candidateRulesRes.rows[i].order_index });
    }
  }

  for (let i = 0; i < currentRulesRes.rows.length; i++) {
    const rule = currentRules[i];
    if (!candidateSignatures.has(ruleSignature(rule))) {
      removedRules.push({ ...rule, orderIndex: currentRulesRes.rows[i].order_index });
    }
  }

  // Get management VLAN CIDRs
  const mgmtVlanRes = await pool.query(
    `SELECT value FROM system_settings WHERE key='management_vlan_id'`
  );
  const mgmtVlanId = mgmtVlanRes.rows[0]?.value || null;
  let mgmtSshCidrs: string[] = [];
  if (mgmtVlanId) {
    const vlanRes = await pool.query(`SELECT subnet FROM vlans WHERE id=$1`, [mgmtVlanId]);
    if (vlanRes.rows[0]?.subnet) {
      mgmtSshCidrs = [vlanRes.rows[0].subnet];
    }
  }

  // Process each host
  for (const hostId of params.hostIds) {
    const hostRes = await pool.query(
      `SELECT h.id, h.hostname, h.mgmt_ip, h.firewall_backend,
              COALESCE(json_agg(json_build_object('name', hi.name, 'role', hi.role, 'enabled', hi.enabled)) FILTER (WHERE hi.id IS NOT NULL), '[]') as interfaces
       FROM hosts h
       LEFT JOIN host_interfaces hi ON hi.host_id = h.id
       WHERE h.id=$1
       GROUP BY h.id`,
      [hostId]
    );

    if (!hostRes.rows[0]) continue;
    const host = hostRes.rows[0];

    const currentPolicyInterfaceScope =
      currentPolicy.interface_scope_type === 'ALL_INTERFACES'
        ? { type: 'ALL_INTERFACES' as const }
        : currentPolicy.interface_scope_type === 'INTERFACE_NAME'
          ? { type: 'INTERFACE_NAME' as const, names: (currentPolicy.interface_scope_names ?? []) as string[] }
          : { type: 'INTERFACE_ROLE' as const, roles: (currentPolicy.interface_scope_roles ?? []) as string[] };

    const candidatePolicyInterfaceScope =
      candidatePolicy.interface_scope_type === 'ALL_INTERFACES'
        ? { type: 'ALL_INTERFACES' as const }
        : candidatePolicy.interface_scope_type === 'INTERFACE_NAME'
          ? { type: 'INTERFACE_NAME' as const, names: (candidatePolicy.interface_scope_names ?? []) as string[] }
          : { type: 'INTERFACE_ROLE' as const, roles: (candidatePolicy.interface_scope_roles ?? []) as string[] };

    // Categorize changes
    const newAllows: PolicyDiffRule[] = [];
    const removedAllows: PolicyDiffRule[] = [];
    const newDenies: PolicyDiffRule[] = [];
    const removedDenies: PolicyDiffRule[] = [];

    for (const rule of addedRules) {
      const diffRule: PolicyDiffRule = {
        type: 'added',
        orderIndex: rule.orderIndex,
        direction: rule.direction,
        action: rule.action,
        protocol: rule.protocol,
        ports: rule.ports || undefined,
        sourceType: rule.sourceType,
        sourceValue: rule.sourceValue,
        comment: rule.comment || undefined
      };

      if (rule.action === 'ALLOW') {
        newAllows.push(diffRule);
      } else {
        newDenies.push(diffRule);
      }
    }

    for (const rule of removedRules) {
      const diffRule: PolicyDiffRule = {
        type: 'removed',
        orderIndex: rule.orderIndex,
        direction: rule.direction,
        action: rule.action,
        protocol: rule.protocol,
        ports: rule.ports || undefined,
        sourceType: rule.sourceType,
        sourceValue: rule.sourceValue,
        comment: rule.comment || undefined
      };

      if (rule.action === 'ALLOW') {
        removedAllows.push(diffRule);
      } else {
        removedDenies.push(diffRule);
      }
    }

    results.push({
      hostId: host.id,
      hostname: host.hostname,
      changes: {
        newAllows,
        removedAllows,
        newDenies,
        removedDenies
      },
      summary: {
        totalNewAllows: newAllows.length,
        totalRemovedAllows: removedAllows.length,
        totalNewDenies: newDenies.length,
        totalRemovedDenies: removedDenies.length
      }
    });
  }

  return results;
}
