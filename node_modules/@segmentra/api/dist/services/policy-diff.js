import { pool } from '../db/pool.js';
/**
 * Compare two policy versions and generate a diff for sample hosts.
 * Returns semantic diff showing what rules were added/removed/modified.
 */
export async function comparePolicyVersions(params) {
    const results = [];
    // Get both policy versions
    const [currentPolicyRes, candidatePolicyRes] = await Promise.all([
        pool.query(`SELECT interface_scope_type, interface_scope_roles, interface_scope_names
       FROM policy_versions WHERE id=$1`, [params.currentVersionId]),
        pool.query(`SELECT interface_scope_type, interface_scope_roles, interface_scope_names
       FROM policy_versions WHERE id=$1`, [params.candidateVersionId])
    ]);
    if (!currentPolicyRes.rows[0] || !candidatePolicyRes.rows[0]) {
        throw new Error('Policy version not found');
    }
    const currentPolicy = currentPolicyRes.rows[0];
    const candidatePolicy = candidatePolicyRes.rows[0];
    // Get rules for both versions
    const [currentRulesRes, candidateRulesRes] = await Promise.all([
        pool.query(`SELECT order_index, direction, action, protocol, ports, source_type, source_value, comment
       FROM policy_rules
       WHERE policy_version_id=$1
       ORDER BY order_index ASC`, [params.currentVersionId]),
        pool.query(`SELECT order_index, direction, action, protocol, ports, source_type, source_value, comment
       FROM policy_rules
       WHERE policy_version_id=$1
       ORDER BY order_index ASC`, [params.candidateVersionId])
    ]);
    // Normalize rules for comparison (create signature)
    const normalizeRule = (r) => ({
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
    const ruleSignature = (r) => `${r.direction}|${r.action}|${r.protocol}|${r.ports || '*'}|${r.sourceType}|${r.sourceValue}`;
    const currentSignatures = new Set(currentRules.map(ruleSignature));
    const candidateSignatures = new Set(candidateRules.map(ruleSignature));
    // Find added and removed rules
    const addedRules = [];
    const removedRules = [];
    for (const rule of candidateRules) {
        if (!currentSignatures.has(ruleSignature(rule))) {
            addedRules.push(rule);
        }
    }
    for (const rule of currentRules) {
        if (!candidateSignatures.has(ruleSignature(rule))) {
            removedRules.push(rule);
        }
    }
    // Get management VLAN CIDRs
    const mgmtVlanRes = await pool.query(`SELECT value FROM system_settings WHERE key='management_vlan_id'`);
    const mgmtVlanId = mgmtVlanRes.rows[0]?.value || null;
    let mgmtSshCidrs = [];
    if (mgmtVlanId) {
        const vlanRes = await pool.query(`SELECT subnet FROM vlans WHERE id=$1`, [mgmtVlanId]);
        if (vlanRes.rows[0]?.subnet) {
            mgmtSshCidrs = [vlanRes.rows[0].subnet];
        }
    }
    // Process each host
    for (const hostId of params.hostIds) {
        const hostRes = await pool.query(`SELECT h.id, h.hostname, h.mgmt_ip, h.firewall_backend,
              COALESCE(json_agg(json_build_object('name', hi.name, 'role', hi.role, 'enabled', hi.enabled)) FILTER (WHERE hi.id IS NOT NULL), '[]') as interfaces
       FROM hosts h
       LEFT JOIN host_interfaces hi ON hi.host_id = h.id
       WHERE h.id=$1
       GROUP BY h.id`, [hostId]);
        if (!hostRes.rows[0])
            continue;
        const host = hostRes.rows[0];
        const currentPolicyInterfaceScope = currentPolicy.interface_scope_type === 'ALL_INTERFACES'
            ? { type: 'ALL_INTERFACES' }
            : currentPolicy.interface_scope_type === 'INTERFACE_NAME'
                ? { type: 'INTERFACE_NAME', names: (currentPolicy.interface_scope_names ?? []) }
                : { type: 'INTERFACE_ROLE', roles: (currentPolicy.interface_scope_roles ?? []) };
        const candidatePolicyInterfaceScope = candidatePolicy.interface_scope_type === 'ALL_INTERFACES'
            ? { type: 'ALL_INTERFACES' }
            : candidatePolicy.interface_scope_type === 'INTERFACE_NAME'
                ? { type: 'INTERFACE_NAME', names: (candidatePolicy.interface_scope_names ?? []) }
                : { type: 'INTERFACE_ROLE', roles: (candidatePolicy.interface_scope_roles ?? []) };
        // Categorize changes
        const newAllows = [];
        const removedAllows = [];
        const newDenies = [];
        const removedDenies = [];
        for (const rule of addedRules) {
            const diffRule = {
                type: 'added',
                orderIndex: 0, // Will be set from candidate rules
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
            }
            else {
                newDenies.push(diffRule);
            }
        }
        for (const rule of removedRules) {
            const diffRule = {
                type: 'removed',
                orderIndex: 0, // Will be set from current rules
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
            }
            else {
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
