import { compileHostPolicy } from '@segmentra/compiler';
import { pool } from '../db/pool.js';
/**
 * Check if a deployment would preserve SSH access from management VLAN.
 * Returns safety check result with warnings/errors.
 */
export async function checkDeploymentSafety(params) {
    const result = {
        safe: true,
        warnings: [],
        errors: [],
        sshAccessPreserved: false,
        blockingRules: []
    };
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
    if (mgmtSshCidrs.length === 0) {
        result.warnings.push('No management VLAN configured - cannot verify SSH access preservation');
        return result;
    }
    // Get policy version
    const policyRes = await pool.query(`SELECT interface_scope_type, interface_scope_roles, interface_scope_names
     FROM policy_versions WHERE id=$1`, [params.policyVersionId]);
    if (!policyRes.rows[0]) {
        result.errors.push('Policy version not found');
        result.safe = false;
        return result;
    }
    const policy = policyRes.rows[0];
    const policyInterfaceScope = policy.interface_scope_type === 'ALL_INTERFACES'
        ? { type: 'ALL_INTERFACES' }
        : policy.interface_scope_type === 'INTERFACE_NAME'
            ? { type: 'INTERFACE_NAME', names: (policy.interface_scope_names ?? []) }
            : { type: 'INTERFACE_ROLE', roles: (policy.interface_scope_roles ?? []) };
    // Get rules
    const rulesRes = await pool.query(`SELECT order_index, direction, action, protocol, ports, source_type, source_value, comment
     FROM policy_rules
     WHERE policy_version_id=$1
     ORDER BY order_index ASC`, [params.policyVersionId]);
    // Check each host
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
        // Compile policy for this host to check baseline SSH rules
        const rules = rulesRes.rows.map((r) => ({
            orderIndex: Number(r.order_index),
            direction: (r.direction ?? 'IN'),
            action: r.action,
            protocol: r.protocol,
            ports: r.ports,
            sourceType: r.source_type,
            sourceValue: r.source_value,
            logMode: 'NONE',
            comment: r.comment,
            usePolicyInterfaceScope: true,
            remote: r.source_type === 'CIDR' ? { kind: 'CIDR' } : { kind: 'SET', setName: `src_${r.source_type.toLowerCase()}_${String(r.source_value).replace(/-/g, '')}` }
        }));
        // Resolve sets (simplified - just check CIDR rules for now)
        const sets = {};
        const compiled = compileHostPolicy({
            host: {
                id: host.id,
                hostname: host.hostname,
                mgmtIp: host.mgmt_ip ? String(host.mgmt_ip) : null,
                firewallBackend: host.firewall_backend === 'iptables' ? 'iptables' : 'nftables',
                interfaces: JSON.parse(host.interfaces || '[]')
            },
            policyInterfaceScope,
            rules,
            sets,
            baseline: { mgmtSshCidrs }
        });
        // Check if compiled text contains SSH allow rules for management CIDRs
        const hasSshAllow = mgmtSshCidrs.some(cidr => {
            // Check for SSH allow rules in compiled text
            // For nftables: look for "tcp dport 22 accept" with mgmt CIDR
            // For iptables: look for "-A INPUT -p tcp --dport 22 -j ACCEPT" with mgmt CIDR
            if (compiled.backend === 'nftables') {
                return compiled.text.includes(`ip saddr ${cidr}`) && compiled.text.includes('tcp dport 22 accept');
            }
            else {
                return compiled.text.includes(cidr) && compiled.text.includes('--dport 22') && compiled.text.includes('-j ACCEPT');
            }
        });
        if (!hasSshAllow) {
            result.errors.push(`Host ${host.hostname}: Compiled policy does not preserve SSH access from management VLAN`);
            result.safe = false;
        }
        else {
            result.sshAccessPreserved = true;
        }
        // Check if user's IP would be blocked (if provided)
        if (params.userIp) {
            // Simple check: see if any DENY rule would block user's IP before an ALLOW rule
            // This is a simplified check - full implementation would need proper rule evaluation
            const userIpBlocked = rules.some((r) => {
                if (r.action === 'DENY' && r.direction !== 'OUT') {
                    // Check if source matches user IP (simplified CIDR check)
                    if (r.sourceType === 'CIDR') {
                        // Basic CIDR check (simplified)
                        return r.sourceValue.includes(params.userIp.split('.')[0]);
                    }
                }
                return false;
            });
            if (userIpBlocked) {
                result.warnings.push(`Your IP (${params.userIp}) may be blocked by DENY rules`);
            }
        }
    }
    return result;
}
