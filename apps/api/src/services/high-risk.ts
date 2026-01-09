import { pool } from '../db/pool.js';

/**
 * Evaluates if a policy version is high-risk based on heuristics:
 * - Wide interface scope + many targets
 * - Very broad source (internet-like) to sensitive ports
 * - Opening management/administrative access beyond the management VLAN
 * - Big "any/any" style rules
 */
export async function isPolicyVersionHighRisk(params: {
  policyVersionId: string;
  // Optional: how many hosts this will target (deployment target_count)
  targetCount?: number;
}): Promise<boolean> {
  const { policyVersionId, targetCount } = params;

  // 1) Load policy version + rules
  const [vRes, rRes] = await Promise.all([
    pool.query(
      `SELECT interface_scope_type
       FROM policy_versions
       WHERE id = $1`,
      [policyVersionId]
    ),
    pool.query(
      `SELECT action, protocol, ports, source_type, source_value, direction
       FROM policy_rules
       WHERE policy_version_id = $1`,
      [policyVersionId]
    )
  ]);

  const version = vRes.rows[0];
  if (!version) return false;
  const rules = rRes.rows;

  // 2) Heuristic 1: ALL_INTERFACES + many targets
  if (
    version.interface_scope_type === 'ALL_INTERFACES' &&
    typeof targetCount === 'number' &&
    targetCount >= 20 // tune threshold
  ) {
    return true;
  }

  // Helper: parse ports into ranges
  function isWidePortRange(ports: string | null): boolean {
    if (!ports) return false;
    const p = ports.trim();
    if (!p) return false;
    // quick checks – you can tighten this later
    if (p === '1-65535' || p === '0-65535') return true;
    // multiple entries: "22,80,443" or "1-65535,8080"
    const parts = p.split(',').map(x => x.trim());
    return parts.some(part => part === '1-65535' || part === '0-65535');
  }

  // broad CIDRs to consider "internet-wide"
  const veryBroadCidrs = new Set([
    '0.0.0.0/0',
    '0.0.0.0/1',
    '128.0.0.0/1'
  ]);

  function isVeryBroadCidr(cidr: string): boolean {
    if (!cidr) return false;
    if (veryBroadCidrs.has(cidr)) return true;
    const m = cidr.match(/^(\d+\.\d+\.\d+\.\d+)\/(\d{1,2})$/);
    if (!m) return false;
    const prefix = parseInt(m[2], 10);
    return prefix >= 0 && prefix <= 8; // /0–/8 are extremely broad
  }

  // "sensitive" ports to watch (you can expand/tune)
  const sensitivePorts = new Set(['22', '5432', '3306', '1433', '3389']);
  function allowsSensitivePort(ports: string | null): boolean {
    if (!ports) return false;
    const parts = ports.split(',').map(x => x.trim());
    for (const p of parts) {
      if (sensitivePorts.has(p)) return true;
      // Check for ranges that include sensitive ports (e.g., "20-25" includes 22)
      if (p.includes('-')) {
        const [start, end] = p.split('-').map(x => parseInt(x.trim(), 10));
        if (!isNaN(start) && !isNaN(end)) {
          for (const sensitivePort of Array.from(sensitivePorts).map(Number)) {
            if (sensitivePort >= start && sensitivePort <= end) return true;
          }
        }
      }
    }
    return false;
  }

  // Get management VLAN CIDRs for SSH access check
  const mgmtVlanRes = await pool.query(
    `SELECT value FROM system_settings WHERE key='management_vlan_id'`
  );
  const mgmtVlanId = mgmtVlanRes.rows[0]?.value || null;
  const mgmtCidrs = new Set<string>();
  if (mgmtVlanId) {
    const vlanRes = await pool.query(`SELECT subnet FROM vlans WHERE id=$1`, [mgmtVlanId]);
    if (vlanRes.rows[0]?.subnet) {
      mgmtCidrs.add(vlanRes.rows[0].subnet);
    }
  }

  // Helper to check if CIDR matches management VLAN
  function isManagementCidr(cidr: string): boolean {
    if (mgmtCidrs.has(cidr)) return true;
    // Could add more sophisticated CIDR matching here if needed
    return false;
  }

  // 3) Scan rules for various high-risk patterns
  for (const r of rules) {
    const action: string = r.action;
    const proto: string = r.protocol;
    const ports: string | null = r.ports;
    const sourceType: string = r.source_type;
    const sourceValue: string = r.source_value;

    // Only consider ALLOW rules for "opening things up"
    if (action !== 'ALLOW') continue;

    // (a) Very broad CIDR to sensitive ports
    if (
      sourceType === 'CIDR' &&
      isVeryBroadCidr(sourceValue) &&
      (allowsSensitivePort(ports) || isWidePortRange(ports))
    ) {
      return true;
    }

    // (b) Any/any style
    if (
      proto === 'any' &&
      (isWidePortRange(ports) || !ports) &&
      (sourceType === 'CIDR' && isVeryBroadCidr(sourceValue))
    ) {
      return true;
    }

    // (c) SSH/management ports from "anywhere" (not just mgmt VLAN)
    if (proto === 'tcp' && allowsSensitivePort(ports)) {
      if (sourceType === 'CIDR') {
        // If it's a very broad CIDR or not the management VLAN, it's high-risk
        if (isVeryBroadCidr(sourceValue) || !isManagementCidr(sourceValue)) {
          return true;
        }
      } else if (sourceType === 'TAG' || sourceType === 'VLAN') {
        // TAG/VLAN sources that aren't the management VLAN are potentially risky
        // For now, we'll be conservative and mark TAG/VLAN sources as risky for SSH
        // (could be refined to check if the TAG/VLAN is the management VLAN)
        return true;
      }
    }
  }

  return false;
}
