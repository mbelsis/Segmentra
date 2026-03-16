import { pool } from '../db/pool.js';

// Sensitive ports that should not be open to 0.0.0.0/0
const SENSITIVE_PORTS = [22, 23, 3389, 5900, 3306, 5432, 1433, 1521, 27017, 6379, 9200, 8080, 8443];
const SENSITIVE_PORT_NAMES: Record<number, string> = {
  22: 'SSH', 23: 'Telnet', 3389: 'RDP', 5900: 'VNC',
  3306: 'MySQL', 5432: 'PostgreSQL', 1433: 'MSSQL', 1521: 'Oracle',
  27017: 'MongoDB', 6379: 'Redis', 9200: 'Elasticsearch',
  8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
};

export interface AuditFinding {
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: string;
  title: string;
  description: string;
  policySetName?: string;
  policyVersionId?: string;
  versionNumber?: number;
  ruleId?: string;
  hostCount?: number;
  details?: Record<string, any>;
}

export async function runExcessiveRulesAudit(): Promise<{
  findings: AuditFinding[];
  summary: { critical: number; high: number; medium: number; low: number; info: number; total: number };
}> {
  const findings: AuditFinding[] = [];

  // 1. Find rules with source 0.0.0.0/0 on sensitive ports (DEPLOYED policies)
  const { rows: wideOpenRules } = await pool.query(
    `SELECT pr.*, pv.version_number, pv.status, ps.name as policy_set_name, ps.id as policy_set_id
     FROM policy_rules pr
     JOIN policy_versions pv ON pv.id = pr.policy_version_id
     JOIN policy_sets ps ON ps.id = pv.policy_set_id
     WHERE pr.source_type = 'CIDR'
       AND pr.source_value = '0.0.0.0/0'
       AND pr.action = 'ALLOW'
       AND pr.direction IN ('IN', 'BOTH')
       AND pv.status IN ('DEPLOYED', 'APPROVED')
     ORDER BY ps.name, pv.version_number`
  );

  for (const rule of wideOpenRules) {
    const ports = parsePorts(rule.ports);
    const sensitiveMatches = ports.filter(p => SENSITIVE_PORTS.includes(p));

    if (sensitiveMatches.length > 0) {
      findings.push({
        severity: 'critical',
        category: 'Wide Open Sensitive Port',
        title: `${sensitiveMatches.map(p => `${SENSITIVE_PORT_NAMES[p] || p}/${p}`).join(', ')} open to ANY source`,
        description: `Rule allows inbound ${rule.protocol.toUpperCase()} on sensitive port(s) from 0.0.0.0/0 (any source). This exposes management/database services to the entire network or internet.`,
        policySetName: rule.policy_set_name,
        policyVersionId: rule.policy_version_id,
        versionNumber: rule.version_number,
        ruleId: rule.id,
        details: { ports: sensitiveMatches, protocol: rule.protocol, direction: rule.direction },
      });
    } else if (!rule.ports || rule.ports === '' || rule.ports === '*') {
      findings.push({
        severity: 'critical',
        category: 'Wide Open All Ports',
        title: `ALL ports open to ANY source (0.0.0.0/0)`,
        description: `Rule allows inbound ${rule.protocol.toUpperCase()} on ALL ports from any source. This is extremely permissive and likely unnecessary.`,
        policySetName: rule.policy_set_name,
        policyVersionId: rule.policy_version_id,
        versionNumber: rule.version_number,
        ruleId: rule.id,
        details: { protocol: rule.protocol, direction: rule.direction },
      });
    }
  }

  // 2. Find rules with very broad CIDR sources (/0 to /8)
  const { rows: broadCidrRules } = await pool.query(
    `SELECT pr.*, pv.version_number, ps.name as policy_set_name
     FROM policy_rules pr
     JOIN policy_versions pv ON pv.id = pr.policy_version_id
     JOIN policy_sets ps ON ps.id = pv.policy_set_id
     WHERE pr.source_type = 'CIDR'
       AND pr.action = 'ALLOW'
       AND pr.direction IN ('IN', 'BOTH')
       AND pr.source_value != '0.0.0.0/0'
       AND pv.status IN ('DEPLOYED', 'APPROVED')`
  );

  for (const rule of broadCidrRules) {
    const cidrMatch = rule.source_value.match(/\/(\d+)$/);
    if (cidrMatch) {
      const prefix = parseInt(cidrMatch[1]);
      if (prefix <= 8) {
        findings.push({
          severity: 'high',
          category: 'Very Broad Source CIDR',
          title: `Source ${rule.source_value} (/${prefix}) covers ${Math.pow(2, 32 - prefix).toLocaleString()} IPs`,
          description: `Rule allows inbound traffic from an extremely broad source range. Consider narrowing to specific subnets.`,
          policySetName: rule.policy_set_name,
          policyVersionId: rule.policy_version_id,
          versionNumber: rule.version_number,
          ruleId: rule.id,
          details: { source: rule.source_value, prefix, ipCount: Math.pow(2, 32 - prefix) },
        });
      }
    }
  }

  // 3. Find protocol:any + no port restriction rules
  const { rows: anyAnyRules } = await pool.query(
    `SELECT pr.*, pv.version_number, ps.name as policy_set_name
     FROM policy_rules pr
     JOIN policy_versions pv ON pv.id = pr.policy_version_id
     JOIN policy_sets ps ON ps.id = pv.policy_set_id
     WHERE pr.protocol = 'any'
       AND pr.action = 'ALLOW'
       AND (pr.ports IS NULL OR pr.ports = '' OR pr.ports = '*')
       AND pv.status IN ('DEPLOYED', 'APPROVED')`
  );

  for (const rule of anyAnyRules) {
    findings.push({
      severity: 'high',
      category: 'Any Protocol / Any Port',
      title: `Rule allows ALL protocols and ALL ports`,
      description: `Rule with protocol=any and no port restriction. This is effectively "allow everything" for the matched source. Consider restricting to specific protocols and ports.`,
      policySetName: rule.policy_set_name,
      policyVersionId: rule.policy_version_id,
      versionNumber: rule.version_number,
      ruleId: rule.id,
      details: { sourceType: rule.source_type, sourceValue: rule.source_value, direction: rule.direction },
    });
  }

  // 4. Find ALL_INTERFACES scope with broad sources
  const { rows: allIfaceRules } = await pool.query(
    `SELECT pv.id as version_id, pv.version_number, pv.interface_scope_type, ps.name as policy_set_name,
       (SELECT COUNT(*)::int FROM policy_rules pr WHERE pr.policy_version_id = pv.id AND pr.source_type = 'CIDR' AND pr.source_value = '0.0.0.0/0' AND pr.action = 'ALLOW') as wide_open_count
     FROM policy_versions pv
     JOIN policy_sets ps ON ps.id = pv.policy_set_id
     WHERE pv.interface_scope_type = 'ALL_INTERFACES'
       AND pv.status IN ('DEPLOYED', 'APPROVED')`
  );

  for (const v of allIfaceRules) {
    if (v.wide_open_count > 0) {
      findings.push({
        severity: 'high',
        category: 'ALL_INTERFACES + Broad Source',
        title: `Policy applies to ALL interfaces with ${v.wide_open_count} wide-open rule(s)`,
        description: `Policy version uses ALL_INTERFACES scope and contains rules allowing traffic from any source. This means management, data, and backup interfaces are all exposed.`,
        policySetName: v.policy_set_name,
        policyVersionId: v.version_id,
        versionNumber: v.version_number,
        details: { wideOpenRuleCount: v.wide_open_count },
      });
    }
  }

  // 5. Find duplicate rules across policy sets
  const { rows: duplicates } = await pool.query(
    `SELECT pr.direction, pr.action, pr.protocol, pr.ports, pr.source_type, pr.source_value,
       array_agg(DISTINCT ps.name) as policy_sets, COUNT(DISTINCT ps.id)::int as policy_count
     FROM policy_rules pr
     JOIN policy_versions pv ON pv.id = pr.policy_version_id
     JOIN policy_sets ps ON ps.id = pv.policy_set_id
     WHERE pv.status IN ('DEPLOYED', 'APPROVED')
     GROUP BY pr.direction, pr.action, pr.protocol, pr.ports, pr.source_type, pr.source_value
     HAVING COUNT(DISTINCT ps.id) > 1`
  );

  for (const dup of duplicates) {
    findings.push({
      severity: 'low',
      category: 'Duplicate Rule',
      title: `Same rule exists in ${dup.policy_count} policy sets`,
      description: `${dup.action} ${dup.protocol.toUpperCase()}${dup.ports ? '/' + dup.ports : ''} from ${dup.source_type}:${dup.source_value} (${dup.direction}) appears in: ${dup.policy_sets.join(', ')}. Consider consolidating.`,
      details: { policySets: dup.policy_sets, direction: dup.direction, protocol: dup.protocol, ports: dup.ports, sourceType: dup.source_type, sourceValue: dup.source_value },
    });
  }

  // 6. Find hosts with no deployed policy (unmanaged)
  const { rows: unmanagedHosts } = await pool.query(
    `SELECT h.id, h.hostname, h.mgmt_ip
     FROM hosts h
     WHERE h.enabled = true
       AND NOT EXISTS (
         SELECT 1 FROM deployment_hosts dh
         JOIN deployments d ON d.id = dh.deployment_id
         WHERE dh.host_id = h.id AND dh.status = 'SUCCEEDED'
       )
     ORDER BY h.hostname`
  );

  if (unmanagedHosts.length > 0) {
    findings.push({
      severity: 'medium',
      category: 'Unmanaged Hosts',
      title: `${unmanagedHosts.length} host(s) have no deployed firewall policy`,
      description: `These hosts are in the inventory but have never had a policy successfully deployed. They may be running with default-open firewall rules.`,
      hostCount: unmanagedHosts.length,
      details: { hosts: unmanagedHosts.slice(0, 20).map((h: any) => ({ hostname: h.hostname, ip: h.mgmt_ip })) },
    });
  }

  // 7. Find policies deployed > 90 days without version change
  const { rows: staleDeployments } = await pool.query(
    `SELECT DISTINCT ON (dh.host_id) h.hostname, h.mgmt_ip, d.created_at as deployed_at,
       ps.name as policy_set_name, pv.version_number,
       EXTRACT(DAY FROM now() - d.created_at)::int as days_since_deploy
     FROM deployment_hosts dh
     JOIN deployments d ON d.id = dh.deployment_id
     JOIN hosts h ON h.id = dh.host_id
     JOIN policy_versions pv ON pv.id = d.policy_version_id
     JOIN policy_sets ps ON ps.id = pv.policy_set_id
     WHERE dh.status = 'SUCCEEDED' AND h.enabled = true
     ORDER BY dh.host_id, d.created_at DESC`
  );

  const staleHosts = staleDeployments.filter((d: any) => d.days_since_deploy > 90);
  if (staleHosts.length > 0) {
    findings.push({
      severity: 'medium',
      category: 'Stale Policies',
      title: `${staleHosts.length} host(s) have policies deployed over 90 days ago without review`,
      description: `These hosts have not had a policy update in over 90 days. Consider reviewing whether the rules are still appropriate.`,
      hostCount: staleHosts.length,
      details: { hosts: staleHosts.slice(0, 20).map((h: any) => ({ hostname: h.hostname, policy: h.policy_set_name, daysAgo: h.days_since_deploy })) },
    });
  }

  // 8. Find hosts with compliance drift
  const { rows: driftedHosts } = await pool.query(
    `SELECT COUNT(*)::int as count FROM (
       SELECT DISTINCT ON (dh.host_id) dh.host_id, dh.applied_hash
       FROM deployment_hosts dh
       JOIN deployments d ON d.id = dh.deployment_id
       JOIN hosts h ON h.id = dh.host_id
       WHERE dh.status = 'SUCCEEDED' AND h.enabled = true
       ORDER BY dh.host_id, d.created_at DESC
     ) latest
     WHERE latest.applied_hash IS NOT NULL`
  );
  // Note: actual drift check requires SSH — this just counts hosts that could be checked

  // Summary
  const summary = {
    critical: findings.filter(f => f.severity === 'critical').length,
    high: findings.filter(f => f.severity === 'high').length,
    medium: findings.filter(f => f.severity === 'medium').length,
    low: findings.filter(f => f.severity === 'low').length,
    info: findings.filter(f => f.severity === 'info').length,
    total: findings.length,
  };

  return { findings, summary };
}

function parsePorts(portsStr: string | null): number[] {
  if (!portsStr || portsStr === '' || portsStr === '*') return [];
  const ports: number[] = [];
  for (const part of portsStr.split(',')) {
    const range = part.trim().split('-');
    if (range.length === 2) {
      const start = parseInt(range[0]);
      const end = parseInt(range[1]);
      for (let p = start; p <= end && p <= start + 100; p++) ports.push(p);
    } else {
      const p = parseInt(range[0]);
      if (!isNaN(p)) ports.push(p);
    }
  }
  return ports;
}
