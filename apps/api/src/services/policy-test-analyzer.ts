import { pool } from '../db/pool.js';
import type { CommunicationFlow } from './log-parser.js';
import { cidrContains } from './ip-utils.js';

// Helper: check if an IP matches a CIDR (IPv4 or IPv6; a bare IP is a /32 or /128)
function ipMatchesCidr(ip: string, cidr: string): boolean {
  return cidrContains(String(cidr).trim(), String(ip).split('/')[0]);
}

function portMatches(port: number | undefined, portSpec: string | null): boolean {
  if (!portSpec || portSpec === '' || portSpec === '*') return true;
  if (port === undefined) return true;
  for (const part of portSpec.split(',')) {
    const range = part.trim().split('-');
    if (range.length === 2) {
      if (port >= parseInt(range[0]) && port <= parseInt(range[1])) return true;
    } else {
      if (port === parseInt(range[0])) return true;
    }
  }
  return false;
}

interface AnalysisResult {
  matchedFlows: Array<{
    flow: CommunicationFlow;
    matchedRule: any;
    expectedAction: string;
  }>;
  unmatchedFlows: Array<{
    flow: CommunicationFlow;
    reason: string;
  }>;
  unexpectedBlocks: Array<{
    flow: CommunicationFlow;
    blockingRule: any;
  }>;
  unexpectedAllows: Array<{
    flow: CommunicationFlow;
    reason: string;
  }>;
  summary: {
    totalFlows: number;
    matched: number;
    unmatched: number;
    unexpectedBlocks: number;
    unexpectedAllows: number;
    coveragePercent: number;
  };
}

async function resolveSourceValue(rule: any): Promise<string[]> {
  const ips: string[] = [];
  if (rule.source_type === 'CIDR') {
    ips.push(rule.source_value);
  } else if (rule.source_type === 'TAG') {
    const { rows } = await pool.query(
      `SELECT h.mgmt_ip FROM hosts h
       JOIN host_tags ht ON ht.host_id = h.id
       WHERE ht.tag_id = $1 AND h.enabled = true`,
      [rule.source_value]
    );
    for (const r of rows) ips.push(r.mgmt_ip);
  } else if (rule.source_type === 'VLAN') {
    const { rows } = await pool.query(
      `SELECT h.mgmt_ip FROM hosts h WHERE h.vlan_id = $1 AND h.enabled = true`,
      [rule.source_value]
    );
    for (const r of rows) ips.push(r.mgmt_ip);

    // Also check VLAN subnet
    const { rows: vlans } = await pool.query(`SELECT subnet FROM vlans WHERE id = $1`, [rule.source_value]);
    if (vlans[0]?.subnet) ips.push(vlans[0].subnet);
  } else if (rule.source_type === 'HOST') {
    const { rows } = await pool.query(`SELECT mgmt_ip FROM hosts WHERE id = $1`, [rule.source_value]);
    if (rows[0]) ips.push(rows[0].mgmt_ip);
  }
  return ips;
}

function doesFlowMatchRule(flow: CommunicationFlow, rule: any, sourceIps: string[]): boolean {
  // Check direction
  if (rule.direction !== 'BOTH' && rule.direction !== flow.direction) return false;

  // Check protocol
  if (rule.protocol !== 'any' && rule.protocol !== flow.protocol) return false;

  // Check ports
  if (!portMatches(flow.destinationPort, rule.ports)) return false;

  // Check source IP
  const flowSourceIp = flow.direction === 'IN' ? flow.sourceIp : flow.destinationIp;
  const matchesSource = sourceIps.some(sip => {
    if (sip.includes('/')) return ipMatchesCidr(flowSourceIp, sip);
    return sip === flowSourceIp;
  });

  // For CIDR 0.0.0.0/0, always match
  if (rule.source_type === 'CIDR' && rule.source_value === '0.0.0.0/0') return true;

  return matchesSource;
}

export async function analyzePolicyTest(sessionId: string): Promise<AnalysisResult> {
  const { rows: sessions } = await pool.query(
    `SELECT * FROM policy_test_sessions WHERE id = $1`,
    [sessionId]
  );
  if (!sessions[0]) throw new Error('Test session not found');
  const session = sessions[0];

  // Get policy rules
  const { rows: rules } = await pool.query(
    `SELECT * FROM policy_rules WHERE policy_version_id = $1 ORDER BY order_index ASC`,
    [session.policy_version_id]
  );

  // Pre-resolve source IPs for all rules
  const ruleSourceIps = new Map<string, string[]>();
  for (const rule of rules) {
    ruleSourceIps.set(rule.id, await resolveSourceValue(rule));
  }

  // Parse flows from raw log data. Reply traffic accepted by the baseline established/related
  // rule is not a flow the policy decides on, so it is not analyzed.
  const flows: CommunicationFlow[] = (session.raw_log_data?.flows ?? []).filter((f: CommunicationFlow) => !f.established);

  // Baseline of every compiled policy (see packages/compiler): SSH from the management VLAN is
  // always allowed before any policy rule, and outbound traffic is allowed by default.
  const { rows: hostRows } = await pool.query(`SELECT ssh_port FROM hosts WHERE id = $1`, [session.host_id]);
  const sshPort = Number(hostRows[0]?.ssh_port) || 22;
  const { rows: mgmtRows } = await pool.query(
    `SELECT v.subnet FROM system_settings s JOIN vlans v ON v.id::text = s.value WHERE s.key = 'management_vlan_id'`
  );
  const mgmtCidrs: string[] = mgmtRows.map((r: any) => String(r.subnet)).filter(Boolean);
  const isMgmtSsh = (f: CommunicationFlow) =>
    f.direction === 'IN' && f.protocol === 'tcp' && f.destinationPort === sshPort &&
    (mgmtCidrs.length === 0 || mgmtCidrs.some((c) => ipMatchesCidr(f.sourceIp, c)));

  const result: AnalysisResult = {
    matchedFlows: [],
    unmatchedFlows: [],
    unexpectedBlocks: [],
    unexpectedAllows: [],
    summary: { totalFlows: 0, matched: 0, unmatched: 0, unexpectedBlocks: 0, unexpectedAllows: 0, coveragePercent: 0 },
  };

  for (const flow of flows) {
    result.summary.totalFlows++;
    let matched = false;

    if (isMgmtSsh(flow)) {
      result.matchedFlows.push({ flow, matchedRule: { comment: 'baseline: management SSH (always allowed)' }, expectedAction: 'ALLOW' });
      result.summary.matched++;
      continue;
    }

    for (const rule of rules) {
      const sourceIps = ruleSourceIps.get(rule.id) ?? [];
      if (doesFlowMatchRule(flow, rule, sourceIps)) {
        matched = true;
        if (rule.action === 'DENY') {
          result.unexpectedBlocks.push({ flow, blockingRule: rule });
          result.summary.unexpectedBlocks++;
        } else {
          result.matchedFlows.push({ flow, matchedRule: rule, expectedAction: rule.action });
          result.summary.matched++;
        }
        break;
      }
    }

    if (!matched && flow.direction === 'OUT') {
      // Outbound default is allow
      result.matchedFlows.push({ flow, matchedRule: { comment: 'default: outbound traffic is allowed' }, expectedAction: 'ALLOW' });
      result.summary.matched++;
    } else if (!matched) {
      // Default deny — this flow would be blocked
      result.unexpectedAllows.push({
        flow,
        reason: 'No matching rule found — default-deny would block this traffic',
      });
      result.summary.unexpectedAllows++;
    }
  }

  result.summary.unmatched = result.summary.unexpectedAllows;
  result.summary.coveragePercent = result.summary.totalFlows > 0
    ? Math.round((result.summary.matched / result.summary.totalFlows) * 10000) / 100
    : 100;

  // Save analysis results
  await pool.query(
    `UPDATE policy_test_sessions SET analysis_results = $2, status = 'COMPLETED', completed_at = now() WHERE id = $1`,
    [sessionId, JSON.stringify(result)]
  );

  return result;
}
