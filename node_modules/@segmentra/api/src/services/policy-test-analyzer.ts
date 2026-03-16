import { pool } from '../db/pool.js';
import type { CommunicationFlow } from './log-parser.js';

// Helper: check if an IP matches a CIDR
function ipMatchesCidr(ip: string, cidr: string): boolean {
  try {
    const cleanIp = ip.split('/')[0];
    const [cidrIp, prefix] = cidr.split('/');
    const prefixLen = prefix ? parseInt(prefix, 10) : 32;
    if (prefixLen < 0 || prefixLen > 32) return false;
    const ipParts = cleanIp.split('.').map(Number);
    const cidrParts = cidrIp.split('.').map(Number);
    if (ipParts.length !== 4 || cidrParts.length !== 4) return false;
    const mask = prefixLen === 0 ? 0 : (0xFFFFFFFF << (32 - prefixLen)) >>> 0;
    const ipNum = (ipParts[0] << 24) + (ipParts[1] << 16) + (ipParts[2] << 8) + ipParts[3];
    const cidrNum = (cidrParts[0] << 24) + (cidrParts[1] << 16) + (cidrParts[2] << 8) + cidrParts[3];
    return (ipNum & mask) === (cidrNum & mask);
  } catch {
    return false;
  }
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

  // Parse flows from raw log data
  const flows: CommunicationFlow[] = session.raw_log_data?.flows ?? [];

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

    if (!matched) {
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
