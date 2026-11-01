import { parseRuleAddresses } from '@segmentra/compiler';

import { pool } from '../db/pool.js';
import { createDestinationResolver, getProtectedDestinations } from './forward-rules.js';
import { cidrContains } from './ip-utils.js';
import type { CommunicationFlow } from './log-parser.js';
import { managementSshSources } from './safety-check.js';
import { createSourceResolver } from './source-resolver.js';

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

type Scope = { type: 'ALL_INTERFACES' } | { type: 'INTERFACE_ROLE'; roles: string[] } | { type: 'INTERFACE_NAME'; names: string[] };

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
  /**
   * Flows whose verdict depends on the interface they used, which the log did not record: a rule
   * with an interface scope would match them, but only on its interfaces. Not counted as covered.
   */
  uncertainFlows: Array<{
    flow: CommunicationFlow;
    rule: any;
    reason: string;
  }>;
  summary: {
    totalFlows: number;
    matched: number;
    unmatched: number;
    unexpectedBlocks: number;
    unexpectedAllows: number;
    uncertain: number;
    /** FORWARD flows among totalFlows (evaluated against FORWARD rules / protected devices) */
    forwarded: number;
    coveragePercent: number;
  };
}

/**
 * The remote addresses a rule matches, resolved exactly like the deployment compiler resolves them:
 * `null` = any address ("any", "*"), otherwise a list of addresses/prefixes. CIDR values go through the
 * compiler's own parser (a value it would refuse matches nothing); HOST/TAG/VLAN through the shared
 * source resolver (HOST = the host's mgmt_ip, TAG/VLAN = mgmt_ip of the enabled member hosts — never
 * the VLAN subnet, which the compiler does not use).
 */
async function resolveSourceValue(rule: any, resolve: ReturnType<typeof createSourceResolver>): Promise<string[] | null> {
  if (rule.source_type === 'CIDR') {
    try {
      return parseRuleAddresses(String(rule.source_value ?? ''));
    } catch {
      return [];
    }
  }
  return resolve(String(rule.source_type), String(rule.source_value ?? ''));
}

async function resolveDestinationValue(rule: any, resolveDest: ReturnType<typeof createDestinationResolver>): Promise<string[] | null> {
  if (rule.destination_type === 'CIDR') {
    try {
      return parseRuleAddresses(String(rule.destination_value ?? ''));
    } catch {
      return [];
    }
  }
  if (!rule.destination_type) return [];
  return resolveDest(String(rule.destination_type), String(rule.destination_value ?? ''));
}

function scopeOf(type: string | null | undefined, roles: unknown, names: unknown): Scope | undefined {
  if (type === 'ALL_INTERFACES') return { type: 'ALL_INTERFACES' };
  if (type === 'INTERFACE_NAME') return { type: 'INTERFACE_NAME', names: (names ?? []) as string[] };
  if (type === 'INTERFACE_ROLE') return { type: 'INTERFACE_ROLE', roles: (roles ?? []) as string[] };
  return undefined;
}

/**
 * Interface names a rule is restricted to, like the compiler's ruleScope() + resolveInterfaceNames():
 * null = all interfaces; [] = a scope that matches no interface (the compiler refuses to compile such a
 * rule, so it matches nothing here).
 */
export function ruleInterfaceNames(
  rule: { use_policy_interface_scope?: boolean | null; interface_scope_type?: string | null; interface_scope_roles?: unknown; interface_scope_names?: unknown },
  policyScope: Scope,
  interfaces: Array<{ name: string; role: string; enabled: boolean }>
): string[] | null {
  const scope = rule.use_policy_interface_scope
    ? policyScope
    : scopeOf(rule.interface_scope_type, rule.interface_scope_roles, rule.interface_scope_names) ?? policyScope;
  if (scope.type === 'ALL_INTERFACES') return null;
  if (scope.type === 'INTERFACE_NAME') return Array.from(new Set(scope.names));
  return Array.from(new Set(interfaces.filter((i) => i.enabled && scope.roles.includes(i.role)).map((i) => i.name)));
}

type MatchVerdict = 'match' | 'no' | 'uncertain';

function addrIn(ip: string, list: string[] | null): boolean {
  if (list === null) return true;
  return list.some((a) => a !== null && a !== undefined && ipMatchesCidr(ip, String(a)));
}

/**
 * Does the flow match the rule? IN/OUT/BOTH rules match the host's own traffic on their interfaces
 * (inbound: kernel IN=, outbound: OUT=); FORWARD rules match forwarded flows by source AND
 * destination (interface scopes do not apply to them).
 */
export function flowMatchesRule(
  flow: CommunicationFlow,
  rule: any,
  sourceIps: string[] | null,
  ifNames: string[] | null,
  destIps: string[] | null = null
): MatchVerdict {
  const dir = rule.direction ?? 'IN';
  if (flow.direction === 'FORWARD') {
    if (dir !== 'FORWARD') return 'no';
  } else if (dir === 'FORWARD' || (dir !== 'BOTH' && dir !== flow.direction)) {
    return 'no';
  }

  // Check protocol
  if (rule.protocol !== 'any' && rule.protocol !== flow.protocol) return 'no';

  // Check ports
  if (!portMatches(flow.destinationPort, rule.ports)) return 'no';

  // Remote address: source of inbound, destination of outbound traffic. "any" matches every address;
  // otherwise family-aware containment, like the compiled rule (0.0.0.0/0 matches IPv4 only, ::/0 IPv6
  // only, and a bare address is a /32 or /128 whatever its textual form).
  if (flow.direction === 'FORWARD') {
    if (!addrIn(flow.sourceIp, sourceIps)) return 'no';
    if (!addrIn(flow.destinationIp, destIps)) return 'no';
    return 'match';
  }
  const remote = flow.direction === 'IN' ? flow.sourceIp : flow.destinationIp;
  if (!addrIn(remote, sourceIps)) return 'no';

  if (ifNames === null) return 'match';
  if (ifNames.length === 0) return 'no';
  const iface = flow.direction === 'IN' ? flow.inInterface : flow.outInterface;
  if (!iface) return 'uncertain';
  return ifNames.includes(iface) ? 'match' : 'no';
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
  const { rows: versionRows } = await pool.query(
    `SELECT interface_scope_type, interface_scope_roles, interface_scope_names FROM policy_versions WHERE id = $1`,
    [session.policy_version_id]
  );
  const v = versionRows[0] ?? {};
  // Same mapping as the deployment compile: anything but ALL_INTERFACES / INTERFACE_NAME is INTERFACE_ROLE.
  const policyScope: Scope =
    v.interface_scope_type === 'ALL_INTERFACES'
      ? { type: 'ALL_INTERFACES' }
      : v.interface_scope_type === 'INTERFACE_NAME'
        ? { type: 'INTERFACE_NAME', names: (v.interface_scope_names ?? []) as string[] }
        : { type: 'INTERFACE_ROLE', roles: (v.interface_scope_roles ?? []) as string[] };

  const { rows: hostRows } = await pool.query(`SELECT ssh_port, mgmt_ip FROM hosts WHERE id = $1`, [session.host_id]);
  const { rows: ifRows } = await pool.query(`SELECT name, role, enabled FROM host_interfaces WHERE host_id = $1`, [session.host_id]);
  const interfaces = ifRows.map((i: any) => ({ name: String(i.name), role: String(i.role ?? ''), enabled: !!i.enabled }));

  // Pre-resolve addresses and interfaces for all rules
  const resolve = createSourceResolver();
  const resolveDest = createDestinationResolver();
  const ruleSourceIps = new Map<string, string[] | null>();
  const ruleDestIps = new Map<string, string[] | null>();
  const ruleIfNames = new Map<string, string[] | null>();
  for (const rule of rules) {
    ruleSourceIps.set(rule.id, await resolveSourceValue(rule, resolve));
    if (rule.direction === 'FORWARD') ruleDestIps.set(rule.id, await resolveDestinationValue(rule, resolveDest));
    ruleIfNames.set(rule.id, rule.direction === 'FORWARD' ? null : ruleInterfaceNames(rule, policyScope, interfaces));
  }
  const hasForwardRules = rules.some((r: any) => r.direction === 'FORWARD');
  const protectedDestinations = await getProtectedDestinations(session.host_id);

  // Parse flows from raw log data. Reply traffic accepted by the baseline established/related
  // rule is not a flow the policy decides on, so it is not analyzed.
  const flows: CommunicationFlow[] = (session.raw_log_data?.flows ?? []).filter((f: CommunicationFlow) => !f.established);

  // Baseline of every compiled policy (see packages/compiler): SSH from the management sources
  // (incl. the per-family "any" fallbacks) is always allowed before any policy rule, and outbound
  // traffic is allowed by default.
  const sshPort = Number(hostRows[0]?.ssh_port) || 22;
  const { rows: mgmtRows } = await pool.query(
    `SELECT v.subnet FROM system_settings s JOIN vlans v ON v.id::text = s.value WHERE s.key = 'management_vlan_id'`
  );
  const mgmtCidrs: string[] = mgmtRows.map((r: any) => String(r.subnet ?? '')).filter(Boolean);
  const mgmt = managementSshSources(mgmtCidrs, hostRows[0]?.mgmt_ip ? String(hostRows[0].mgmt_ip) : null);
  const isMgmtSsh = (f: CommunicationFlow) =>
    f.direction === 'IN' && f.protocol === 'tcp' && f.destinationPort === sshPort &&
    mgmt.sources.some((c) => ipMatchesCidr(f.sourceIp, c));

  const result: AnalysisResult = {
    matchedFlows: [],
    unmatchedFlows: [],
    unexpectedBlocks: [],
    unexpectedAllows: [],
    uncertainFlows: [],
    summary: { totalFlows: 0, matched: 0, unmatched: 0, unexpectedBlocks: 0, unexpectedAllows: 0, uncertain: 0, forwarded: 0, coveragePercent: 0 },
  };

  for (const flow of flows) {
    result.summary.totalFlows++;
    if (flow.direction === 'FORWARD') result.summary.forwarded++;

    if (isMgmtSsh(flow)) {
      result.matchedFlows.push({ flow, matchedRule: { comment: 'baseline: management SSH (always allowed)' }, expectedAction: 'ALLOW' });
      result.summary.matched++;
      continue;
    }

    let decided = false;
    for (const rule of rules) {
      const resolved = ruleSourceIps.get(rule.id);
      const sourceIps = resolved === undefined ? [] : resolved; // null = any address
      const destIps = ruleDestIps.has(rule.id) ? ruleDestIps.get(rule.id)! : [];
      const verdict = flowMatchesRule(flow, rule, sourceIps, ruleIfNames.get(rule.id) ?? null, destIps);
      if (verdict === 'no') continue;
      decided = true;
      if (verdict === 'uncertain') {
        result.uncertainFlows.push({
          flow,
          rule,
          reason: `Rule #${rule.order_index} is limited to interface(s) ${(ruleIfNames.get(rule.id) ?? []).join(', ')}, but the log did not record the packet's interface`,
        });
        result.summary.uncertain++;
      } else if (rule.action === 'DENY') {
        result.unexpectedBlocks.push({ flow, blockingRule: rule });
        result.summary.unexpectedBlocks++;
      } else {
        result.matchedFlows.push({ flow, matchedRule: rule, expectedAction: rule.action });
        result.summary.matched++;
      }
      break;
    }
    if (decided) continue;

    if (flow.direction === 'FORWARD') {
      // Unmatched forwarded traffic is only dropped when it goes to a device this gateway protects;
      // anything else is not filtered by Segmentra (the host's own FORWARD policy decides).
      if (protectedDestinations.some((d) => ipMatchesCidr(flow.destinationIp, d))) {
        result.unexpectedAllows.push({ flow, reason: 'No FORWARD rule allows this traffic to a protected device — it would be blocked' });
        result.summary.unexpectedAllows++;
      } else {
        result.matchedFlows.push({
          flow,
          matchedRule: { comment: hasForwardRules || protectedDestinations.length ? 'default: forwarded traffic to unprotected destinations is not filtered' : 'forwarded traffic is not filtered by this policy' },
          expectedAction: 'ALLOW',
        });
        result.summary.matched++;
      }
    } else if (flow.direction === 'OUT') {
      // Outbound default is allow
      result.matchedFlows.push({ flow, matchedRule: { comment: 'default: outbound traffic is allowed' }, expectedAction: 'ALLOW' });
      result.summary.matched++;
    } else {
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
