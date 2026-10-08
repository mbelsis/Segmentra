import { compileHostPolicy, type PolicyRule } from '@segmentra/compiler';
import { pool } from '../db/pool.js';
import {
  cidrContains,
  cidrsOverlap,
  hostIpOnly,
  isValidCidr,
  isValidIp,
  portSpecCoversRange,
  portSpecIncludes,
  portSpecIntersectsRange,
} from './ip-utils.js';
import { createSourceResolver } from './source-resolver.js';
import { addDestinationSets, compilerDestination, getProtectedDestinations } from './forward-rules.js';

export interface SafetyCheckResult {
  safe: boolean;
  warnings: string[];
  errors: string[];
  sshAccessPreserved: boolean;
  blockingRules: Array<{
    ruleIndex: number;
    action: string;
    source: string;
    protocol: string;
    ports?: string;
    comment?: string;
  }>;
}

/**
 * Check whether deploying a policy version would preserve SSH access from the management
 * network, by evaluating the ordered rules against what the compiler emits (inbound baseline
 * before policy rules; no established exception on the output chain).
 * Returns safety check result with warnings/errors.
 */
export async function checkDeploymentSafety(params: {
  policyVersionId: string;
  hostIds: string[];
  userIp?: string; // Optional: check if current user's IP would be blocked
}): Promise<SafetyCheckResult> {
  const result: SafetyCheckResult = {
    safe: true,
    warnings: [],
    errors: [],
    sshAccessPreserved: false,
    blockingRules: []
  };

  // Get management VLAN CIDRs (same source the deployment compiler uses for its baseline)
  const mgmtVlanRes = await pool.query(
    `SELECT value FROM system_settings WHERE key='management_vlan_id'`
  );
  const mgmtVlanId = mgmtVlanRes.rows[0]?.value || null;

  let mgmtSshCidrs: string[] = [];
  if (mgmtVlanId) {
    const vlanRes = await pool.query(`SELECT subnet FROM vlans WHERE id=$1`, [mgmtVlanId]);
    if (vlanRes.rows[0]?.subnet && isValidCidr(String(vlanRes.rows[0].subnet))) {
      mgmtSshCidrs = [String(vlanRes.rows[0].subnet)];
    }
  }

  if (mgmtSshCidrs.length === 0) {
    result.warnings.push(
      'No management VLAN subnet configured: the compiler falls back to allowing the SSH port from any source. ' +
        'Configure a management VLAN to restrict SSH and enable precise lockout analysis.'
    );
  }

  // Get policy version
  const policyRes = await pool.query(
    `SELECT interface_scope_type, interface_scope_roles, interface_scope_names
     FROM policy_versions WHERE id=$1`,
    [params.policyVersionId]
  );
  if (!policyRes.rows[0]) {
    result.errors.push('Policy version not found');
    result.safe = false;
    return result;
  }

  const policy = policyRes.rows[0];
  const policyInterfaceScope =
    policy.interface_scope_type === 'ALL_INTERFACES'
      ? { type: 'ALL_INTERFACES' as const }
      : policy.interface_scope_type === 'INTERFACE_NAME'
        ? { type: 'INTERFACE_NAME' as const, names: (policy.interface_scope_names ?? []) as string[] }
        : { type: 'INTERFACE_ROLE' as const, roles: (policy.interface_scope_roles ?? []) as string[] };

  // Get rules, in evaluation order
  const rulesRes = await pool.query(
    `SELECT order_index, direction, action, protocol, ports, source_type, source_value, comment,
            destination_type, destination_value
     FROM policy_rules
     WHERE policy_version_id=$1
     ORDER BY order_index ASC`,
    [params.policyVersionId]
  );

  // Resolve every rule's remote side to concrete addresses (same semantics as deployment).
  const resolve = createSourceResolver();
  const evalRules: EvalRule[] = [];
  // FORWARD rules filter traffic routed THROUGH the host; they never affect SSH to the host
  // itself, so they are only compiled (validated), not part of the lockout analysis.
  const forwardRows: any[] = [];
  const sets: Record<string, string[]> = {};
  for (const r of rulesRes.rows as any[]) {
    const addrs = await resolve(r.source_type, r.source_value);
    const setName = setNameFor(r.source_type, r.source_value);
    if (r.source_type !== 'CIDR') sets[setName] = addrs;
    if (r.direction === 'FORWARD') {
      forwardRows.push(r);
      continue;
    }
    evalRules.push({
      orderIndex: Number(r.order_index),
      direction: (r.direction ?? 'IN') as 'IN' | 'OUT' | 'BOTH',
      action: r.action,
      protocol: r.protocol,
      ports: r.ports,
      sourceType: r.source_type,
      sourceValue: r.source_value,
      comment: r.comment,
      addrs,
    });
  }
  await addDestinationSets(forwardRows, sets);

  const userIp = params.userIp ? hostIpOnly(params.userIp.replace(/^::ffff:(?=\d+\.)/i, '')) : null;
  let allHostsPreserved = params.hostIds.length > 0;

  // Check each host
  for (const hostId of params.hostIds) {
    const hostRes = await pool.query(
      `SELECT h.id, h.hostname, h.mgmt_ip, h.ssh_port, h.firewall_backend,
              COALESCE(json_agg(json_build_object('name', hi.name, 'role', hi.role, 'enabled', hi.enabled)) FILTER (WHERE hi.id IS NOT NULL), '[]') as interfaces
       FROM hosts h
       LEFT JOIN host_interfaces hi ON hi.host_id = h.id
       WHERE h.id=$1
       GROUP BY h.id`,
      [hostId]
    );

    if (!hostRes.rows[0]) continue;
    const host = hostRes.rows[0];
    const sshPort = Number(host.ssh_port) || 22;

    // 1) The policy must compile for this host at all (incl. FORWARD rules and protected devices).
    try {
      const protectedDestinations = await getProtectedDestinations(host.id);
      compileHostPolicy({
        host: {
          id: host.id,
          hostname: host.hostname,
          mgmtIp: host.mgmt_ip ? String(host.mgmt_ip) : null,
          firewallBackend: host.firewall_backend === 'iptables' ? 'iptables' : 'nftables',
          interfaces: typeof host.interfaces === 'string' ? JSON.parse(host.interfaces) : (host.interfaces || []),
          sshPort,
        },
        policyInterfaceScope,
        rules: (evalRules.map((r) => ({
          orderIndex: r.orderIndex,
          direction: r.direction,
          action: r.action,
          protocol: r.protocol,
          ports: r.ports,
          sourceType: r.sourceType,
          sourceValue: r.sourceValue,
          logMode: 'NONE' as const,
          comment: r.comment,
          usePolicyInterfaceScope: true,
          remote: r.sourceType === 'CIDR' ? { kind: 'CIDR' as const } : { kind: 'SET' as const, setName: setNameFor(r.sourceType, r.sourceValue) },
        })) as PolicyRule[]).concat(forwardRows.map((r: any) => ({
          orderIndex: Number(r.order_index),
          direction: 'FORWARD' as const,
          action: r.action,
          protocol: r.protocol,
          ports: r.ports,
          sourceType: r.source_type,
          sourceValue: r.source_value,
          logMode: 'NONE' as const,
          comment: r.comment,
          usePolicyInterfaceScope: true,
          remote: r.source_type === 'CIDR' ? { kind: 'CIDR' as const } : { kind: 'SET' as const, setName: setNameFor(r.source_type, r.source_value) },
          ...compilerDestination(r),
        }))),
        sets,
        baseline: { mgmtSshCidrs },
        protectedDestinations,
      });
    } catch (e: any) {
      result.errors.push(`Host ${host.hostname}: policy does not compile: ${e?.message ?? String(e)}`);
      result.safe = false;
      allHostsPreserved = false;
      continue;
    }

    // 2) Inbound SSH. The compiler emits the management baseline (accept tcp/<sshPort> from the
    //    management CIDRs, or from anywhere when none are configured) BEFORE policy rules, so
    //    inbound DENY rules cannot cut management SSH. Report DENYs that target it anyway, since
    //    they will block SSH from every non-management source.
    for (const r of evalRules) {
      if (r.action !== 'DENY' || r.direction === 'OUT') continue;
      if (!protoCoversTcp(r.protocol) || !portSpecIncludes(r.ports, sshPort)) continue;
      const hitsMgmt = mgmtSshCidrs.length === 0 || mgmtSshCidrs.some((m) => r.addrs.some((a) => cidrsOverlap(a, m)));
      if (hitsMgmt) {
        result.warnings.push(
          `Host ${host.hostname}: rule #${r.orderIndex} denies inbound SSH (tcp/${sshPort}) from ${describe(r)}; ` +
            'management SSH stays open via the baseline rule, other sources will be blocked'
        );
      }
    }

    // 3) Outbound replies. The output chain has NO established/related exception, so an OUT
    //    (or BOTH) DENY toward the management subnet drops the SSH server's reply packets
    //    (tcp sport <sshPort> → client ephemeral port) and locks operators out.
    const replyTargets = mgmtSshCidrs.length > 0 ? mgmtSshCidrs : ['0.0.0.0/0', '::/0'];
    let hostPreserved = true;
    for (const target of replyTargets) {
      const verdict = evaluateOutboundReplies(evalRules, target);
      if (verdict.kind === 'blocked') {
        hostPreserved = false;
        result.safe = false;
        result.errors.push(
          `Host ${host.hostname}: rule #${verdict.rule.orderIndex} (OUT ${verdict.rule.action} ${describe(verdict.rule)}) ` +
            `drops SSH reply traffic to the management network ${target} — deploying would lock out SSH`
        );
        result.blockingRules.push(toBlocking(verdict.rule));
      } else if (verdict.partial.length > 0) {
        for (const pr of verdict.partial) {
          result.warnings.push(
            `Host ${host.hostname}: rule #${pr.orderIndex} (OUT DENY ${describe(pr)}) may drop some SSH reply traffic to ${target}`
          );
          result.blockingRules.push(toBlocking(pr));
        }
      }
    }
    if (!hostPreserved) allHostsPreserved = false;

    // 4) The caller's own IP (proper CIDR containment, first match wins).
    if (userIp && isValidIp(userIp)) {
      const inbound = firstMatch(evalRules, (r) => r.direction !== 'OUT' && r.addrs.some((a) => cidrContains(a, userIp)));
      const userInMgmt = mgmtSshCidrs.some((m) => cidrContains(m, userIp)) || mgmtSshCidrs.length === 0;
      if (inbound && inbound.action === 'DENY') {
        result.warnings.push(
          `Host ${host.hostname}: your IP (${userIp}) is denied inbound by rule #${inbound.orderIndex}` +
            (userInMgmt ? ' (management SSH remains allowed by the baseline)' : '')
        );
      } else if (!inbound && !userInMgmt) {
        result.warnings.push(
          `Host ${host.hostname}: your IP (${userIp}) is not in the management network and no rule allows it; ` +
            'inbound traffic from it (including SSH) will be dropped by the default policy'
        );
      }
      const outbound = evaluateOutboundReplies(evalRules, userIp.includes(':') ? `${userIp}/128` : `${userIp}/32`);
      if (outbound.kind === 'blocked') {
        result.warnings.push(
          `Host ${host.hostname}: rule #${outbound.rule.orderIndex} drops outbound traffic to your IP (${userIp}); replies to you will be lost`
        );
      }
    }
  }

  result.sshAccessPreserved = allHostsPreserved && result.errors.length === 0;
  return result;
}

type EvalRule = {
  orderIndex: number;
  direction: 'IN' | 'OUT' | 'BOTH';
  action: 'ALLOW' | 'DENY';
  protocol: 'tcp' | 'udp' | 'icmp' | 'any';
  ports: string | null;
  sourceType: 'CIDR' | 'TAG' | 'VLAN' | 'HOST';
  sourceValue: string;
  comment: string | null;
  addrs: string[];
};

const EPHEMERAL_FROM = 1024;
const EPHEMERAL_TO = 65535;

function setNameFor(sourceType: string, sourceValue: string): string {
  return `src_${String(sourceType).toLowerCase()}_${String(sourceValue).replace(/-/g, '')}`;
}

function protoCoversTcp(protocol: string): boolean {
  return protocol === 'tcp' || protocol === 'any';
}

function describe(r: EvalRule): string {
  const ports = r.ports ? `/${r.ports}` : '';
  return `${r.sourceType}:${r.sourceValue} ${r.protocol}${ports}`;
}

function toBlocking(r: EvalRule) {
  return {
    ruleIndex: r.orderIndex,
    action: r.action,
    source: `${r.sourceType}:${r.sourceValue}`,
    protocol: r.protocol,
    ports: r.ports ?? undefined,
    comment: r.comment ?? undefined,
  };
}

function firstMatch(rules: EvalRule[], pred: (r: EvalRule) => boolean): EvalRule | undefined {
  return rules.find(pred);
}

/**
 * Walk OUT/BOTH rules in order for TCP packets toward `target` with an ephemeral destination
 * port (SSH replies). Output default policy is accept.
 *  - A DENY that fully covers the target and the ephemeral range before any covering ALLOW → blocked.
 *  - DENYs that only partially overlap are reported as partial.
 */
function evaluateOutboundReplies(
  rules: EvalRule[],
  target: string
): { kind: 'blocked'; rule: EvalRule } | { kind: 'ok'; partial: EvalRule[] } {
  const partial: EvalRule[] = [];
  for (const r of rules) {
    if (r.direction === 'IN') continue;
    if (!protoCoversTcp(r.protocol)) continue;
    if (!portSpecIntersectsRange(r.ports, EPHEMERAL_FROM, EPHEMERAL_TO)) continue;
    const overlaps = r.addrs.some((a) => cidrsOverlap(a, target));
    if (!overlaps) continue;
    const coversAddr = r.addrs.some((a) => cidrContains(a, target));
    const coversPorts = portSpecCoversRange(r.ports, EPHEMERAL_FROM, EPHEMERAL_TO);
    const full = coversAddr && coversPorts;
    if (r.action === 'ALLOW') {
      if (full) break; // everything after this is shadowed for the reply traffic
      continue;
    }
    if (full) return { kind: 'blocked', rule: r };
    partial.push(r);
  }
  return { kind: 'ok', partial };
}
