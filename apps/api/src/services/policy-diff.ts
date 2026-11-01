import { compileHostPolicy } from '@segmentra/compiler';
import { pool } from '../db/pool.js';

export interface PolicyDiffRule {
  type: 'added' | 'removed' | 'modified' | 'reordered';
  orderIndex: number;
  /** For 'reordered' rules: the order_index in the current version */
  previousOrderIndex?: number;
  /** Per-rule interface scope (only set when the rule overrides the policy scope) */
  interfaceScope?: string;
  direction: string;
  action: string;
  protocol: string;
  ports?: string;
  sourceType: string;
  sourceValue: string;
  /** FORWARD rules only */
  destinationType?: string;
  destinationValue?: string;
  comment?: string;
  logMode?: string;
}

export interface PolicyDiffResult {
  hostId: string;
  hostname: string;
  changes: {
    newAllows: PolicyDiffRule[];
    removedAllows: PolicyDiffRule[];
    newDenies: PolicyDiffRule[];
    removedDenies: PolicyDiffRule[];
    /** Rules present in both versions whose relative evaluation order changed (first match wins) */
    reordered: PolicyDiffRule[];
    /** Set when the policy-level interface scope differs between the versions */
    interfaceScopeChange: { from: string; to: string } | null;
  };
  summary: {
    totalNewAllows: number;
    totalRemovedAllows: number;
    totalNewDenies: number;
    totalRemovedDenies: number;
    totalReordered: number;
    interfaceScopeChanged: boolean;
  };
}

/**
 * Policy-level interface scope as the compiler sees it (routes/deployments.ts): ALL_INTERFACES and
 * INTERFACE_NAME as stored, anything else — including NULL — is INTERFACE_ROLE with the stored roles
 * (none → a scope that matches no interface).
 */
export function describeScope(type: string | null | undefined, roles: unknown, names: unknown): string {
  if (type === 'ALL_INTERFACES') return 'ALL_INTERFACES';
  if (type === 'INTERFACE_NAME') return `INTERFACE_NAME:${[...((names as string[]) ?? [])].sort().join(',')}`;
  return `INTERFACE_ROLE:${[...((roles as string[]) ?? [])].sort().join(',')}`;
}

/**
 * Per-rule interface scope as the compiler resolves it: null = the rule follows the policy scope
 * (use_policy_interface_scope, or no valid rule-level scope stored, which falls back to the policy scope).
 */
export function describeRuleScope(r: {
  use_policy_interface_scope?: boolean | null;
  interface_scope_type?: string | null;
  interface_scope_roles?: unknown;
  interface_scope_names?: unknown;
}): string | null {
  if (r.use_policy_interface_scope) return null;
  const t = r.interface_scope_type;
  if (t !== 'ALL_INTERFACES' && t !== 'INTERFACE_NAME' && t !== 'INTERFACE_ROLE') return null;
  return describeScope(t, r.interface_scope_roles, r.interface_scope_names);
}

/** Longest common subsequence over keys; returns the set of kept keys. */
function lcsKeys(a: string[], b: string[]): Set<string> {
  const n = a.length;
  const m = b.length;
  const dp: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
  const kept = new Set<string>();
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      kept.add(a[i]);
      i++;
      j++;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) i++;
    else j++;
  }
  return kept;
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
      `SELECT order_index, direction, action, protocol, ports, source_type, source_value, comment, log_mode,
              use_policy_interface_scope, interface_scope_type, interface_scope_roles, interface_scope_names,
              destination_type, destination_value
       FROM policy_rules
       WHERE policy_version_id=$1
       ORDER BY order_index ASC`,
      [params.currentVersionId]
    ),
    pool.query(
      `SELECT order_index, direction, action, protocol, ports, source_type, source_value, comment, log_mode,
              use_policy_interface_scope, interface_scope_type, interface_scope_roles, interface_scope_names,
              destination_type, destination_value
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
    destinationType: (r.destination_type as string | null) || null,
    destinationValue: (r.destination_value as string | null) || null,
    comment: r.comment || null,
    logMode: (r.log_mode as string | null) || 'NONE',
    orderIndex: Number(r.order_index),
    // Per-rule interface scope only matters when the rule overrides the policy scope.
    interfaceScope: describeRuleScope(r)
  });

  const currentRules = currentRulesRes.rows.map(normalizeRule);
  const candidateRules = candidateRulesRes.rows.map(normalizeRule);

  // Content signature (order is compared separately so one insertion doesn't flag every rule)
  // Every column the compiler turns into firewall config is part of it: a log_mode or comment change
  // (log statement / rule comment) is a real ruleset change, so it shows up as removed + added.
  const ruleSignature = (r: ReturnType<typeof normalizeRule>) =>
    JSON.stringify([
      r.direction, r.action, r.protocol, (r.ports || '*').replace(/\s+/g, ''), r.sourceType, r.sourceValue,
      r.interfaceScope ?? 'policy', r.destinationType ?? null, r.destinationType ? r.destinationValue : null,
      r.logMode, r.comment ?? '',
    ]);

  // Reorder detection: give duplicate signatures an occurrence suffix, then find rules common to
  // both versions whose relative order changed (outside the longest common subsequence).
  const withOccurrence = (rules: ReturnType<typeof normalizeRule>[]) => {
    const seen = new Map<string, number>();
    return rules.map((r) => {
      const sig = ruleSignature(r);
      const n = (seen.get(sig) ?? 0) + 1;
      seen.set(sig, n);
      return `${sig}#${n}`;
    });
  };
  const currentKeys = withOccurrence(currentRules);
  const candidateKeys = withOccurrence(candidateRules);
  const currentKeySet = new Set(currentKeys);
  const candidateKeySet = new Set(candidateKeys);
  const commonCurrent = currentKeys.filter((k) => candidateKeySet.has(k));
  const commonCandidate = candidateKeys.filter((k) => currentKeySet.has(k));
  const stable = lcsKeys(commonCurrent, commonCandidate);
  const reorderedRules: Array<ReturnType<typeof normalizeRule> & { previousOrderIndex: number }> = [];
  candidateKeys.forEach((k, idx) => {
    if (!currentKeySet.has(k) || stable.has(k)) return;
    const prev = currentRules[currentKeys.indexOf(k)];
    reorderedRules.push({ ...candidateRules[idx], previousOrderIndex: prev.orderIndex });
  });

  const currentScope = describeScope(currentPolicy.interface_scope_type, currentPolicy.interface_scope_roles, currentPolicy.interface_scope_names);
  const candidateScope = describeScope(candidatePolicy.interface_scope_type, candidatePolicy.interface_scope_roles, candidatePolicy.interface_scope_names);
  const interfaceScopeChange = currentScope !== candidateScope ? { from: currentScope, to: candidateScope } : null;


  // Find added and removed rules, preserving order_index
  const addedRules: Array<typeof candidateRules[0] & { orderIndex: number }> = [];
  const removedRules: Array<typeof currentRules[0] & { orderIndex: number }> = [];

  for (let i = 0; i < candidateRulesRes.rows.length; i++) {
    const rule = candidateRules[i];
    if (!currentKeySet.has(candidateKeys[i])) {
      addedRules.push({ ...rule, orderIndex: candidateRulesRes.rows[i].order_index });
    }
  }

  for (let i = 0; i < currentRulesRes.rows.length; i++) {
    const rule = currentRules[i];
    if (!candidateKeySet.has(currentKeys[i])) {
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
        destinationType: rule.destinationType || undefined,
        destinationValue: rule.destinationValue || undefined,
        comment: rule.comment || undefined,
        logMode: rule.logMode,
        interfaceScope: rule.interfaceScope ?? undefined
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
        destinationType: rule.destinationType || undefined,
        destinationValue: rule.destinationValue || undefined,
        comment: rule.comment || undefined,
        logMode: rule.logMode,
        interfaceScope: rule.interfaceScope ?? undefined
      };

      if (rule.action === 'ALLOW') {
        removedAllows.push(diffRule);
      } else {
        removedDenies.push(diffRule);
      }
    }

    const reordered: PolicyDiffRule[] = reorderedRules.map((rule) => ({
      type: 'reordered',
      orderIndex: rule.orderIndex,
      previousOrderIndex: rule.previousOrderIndex,
      direction: rule.direction,
      action: rule.action,
      protocol: rule.protocol,
      ports: rule.ports || undefined,
      sourceType: rule.sourceType,
      sourceValue: rule.sourceValue,
      destinationType: rule.destinationType || undefined,
      destinationValue: rule.destinationValue || undefined,
      comment: rule.comment || undefined,
      logMode: rule.logMode,
      interfaceScope: rule.interfaceScope ?? undefined
    }));

    results.push({
      hostId: host.id,
      hostname: host.hostname,
      changes: {
        newAllows,
        removedAllows,
        newDenies,
        removedDenies,
        reordered,
        interfaceScopeChange
      },
      summary: {
        totalNewAllows: newAllows.length,
        totalRemovedAllows: removedAllows.length,
        totalNewDenies: newDenies.length,
        totalRemovedDenies: removedDenies.length,
        totalReordered: reordered.length,
        interfaceScopeChanged: interfaceScopeChange !== null
      }
    });
  }

  return results;
}
