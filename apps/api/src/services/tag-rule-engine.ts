import type { PoolClient } from 'pg';

import { pool } from '../db/pool.js';
import { cidrContains, isValidCidr } from './ip-utils.js';

// Helper: check if IP matches a CIDR range (IPv4 and IPv6)
function ipMatchesCidr(ip: string, cidr: string): boolean {
  return cidrContains(cidr, String(ip).split('/')[0]);
}

/** Max length of a user-supplied regex and of the string it is tested against. */
export const MAX_REGEX_LENGTH = 200;
export const MAX_REGEX_INPUT_LENGTH = 256;

/**
 * Heuristic ReDoS guard for user-supplied regexes. Rejects:
 *  - backreferences (\1, \k<name>)
 *  - nested quantifiers: a quantified group that itself contains a quantifier, e.g. (a+)+, (.*)*, (\w+\d*){2,}
 *  - quantified groups with alternation, e.g. (a|aa)+ (overlapping alternatives backtrack exponentially)
 * Returns a reason string when the pattern is rejected, otherwise null.
 */
export function regexDangerReason(pattern: string): string | null {
  if (pattern.length > MAX_REGEX_LENGTH) return `regex longer than ${MAX_REGEX_LENGTH} characters`;
  if (/\\[1-9]|\\k<[^>]+>/.test(pattern)) return 'backreferences are not allowed';

  // Strip escaped characters and character classes so only structural tokens remain.
  const stripped = pattern.replace(/\\./g, 'x').replace(/\[(?:\\.|[^\]])*\]/g, 'x');
  const quantAfter = /^(?:[+*]|\{\d+(?:,\d*)?\})/;
  const stack: Array<{ hasQuant: boolean; hasAlt: boolean }> = [];
  for (let i = 0; i < stripped.length; i++) {
    const c = stripped[i];
    if (c === '(') {
      stack.push({ hasQuant: false, hasAlt: false });
    } else if (c === ')') {
      const group = stack.pop();
      if (!group) continue;
      const rest = stripped.slice(i + 1);
      const quantified = quantAfter.test(rest);
      if (quantified && group.hasQuant) return 'nested quantifiers (e.g. (a+)+) are not allowed';
      if (quantified && group.hasAlt) return 'quantified alternation (e.g. (a|aa)+) is not allowed';
      // Propagate to the parent: a quantified group (or one containing quantifiers) counts as a quantifier.
      if (stack.length > 0 && (group.hasQuant || quantified)) stack[stack.length - 1].hasQuant = true;
    } else if (c === '|') {
      if (stack.length > 0) stack[stack.length - 1].hasAlt = true;
    } else if (c === '+' || c === '*' || c === '{') {
      if (c === '{' && !/^\{\d+(?:,\d*)?\}/.test(stripped.slice(i))) continue;
      if (stack.length > 0) stack[stack.length - 1].hasQuant = true;
    }
  }
  try {
    new RegExp(pattern, 'i');
  } catch (e: any) {
    return `invalid regex: ${e?.message ?? 'syntax error'}`;
  }
  return null;
}

/** Validate tag-rule criteria before storing it. Returns a list of problems (empty = valid). */
export function validateCriteria(criteria: TagRuleCriteria): string[] {
  const problems: string[] = [];
  (criteria?.conditions ?? []).forEach((c, idx) => {
    if (c.operator === 'matches') {
      const reason = regexDangerReason(String(c.value ?? ''));
      if (reason) problems.push(`condition ${idx + 1}: ${reason}`);
    }
    if (c.operator === 'in_cidr' && !isValidCidr(String(c.value ?? ''))) {
      problems.push(`condition ${idx + 1}: "${c.value}" is not a valid CIDR`);
    }
  });
  return problems;
}

export interface TagRuleCondition {
  field: string;      // hostname, mgmt_ip, vlan_id, vlan_tag, os_family, environment, firewall_backend, tag
  operator: string;   // equals, not_equals, matches, contains, in_cidr, has_tag
  value: string;
}

export interface TagRuleCriteria {
  conditions: TagRuleCondition[];
  logic: 'AND' | 'OR';
}

export interface HostData {
  id: string;
  hostname: string;
  mgmt_ip: string;
  vlan_id: string | null;
  vlan_tag: number | null;
  os_family: string | null;
  environment: string | null;
  firewall_backend: string | null;
  tag_ids: string[];
  tag_names: string[];
}

async function getHostData(hostId?: string, db: Pick<PoolClient, 'query'> = pool): Promise<HostData[]> {
  const { rows } = await db.query(
    `SELECT h.id, h.hostname, host(h.mgmt_ip) AS mgmt_ip, h.vlan_id, v.vlan_tag, h.os_family, h.environment,
            h.firewall_backend,
            COALESCE(array_agg(t.id) FILTER (WHERE t.id IS NOT NULL), '{}') AS tag_ids,
            COALESCE(array_agg(t.name) FILTER (WHERE t.id IS NOT NULL), '{}') AS tag_names
       FROM hosts h
       LEFT JOIN vlans v ON h.vlan_id = v.id
       LEFT JOIN host_tags ht ON ht.host_id = h.id
       LEFT JOIN tags t ON t.id = ht.tag_id
      WHERE ${hostId ? 'h.id = $1' : 'h.enabled = true'}
      GROUP BY h.id, v.vlan_tag
      ORDER BY h.hostname ASC`,
    hostId ? [hostId] : []
  );
  return rows.map((host: any) => ({
    id: host.id,
    hostname: host.hostname,
    mgmt_ip: host.mgmt_ip,
    vlan_id: host.vlan_id,
    vlan_tag: host.vlan_tag,
    os_family: host.os_family,
    environment: host.environment,
    firewall_backend: host.firewall_backend,
    tag_ids: host.tag_ids ?? [],
    tag_names: host.tag_names ?? [],
  }));
}

function evaluateCondition(condition: TagRuleCondition, host: HostData): boolean {
  const { field, operator, value } = condition;

  let fieldValue: string | null = null;
  switch (field) {
    case 'hostname': fieldValue = host.hostname; break;
    case 'mgmt_ip': fieldValue = host.mgmt_ip; break;
    case 'vlan_id': fieldValue = host.vlan_id; break;
    case 'vlan_tag': fieldValue = host.vlan_tag?.toString() ?? null; break;
    case 'os_family': fieldValue = host.os_family; break;
    case 'environment': fieldValue = host.environment; break;
    case 'firewall_backend': fieldValue = host.firewall_backend; break;
    case 'tag':
      // Special: check tag names
      if (operator === 'has_tag') {
        return host.tag_names.some(t => t.toLowerCase() === value.toLowerCase());
      }
      fieldValue = host.tag_names.join(',');
      break;
    default:
      return false;
  }

  if (fieldValue === null || fieldValue === undefined) {
    return operator === 'not_equals';
  }

  switch (operator) {
    case 'equals':
      return fieldValue.toLowerCase() === value.toLowerCase();
    case 'not_equals':
      return fieldValue.toLowerCase() !== value.toLowerCase();
    case 'matches':
      try {
        // Rules are validated on create/update; re-check here for rows stored before that.
        if (regexDangerReason(value)) return false;
        const regex = new RegExp(value, 'i');
        const testValue = fieldValue.slice(0, MAX_REGEX_INPUT_LENGTH);
        return regex.test(testValue);
      } catch {
        return false;
      }
    case 'contains':
      return fieldValue.toLowerCase().includes(value.toLowerCase());
    case 'in_cidr':
      return ipMatchesCidr(fieldValue, value);
    case 'has_tag':
      return host.tag_names.some(t => t.toLowerCase() === value.toLowerCase());
    default:
      return false;
  }
}

/** Pure matcher: does a host satisfy the criteria? */
export function evaluateCriteria(criteria: TagRuleCriteria, host: HostData): boolean {
  if (!criteria.conditions || criteria.conditions.length === 0) return false;

  if (criteria.logic === 'OR') {
    return criteria.conditions.some(c => evaluateCondition(c, host));
  }
  // Default AND
  return criteria.conditions.every(c => evaluateCondition(c, host));
}

/**
 * Hosts that would match the criteria right now. Performs no writes (used by
 * POST /api/tag-rules/preview).
 */
export async function previewCriteria(criteria: TagRuleCriteria): Promise<Array<{ id: string; hostname: string }>> {
  const hosts = await getHostData();
  return hosts.filter((h) => evaluateCriteria(criteria, h)).map((h) => ({ id: h.id, hostname: h.hostname }));
}

/** Remove every host_tags row a rule assigned (used when a rule is disabled, retargeted or deleted). */
export async function removeRuleAssignedTags(ruleId: string, db: Pick<PoolClient, 'query'> = pool): Promise<number> {
  const { rowCount } = await db.query(`DELETE FROM host_tags WHERE source = 'rule' AND source_rule_id = $1`, [ruleId]);
  await db.query(`UPDATE tag_rule_results SET matched = false, evaluated_at = now() WHERE tag_rule_id = $1`, [ruleId]);
  return rowCount ?? 0;
}

type ReconcileResult = {
  perRule: Map<string, number>;
  hostsEvaluated: number;
  rulesEvaluated: number;
  assigned: Array<{ hostId: string; tagId: string; ruleId: string }>;
};

/**
 * Bring rule-assigned host tags in line with the ENABLED rules (disabled rules assign nothing).
 * For each (host, tag) the highest-priority matching rule owns the assignment. Manual tags are
 * never touched; a manual tag also satisfies a rule (no duplicate row is created).
 */
async function reconcileRuleTags(opts: { hostId?: string } = {}): Promise<ReconcileResult> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // Serialize concurrent reconciliations (interval job vs. API calls).
    await client.query(`SELECT pg_advisory_xact_lock(hashtext('segmentra_tag_rule_reconcile'))`);

    const { rows: rules } = await client.query(
      `SELECT id, tag_id, criteria, enabled FROM tag_rules ORDER BY priority DESC, created_at ASC, id ASC`
    );
    const enabledRules = rules.filter((r: any) => r.enabled);
    const disabledIds = rules.filter((r: any) => !r.enabled).map((r: any) => r.id);
    const hosts = await getHostData(opts.hostId, client);
    const hostIds = hosts.map((h) => h.id);

    const perRule = new Map<string, number>();
    const desired = new Map<string, string>(); // `${hostId}|${tagId}` -> ruleId

    for (const rule of enabledRules) {
      const criteria = (typeof rule.criteria === 'string' ? JSON.parse(rule.criteria) : rule.criteria) as TagRuleCriteria;
      const matchedIds: string[] = [];
      const unmatchedIds: string[] = [];
      for (const host of hosts) {
        if (evaluateCriteria(criteria, host)) {
          matchedIds.push(host.id);
          const key = `${host.id}|${rule.tag_id}`;
          if (!desired.has(key)) desired.set(key, rule.id);
        } else {
          unmatchedIds.push(host.id);
        }
      }
      perRule.set(rule.id, matchedIds.length);
      if (hosts.length > 0) {
        await client.query(
          `INSERT INTO tag_rule_results (tag_rule_id, host_id, matched, evaluated_at)
           SELECT $1, x.host_id, x.matched, now()
             FROM unnest($2::uuid[], $3::boolean[]) AS x(host_id, matched)
           ON CONFLICT (tag_rule_id, host_id) DO UPDATE SET matched = EXCLUDED.matched, evaluated_at = now()`,
          [rule.id, [...matchedIds, ...unmatchedIds], [...matchedIds.map(() => true), ...unmatchedIds.map(() => false)]]
        );
      }
    }

    // Disabled rules match nothing.
    if (disabledIds.length > 0 && hostIds.length > 0) {
      await client.query(
        `UPDATE tag_rule_results SET matched = false, evaluated_at = now()
          WHERE tag_rule_id = ANY($1::uuid[]) AND host_id = ANY($2::uuid[])`,
        [disabledIds, hostIds]
      );
    }

    // Existing rule-assigned tags for the evaluated hosts.
    const { rows: existing } = hostIds.length
      ? await client.query(
          `SELECT host_id, tag_id, source_rule_id FROM host_tags WHERE source = 'rule' AND host_id = ANY($1::uuid[])`,
          [hostIds]
        )
      : { rows: [] as any[] };

    const existingKeys = new Set<string>();
    for (const row of existing) {
      const key = `${row.host_id}|${row.tag_id}`;
      existingKeys.add(key);
      const owner = desired.get(key);
      if (!owner) {
        await client.query(
          `DELETE FROM host_tags WHERE host_id = $1 AND tag_id = $2 AND source = 'rule'`,
          [row.host_id, row.tag_id]
        );
      } else if (owner !== row.source_rule_id) {
        await client.query(
          `UPDATE host_tags SET source_rule_id = $3 WHERE host_id = $1 AND tag_id = $2 AND source = 'rule'`,
          [row.host_id, row.tag_id, owner]
        );
      }
    }

    const assigned: ReconcileResult['assigned'] = [];
    for (const [key, ruleId] of desired) {
      if (existingKeys.has(key)) continue;
      const [hostId, tagId] = key.split('|');
      const { rowCount } = await client.query(
        `INSERT INTO host_tags (host_id, tag_id, source, source_rule_id)
         VALUES ($1, $2, 'rule', $3)
         ON CONFLICT (host_id, tag_id) DO NOTHING`,
        [hostId, tagId, ruleId]
      );
      if (rowCount) assigned.push({ hostId, tagId, ruleId });
    }

    await client.query('COMMIT');
    return { perRule, hostsEvaluated: hosts.length, rulesEvaluated: enabledRules.length, assigned };
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }
}

export async function evaluateRule(ruleId: string): Promise<{ matched: number; total: number; enabled: boolean }> {
  const { rows: rules } = await pool.query(`SELECT id, enabled FROM tag_rules WHERE id = $1`, [ruleId]);
  if (!rules[0]) throw new Error('Tag rule not found');
  const result = await reconcileRuleTags();
  return { matched: result.perRule.get(ruleId) ?? 0, total: result.hostsEvaluated, enabled: !!rules[0].enabled };
}

export async function evaluateAllRules(): Promise<{ rulesEvaluated: number; totalMatches: number }> {
  const result = await reconcileRuleTags();
  let totalMatches = 0;
  for (const n of result.perRule.values()) totalMatches += n;
  return { rulesEvaluated: result.rulesEvaluated, totalMatches };
}

export async function evaluateHostAgainstRules(hostId: string): Promise<{ rulesMatched: number; tagsAssigned: string[] }> {
  const { rows } = await pool.query(`SELECT id FROM hosts WHERE id = $1`, [hostId]);
  if (!rows[0]) throw new Error('Host not found');
  const result = await reconcileRuleTags({ hostId });
  let rulesMatched = 0;
  for (const n of result.perRule.values()) if (n > 0) rulesMatched++;
  return { rulesMatched, tagsAssigned: result.assigned.map((a) => a.tagId) };
}
