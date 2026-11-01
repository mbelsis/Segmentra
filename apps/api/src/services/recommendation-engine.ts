import net from 'node:net';

import { pool } from '../db/pool.js';
import {
  directionSchema,
  protocolSchema,
  ruleCommentSchema,
  sourceTypeSchema,
  validateRuleSemantics,
} from '../lib/rule-validation.js';
import { cidrContains } from './ip-utils.js';
import { COMPILER_PROTOCOLS, type CommunicationFlow } from './log-parser.js';
import { createDraftVersion, insertRule, loadVersionRules, lockPolicySetAndGetBase } from './policy-version-clone.js';

// Well-known service ports for confidence scoring
const KNOWN_SERVICE_PORTS: Record<number, string> = {
  22: 'SSH', 53: 'DNS', 80: 'HTTP', 443: 'HTTPS',
  3306: 'MySQL', 5432: 'PostgreSQL', 6379: 'Redis',
  8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 25: 'SMTP',
  110: 'POP3', 143: 'IMAP', 993: 'IMAPS', 995: 'POP3S',
  3389: 'RDP', 5900: 'VNC', 27017: 'MongoDB',
};

interface RecommendedRule {
  direction: 'IN' | 'OUT';
  action: 'ALLOW';
  protocol: string;
  ports: string | null;
  sourceType: string;
  sourceValue: string;
  comment: string;
  confidence: number;
  flowCount: number;
  /** Informational only (never used as the rule source): inventory context of the observed address. */
  context?: string;
}

// Helper: check if IP matches a CIDR range (IPv4 and IPv6)
function ipMatchesCidr(ip: string, cidr: string): boolean {
  return cidrContains(cidr, ip.split('/')[0]);
}

type ResolvedSource = { type: 'HOST' | 'CIDR'; value: string; label: string; context?: string; inInventory: boolean };

/**
 * The narrowest source that matches exactly the observed address, as the compiler resolves it:
 *  - HOST only when the address IS that host's mgmt_ip (a HOST source compiles to the mgmt_ip, nothing else)
 *  - otherwise the address itself as a /32 (IPv4) or /128 (IPv6) CIDR.
 * Never widened to a TAG or VLAN automatically: those compile to the mgmt_ip of every member host,
 * which may be far broader than what was observed and may not even contain the observed address
 * (an interface address or a VLAN-subnet device without inventory entry). Inventory context
 * (interface owner, tags, VLAN) only goes into the comment/context.
 */
export async function resolveIpToEntity(rawIp: string): Promise<ResolvedSource | null> {
  const ip = String(rawIp ?? '').trim();
  if (!net.isIP(ip)) return null;
  const hostCidr = `${ip}/${ip.includes(':') ? 128 : 32}`;

  const { rows: hosts } = await pool.query(
    `SELECT h.id, h.hostname FROM hosts h WHERE h.mgmt_ip = $1::inet AND h.enabled = true ORDER BY h.hostname, h.id LIMIT 1`,
    [ip]
  );
  if (hosts[0]) {
    const tags = await hostTagNames(hosts[0].id);
    return {
      type: 'HOST',
      value: hosts[0].id,
      label: `HOST:${hosts[0].hostname}`,
      context: tags.length ? `host ${hosts[0].hostname}, tags ${tags.join(', ')}` : `host ${hosts[0].hostname}`,
      inInventory: true,
    };
  }

  const context: string[] = [];
  const { rows: ifaces } = await pool.query(
    `SELECT hi.host_id, h.hostname, hi.name FROM host_interfaces hi
     JOIN hosts h ON h.id = hi.host_id
     WHERE host(hi.ip_address) = $1 AND h.enabled = true ORDER BY h.hostname LIMIT 1`,
    [ip]
  );
  if (ifaces[0]) {
    const tags = await hostTagNames(ifaces[0].host_id);
    context.push(`interface ${ifaces[0].name} of ${ifaces[0].hostname}${tags.length ? ` (tags ${tags.join(', ')})` : ''}`);
  }
  const { rows: vlans } = await pool.query(`SELECT id, name, subnet FROM vlans WHERE subnet IS NOT NULL ORDER BY vlan_tag ASC, id ASC`);
  const vlan = vlans.find((v: any) => v.subnet && ipMatchesCidr(ip, String(v.subnet)));
  if (vlan) context.push(`in VLAN ${vlan.name}`);

  return {
    type: 'CIDR',
    value: hostCidr,
    label: `CIDR:${hostCidr}`,
    context: context.length ? context.join(', ') : undefined,
    inInventory: !!ifaces[0],
  };
}

async function hostTagNames(hostId: string): Promise<string[]> {
  const { rows } = await pool.query(
    `SELECT t.name FROM tags t JOIN host_tags ht ON ht.tag_id = t.id WHERE ht.host_id = $1 ORDER BY t.name ASC LIMIT 5`,
    [hostId]
  );
  return rows.map((r: any) => String(r.name));
}

/** Keep generated comments within the rule-comment rules (no quotes/backslashes/$/backticks, ≤255 chars). */
function safeComment(text: string): string {
  return text.replace(/["\\\r\n`$']/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 255);
}

/**
 * The same checks the policy-rules route applies to a rule before it is stored (lib/rule-validation),
 * so a recommendation can never put a rule into a policy version that the API itself would refuse.
 */
export function recommendedRuleProblems(rule: Partial<RecommendedRule>): string[] {
  const problems: string[] = [];
  if (!directionSchema.safeParse(rule.direction).success || (rule.direction !== 'IN' && rule.direction !== 'OUT')) {
    problems.push(`invalid direction '${rule.direction}'`);
  }
  if (rule.action !== 'ALLOW') problems.push(`invalid action '${rule.action}'`);
  if (!protocolSchema.safeParse(rule.protocol).success) problems.push(`protocol '${rule.protocol}' cannot be expressed in a policy rule`);
  if (!sourceTypeSchema.safeParse(rule.sourceType).success) problems.push(`invalid source type '${rule.sourceType}'`);
  if (rule.comment !== undefined && rule.comment !== null && !ruleCommentSchema.safeParse(rule.comment).success) {
    problems.push('comment contains characters that are not allowed');
  }
  problems.push(
    ...validateRuleSemantics({
      protocol: rule.protocol,
      ports: rule.ports ?? null,
      sourceType: rule.sourceType,
      sourceValue: rule.sourceValue,
      direction: rule.direction,
      destinationType: null,
      destinationValue: null,
    })
  );
  return problems;
}

function calculateConfidence(flow: CommunicationFlow, isKnownPort: boolean, bothInInventory: boolean): number {
  let confidence = 50; // Base confidence

  // Higher confidence for well-known ports
  if (isKnownPort) confidence += 20;

  // Higher confidence for frequent flows
  if (flow.count >= 100) confidence += 15;
  else if (flow.count >= 10) confidence += 10;
  else if (flow.count >= 3) confidence += 5;

  // Higher confidence when both endpoints are in inventory
  if (bothInInventory) confidence += 15;

  return Math.min(confidence, 100);
}

function ruleKey(r: { direction: string; protocol: string; ports: string | null; sourceType: string; sourceValue: string }): string {
  return [r.direction, r.protocol, (r.ports ?? '').replace(/\s+/g, ''), r.sourceType, r.sourceValue].join('|');
}

export class RecommendationError extends Error {
  constructor(public code: string, message: string, public status = 400) {
    super(message);
    this.name = 'RecommendationError';
  }
}

/**
 * Build recommendations from an audit session and store them (with the audit event) in a
 * single transaction. Rules already present in another PENDING recommendation for the same
 * host are skipped; when nothing new remains no recommendation row is created.
 */
export async function generateRecommendations(
  auditSessionId: string,
  hostId: string,
  actorUserId: string | null = null
): Promise<{ recommendationId: string | null; ruleCount: number; avgConfidence: number; skippedDuplicates: number }> {
  // Get audit session flows
  const { rows: sessions } = await pool.query(
    `SELECT * FROM firewall_audit_sessions WHERE id = $1`,
    [auditSessionId]
  );
  if (!sessions[0]) throw new RecommendationError('audit_session_not_found', 'Audit session not found', 404);
  const session = sessions[0];
  if (session.host_id !== hostId) {
    throw new RecommendationError('host_mismatch', 'Audit session does not belong to this host');
  }

  if (!session.log_data?.flows || session.log_data.flows.length === 0) {
    throw new RecommendationError('no_flow_data', 'No flow data available for this audit session');
  }

  // Ignore reply traffic accepted by the baseline established/related rule — it is not a
  // service the host needs a rule for — as well as loopback/forwarded packets.
  // Protocols a policy rule cannot express (IGMP, GRE, ESP, ...) are skipped: a recommendation for
  // them could never be compiled.
  const flows: CommunicationFlow[] = (session.log_data.flows as CommunicationFlow[]).filter(
    (f) => !f.established && (f.direction === 'IN' || f.direction === 'OUT') && COMPILER_PROTOCOLS.has(String(f.protocol))
  );
  if (flows.length === 0) {
    throw new RecommendationError('no_flow_data', 'Only established/related reply traffic was observed; nothing to recommend');
  }

  // Get existing deployed rules for dedup
  const { rows: deployedRules } = await pool.query(
    `SELECT pr.* FROM policy_rules pr
     JOIN policy_versions pv ON pv.id = pr.policy_version_id
     JOIN deployments d ON d.policy_version_id = pv.id
     JOIN deployment_hosts dh ON dh.deployment_id = d.id
     WHERE dh.host_id = $1 AND dh.status = 'SUCCEEDED'
     ORDER BY d.created_at DESC`,
    [hostId]
  );

  const recommendedRules: RecommendedRule[] = [];

  // Group flows by destination port for consolidation
  const portGroups = new Map<string, CommunicationFlow[]>();
  for (const flow of flows) {
    // Ports only exist for tcp/udp; an icmp flow never carries one into a rule.
    const hasPorts = flow.protocol === 'tcp' || flow.protocol === 'udp';
    const key = `${flow.direction}:${flow.protocol}:${hasPorts ? flow.destinationPort ?? '*' : '*'}`;
    if (!portGroups.has(key)) portGroups.set(key, []);
    portGroups.get(key)!.push(flow);
  }

  for (const [key, groupFlows] of portGroups) {
    const [direction, protocol, portStr] = key.split(':');
    const port = portStr === '*' ? null : parseInt(portStr, 10);
    const isKnownPort = port !== null && KNOWN_SERVICE_PORTS[port] !== undefined;

    // Resolve source IPs to entities
    const sourceEntities = new Map<string, { entity: ResolvedSource; flows: CommunicationFlow[] }>();
    for (const flow of groupFlows) {
      const sourceIp = direction === 'IN' ? flow.sourceIp : flow.destinationIp;
      const entity = await resolveIpToEntity(sourceIp);
      if (!entity) continue;

      const entityKey = `${entity.type}:${entity.value}`;
      if (!sourceEntities.has(entityKey)) {
        sourceEntities.set(entityKey, { entity, flows: [] });
      }
      sourceEntities.get(entityKey)!.flows.push(flow);
    }

    // Create a rule per source entity
    for (const [, { entity, flows: entityFlows }] of sourceEntities) {
      const totalFlowCount = entityFlows.reduce((sum, f) => sum + f.count, 0);

      // Check both endpoints in inventory
      const bothInInventory = entity.inInventory;

      const confidence = calculateConfidence(
        entityFlows[0],
        isKnownPort,
        bothInInventory
      );

      // Dedup: check if rule already exists
      const isDuplicate = deployedRules.some(r => {
        if (r.direction !== direction && r.direction !== 'BOTH') return false;
        if (r.protocol !== protocol && r.protocol !== 'any') return false;
        if (r.source_type !== entity.type) return false;
        if (r.source_value !== entity.value) return false;
        if (port && r.ports && !r.ports.split(',').includes(String(port))) return false;
        return true;
      });
      if (isDuplicate) continue;

      const serviceName = port && KNOWN_SERVICE_PORTS[port] ? ` (${KNOWN_SERVICE_PORTS[port]})` : '';
      const candidate: RecommendedRule = {
        direction: direction as 'IN' | 'OUT',
        action: 'ALLOW',
        protocol,
        ports: port ? String(port) : null,
        sourceType: entity.type,
        sourceValue: entity.value,
        comment: safeComment(
          `Auto-recommended: ${entity.label} → ${protocol}/${port ?? 'any'}${serviceName} (${totalFlowCount} flows observed)` +
            (entity.context ? ` [${entity.context}]` : '')
        ),
        confidence,
        flowCount: totalFlowCount,
        ...(entity.context ? { context: entity.context } : {}),
      };
      if (recommendedRuleProblems(candidate).length > 0) continue;
      recommendedRules.push(candidate);
    }
  }

  // Sort by confidence desc
  recommendedRules.sort((a, b) => b.confidence - a.confidence);

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // Serialize generation per host so concurrent requests cannot create duplicates.
    const hostLock = await client.query(`SELECT id FROM hosts WHERE id = $1 FOR UPDATE`, [hostId]);
    if (!hostLock.rows[0]) throw new RecommendationError('host_not_found', 'Host not found', 404);

    const { rows: pending } = await client.query(
      `SELECT recommended_rules FROM policy_recommendations WHERE host_id = $1 AND status = 'PENDING'`,
      [hostId]
    );
    const pendingKeys = new Set<string>();
    for (const p of pending) {
      const list = (typeof p.recommended_rules === 'string' ? JSON.parse(p.recommended_rules) : p.recommended_rules) ?? [];
      for (const r of list as RecommendedRule[]) pendingKeys.add(ruleKey(r));
    }
    const freshRules = recommendedRules.filter((r) => !pendingKeys.has(ruleKey(r)));
    const skippedDuplicates = recommendedRules.length - freshRules.length;

    if (freshRules.length === 0) {
      await client.query('ROLLBACK');
      return { recommendationId: null, ruleCount: 0, avgConfidence: 0, skippedDuplicates };
    }

    const avgConfidence = freshRules.reduce((sum, r) => sum + r.confidence, 0) / freshRules.length;

    const { rows } = await client.query(
      `INSERT INTO policy_recommendations (audit_session_id, host_id, status, recommended_rules, confidence_score)
       VALUES ($1, $2, 'PENDING', $3, $4) RETURNING id`,
      [auditSessionId, hostId, JSON.stringify(freshRules), avgConfidence]
    );
    const recommendationId = rows[0].id;

    await client.query(
      `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
       VALUES ($1, 'RECOMMENDATION_GENERATE', 'policy_recommendation', $2, $3)`,
      [actorUserId, recommendationId, JSON.stringify({ auditSessionId, hostId, ruleCount: freshRules.length, skippedDuplicates })]
    );

    await client.query('COMMIT');
    return {
      recommendationId,
      ruleCount: freshRules.length,
      avgConfidence: Math.round(avgConfidence * 100) / 100,
      skippedDuplicates,
    };
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }
}

/**
 * Pick the policy set a recommendation should extend, deterministically:
 *  1. HOST_LIST sets containing the host (fewest member hosts first, then oldest)
 *  2. TAG sets scoped to one of the host's tags (ordered by tag name, then oldest)
 *  3. otherwise null (caller creates a dedicated HOST_LIST set)
 */
async function findTargetPolicySet(client: import('pg').PoolClient, hostId: string): Promise<string | null> {
  const { rows: hostList } = await client.query(
    `SELECT ps.id
       FROM policy_sets ps
       JOIN policy_set_hosts psh ON psh.policy_set_id = ps.id AND psh.host_id = $1
      WHERE ps.scope_type = 'HOST_LIST'
      ORDER BY (SELECT COUNT(*) FROM policy_set_hosts x WHERE x.policy_set_id = ps.id) ASC, ps.created_at ASC, ps.id ASC
      LIMIT 1`,
    [hostId]
  );
  if (hostList[0]) return hostList[0].id;

  const { rows: tagSets } = await client.query(
    `SELECT ps.id
       FROM policy_sets ps
       JOIN host_tags ht ON ht.tag_id = ps.scope_tag_id AND ht.host_id = $1
       JOIN tags t ON t.id = ps.scope_tag_id
      WHERE ps.scope_type = 'TAG'
      ORDER BY t.name ASC, ps.created_at ASC, ps.id ASC
      LIMIT 1`,
    [hostId]
  );
  return tagSets[0]?.id ?? null;
}

/**
 * Apply an ACCEPTED recommendation: create a new DRAFT version of the target policy set that
 * keeps all rules of the base version (latest APPROVED/DEPLOYED, else latest) and appends the
 * recommended rules (skipping ones already present). The draft must go through review.
 */
export async function applyRecommendation(
  recommendationId: string,
  userId: string | null,
  policySetId?: string
): Promise<{
  versionId: string;
  policySetId: string;
  rulesCreated: number;
  rulesCarriedOver: number;
  skippedExisting: number;
  skippedInvalid: Array<{ index: number; problems: string[] }>;
}> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const { rows } = await client.query(
      `SELECT * FROM policy_recommendations WHERE id = $1 FOR UPDATE`,
      [recommendationId]
    );
    if (!rows[0]) throw new RecommendationError('not_found', 'Recommendation not found', 404);
    const rec = rows[0];
    if (rec.status !== 'ACCEPTED') {
      throw new RecommendationError('not_accepted', 'Recommendation must be accepted before applying', 409);
    }

    const storedRules: RecommendedRule[] =
      (typeof rec.recommended_rules === 'string' ? JSON.parse(rec.recommended_rules) : rec.recommended_rules) ?? [];
    // Recommendations stored by older versions may contain rules the API would refuse (IGMP, ports on
    // icmp, ...). Those are never applied; they are reported back instead.
    const skippedInvalid: Array<{ index: number; problems: string[] }> = [];
    const rules = storedRules.filter((r, index) => {
      const problems = recommendedRuleProblems(r);
      if (problems.length) skippedInvalid.push({ index, problems });
      return problems.length === 0;
    });
    if (rules.length === 0) {
      throw new RecommendationError(
        'invalid_recommendation',
        storedRules.length === 0
          ? 'Recommendation contains no rules'
          : `None of the recommended rules is valid: ${skippedInvalid.map((s) => `rule ${s.index + 1}: ${s.problems.join(', ')}`).join('; ')}`
      );
    }

    let targetPolicySetId = policySetId ?? (await findTargetPolicySet(client, rec.host_id));

    if (!targetPolicySetId) {
      // Create a new HOST_LIST policy set dedicated to this host
      const { rows: hostInfo } = await client.query(`SELECT hostname FROM hosts WHERE id = $1`, [rec.host_id]);
      const hostname = hostInfo[0]?.hostname ?? 'Unknown';
      const { rows: ps } = await client.query(
        `INSERT INTO policy_sets (name, description, scope_type, created_by)
         VALUES ($1, $2, 'HOST_LIST', $3) RETURNING id`,
        [`Recommended: ${hostname}`, `Auto-generated from audit recommendation`, userId]
      );
      targetPolicySetId = ps[0].id as string;
      await client.query(
        `INSERT INTO policy_set_hosts (policy_set_id, host_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
        [targetPolicySetId, rec.host_id]
      );
    }

    const locked = await lockPolicySetAndGetBase(client, targetPolicySetId);
    if (!locked) throw new RecommendationError('policy_set_not_found', 'Policy set not found', 404);
    const { base, nextVersionNumber } = locked;
    const existingRules = base ? await loadVersionRules(client, base.id) : [];

    const existingKeys = new Set(
      existingRules
        .filter((r) => r.action === 'ALLOW')
        .map((r) =>
          ruleKey({ direction: r.direction ?? 'IN', protocol: r.protocol, ports: r.ports, sourceType: r.source_type, sourceValue: r.source_value })
        )
    );
    const toAppend = rules.filter((r) => !existingKeys.has(ruleKey(r)));

    const versionId = await createDraftVersion(client, {
      policySetId: targetPolicySetId,
      versionNumber: nextVersionNumber,
      base,
      changeSummary: `Audit recommendation: ${toAppend.length} rule(s) appended to v${base?.version_number ?? 0} — review rule order before submitting`,
      createdBy: userId,
    });

    let orderIndex = 0;
    for (const r of existingRules) {
      await insertRule(client, versionId, orderIndex++, r);
    }
    for (const rule of toAppend) {
      await insertRule(client, versionId, orderIndex++, {
        direction: rule.direction,
        action: rule.action,
        protocol: rule.protocol,
        ports: rule.ports,
        source_type: rule.sourceType,
        source_value: rule.sourceValue,
        log_mode: 'NONE',
        comment: rule.comment,
      });
    }

    await client.query(
      `UPDATE policy_recommendations SET status = 'APPLIED', applied_policy_version_id = $2 WHERE id = $1`,
      [recommendationId, versionId]
    );

    await client.query(
      `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
       VALUES ($1, 'RECOMMENDATION_APPLY', 'policy_recommendation', $2, $3)`,
      [userId, recommendationId, JSON.stringify({
        versionId,
        policySetId: targetPolicySetId,
        baseVersionId: base?.id ?? null,
        rulesCreated: toAppend.length,
        rulesCarriedOver: existingRules.length,
        skippedInvalid: skippedInvalid.length,
      })]
    );

    await client.query('COMMIT');
    return {
      versionId,
      policySetId: targetPolicySetId,
      rulesCreated: toAppend.length,
      rulesCarriedOver: existingRules.length,
      skippedExisting: rules.length - toAppend.length,
      skippedInvalid,
    };
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }
}
