import { pool } from '../db/pool.js';
import type { CommunicationFlow } from './log-parser.js';

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
}

// Helper: check if IP matches a CIDR range
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

async function resolveIpToEntity(ip: string): Promise<{ type: string; value: string; label: string } | null> {
  // Check if IP belongs to a host with tags
  const { rows: hosts } = await pool.query(
    `SELECT h.id, h.hostname, h.mgmt_ip FROM hosts h WHERE h.mgmt_ip = $1 AND h.enabled = true`,
    [ip]
  );
  if (hosts[0]) {
    // Try to resolve to a tag
    const { rows: tags } = await pool.query(
      `SELECT t.id, t.name FROM tags t JOIN host_tags ht ON ht.tag_id = t.id WHERE ht.host_id = $1 LIMIT 1`,
      [hosts[0].id]
    );
    if (tags[0]) {
      return { type: 'TAG', value: tags[0].id, label: `TAG:${tags[0].name}` };
    }
    return { type: 'HOST', value: hosts[0].id, label: `HOST:${hosts[0].hostname}` };
  }

  // Check host interfaces
  const { rows: ifaces } = await pool.query(
    `SELECT hi.host_id, h.hostname FROM host_interfaces hi
     JOIN hosts h ON h.id = hi.host_id
     WHERE hi.ip_address = $1 AND h.enabled = true LIMIT 1`,
    [ip]
  );
  if (ifaces[0]) {
    const { rows: tags } = await pool.query(
      `SELECT t.id, t.name FROM tags t JOIN host_tags ht ON ht.tag_id = t.id WHERE ht.host_id = $1 LIMIT 1`,
      [ifaces[0].host_id]
    );
    if (tags[0]) {
      return { type: 'TAG', value: tags[0].id, label: `TAG:${tags[0].name}` };
    }
  }

  // Check VLANs by subnet
  const { rows: vlans } = await pool.query(`SELECT id, name, subnet FROM vlans WHERE subnet IS NOT NULL`);
  for (const vlan of vlans) {
    if (vlan.subnet && ipMatchesCidr(ip, vlan.subnet)) {
      return { type: 'VLAN', value: vlan.id, label: `VLAN:${vlan.name}` };
    }
  }

  // Fallback to CIDR
  return { type: 'CIDR', value: `${ip}/32`, label: `CIDR:${ip}/32` };
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

export async function generateRecommendations(
  auditSessionId: string,
  hostId: string
): Promise<{ recommendationId: string; ruleCount: number; avgConfidence: number }> {
  // Get audit session flows
  const { rows: sessions } = await pool.query(
    `SELECT * FROM firewall_audit_sessions WHERE id = $1`,
    [auditSessionId]
  );
  if (!sessions[0]) throw new Error('Audit session not found');
  const session = sessions[0];

  if (!session.log_data?.flows || session.log_data.flows.length === 0) {
    throw new Error('No flow data available for this audit session');
  }

  const flows: CommunicationFlow[] = session.log_data.flows;

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
    const key = `${flow.direction}:${flow.protocol}:${flow.destinationPort ?? '*'}`;
    if (!portGroups.has(key)) portGroups.set(key, []);
    portGroups.get(key)!.push(flow);
  }

  for (const [key, groupFlows] of portGroups) {
    const [direction, protocol, portStr] = key.split(':');
    const port = portStr === '*' ? null : parseInt(portStr, 10);
    const isKnownPort = port !== null && KNOWN_SERVICE_PORTS[port] !== undefined;

    // Resolve source IPs to entities
    const sourceEntities = new Map<string, { entity: any; flows: CommunicationFlow[] }>();
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
      const bothInInventory = entity.type !== 'CIDR';

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
      recommendedRules.push({
        direction: direction as 'IN' | 'OUT',
        action: 'ALLOW',
        protocol,
        ports: port ? String(port) : null,
        sourceType: entity.type,
        sourceValue: entity.value,
        comment: `Auto-recommended: ${entity.label} → ${protocol}/${port ?? 'any'}${serviceName} (${totalFlowCount} flows observed)`,
        confidence,
        flowCount: totalFlowCount,
      });
    }
  }

  // Sort by confidence desc
  recommendedRules.sort((a, b) => b.confidence - a.confidence);

  const avgConfidence = recommendedRules.length > 0
    ? recommendedRules.reduce((sum, r) => sum + r.confidence, 0) / recommendedRules.length
    : 0;

  // Save recommendation
  const { rows } = await pool.query(
    `INSERT INTO policy_recommendations (audit_session_id, host_id, status, recommended_rules, confidence_score)
     VALUES ($1, $2, 'PENDING', $3, $4) RETURNING id`,
    [auditSessionId, hostId, JSON.stringify(recommendedRules), avgConfidence]
  );

  return {
    recommendationId: rows[0].id,
    ruleCount: recommendedRules.length,
    avgConfidence: Math.round(avgConfidence * 100) / 100,
  };
}

export async function applyRecommendation(
  recommendationId: string,
  userId: string,
  policySetId?: string
): Promise<{ versionId: string; rulesCreated: number }> {
  const { rows } = await pool.query(
    `SELECT * FROM policy_recommendations WHERE id = $1`,
    [recommendationId]
  );
  if (!rows[0]) throw new Error('Recommendation not found');
  const rec = rows[0];

  if (rec.status !== 'ACCEPTED') throw new Error('Recommendation must be accepted before applying');

  const rules: RecommendedRule[] = rec.recommended_rules;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    let targetPolicySetId = policySetId;

    // If no policy set specified, find one matching the host's tags, or create one
    if (!targetPolicySetId) {
      const { rows: hostTags } = await client.query(
        `SELECT ht.tag_id FROM host_tags ht WHERE ht.host_id = $1 LIMIT 1`,
        [rec.host_id]
      );
      if (hostTags[0]) {
        const { rows: ps } = await client.query(
          `SELECT id FROM policy_sets WHERE scope_type = 'TAG' AND scope_tag_id = $1 LIMIT 1`,
          [hostTags[0].tag_id]
        );
        targetPolicySetId = ps[0]?.id;
      }

      if (!targetPolicySetId) {
        // Create a new HOST_LIST policy set
        const { rows: hostInfo } = await client.query(`SELECT hostname FROM hosts WHERE id = $1`, [rec.host_id]);
        const hostname = hostInfo[0]?.hostname ?? 'Unknown';
        const { rows: ps } = await client.query(
          `INSERT INTO policy_sets (name, description, scope_type, created_by)
           VALUES ($1, $2, 'HOST_LIST', $3) RETURNING *`,
          [`Recommended: ${hostname}`, `Auto-generated from audit recommendation`, userId]
        );
        targetPolicySetId = ps[0].id;
        await client.query(
          `INSERT INTO policy_set_hosts (policy_set_id, host_id) VALUES ($1, $2)`,
          [targetPolicySetId, rec.host_id]
        );
      }
    }

    // Get next version number
    const { rows: latestV } = await client.query(
      `SELECT COALESCE(MAX(version_number), 0)::int AS v FROM policy_versions WHERE policy_set_id = $1`,
      [targetPolicySetId]
    );
    const nextVersion = (latestV[0]?.v ?? 0) + 1;

    // Create version
    const { rows: vRows } = await client.query(
      `INSERT INTO policy_versions (policy_set_id, version_number, status, change_summary, created_by, interface_scope_type)
       VALUES ($1, $2, 'DRAFT', $3, $4, 'ALL_INTERFACES') RETURNING *`,
      [targetPolicySetId, nextVersion, 'Auto-generated from audit recommendation', userId]
    );
    const version = vRows[0];

    // Create rules
    let rulesCreated = 0;
    for (let i = 0; i < rules.length; i++) {
      const rule = rules[i];
      await client.query(
        `INSERT INTO policy_rules (policy_version_id, order_index, direction, action, protocol, ports, source_type, source_value, log_mode, comment)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'NONE', $9)`,
        [version.id, i, rule.direction, rule.action, rule.protocol, rule.ports, rule.sourceType, rule.sourceValue, rule.comment]
      );
      rulesCreated++;
    }

    // Update recommendation
    await client.query(
      `UPDATE policy_recommendations SET status = 'APPLIED', applied_policy_version_id = $2 WHERE id = $1`,
      [recommendationId, version.id]
    );

    await client.query(
      `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
       VALUES ($1, 'RECOMMENDATION_APPLY', 'policy_recommendation', $2, $3)`,
      [userId, recommendationId, JSON.stringify({ versionId: version.id, rulesCreated })]
    );

    await client.query('COMMIT');
    return { versionId: version.id, rulesCreated };
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}
