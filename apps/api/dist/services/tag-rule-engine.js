import { pool } from '../db/pool.js';
// Helper: check if IP matches a CIDR range
function ipMatchesCidr(ip, cidr) {
    try {
        const cleanIp = ip.split('/')[0];
        const [cidrIp, prefix] = cidr.split('/');
        const prefixLen = prefix ? parseInt(prefix, 10) : 32;
        if (prefixLen < 0 || prefixLen > 32)
            return false;
        const ipParts = cleanIp.split('.').map(Number);
        const cidrParts = cidrIp.split('.').map(Number);
        if (ipParts.length !== 4 || cidrParts.length !== 4)
            return false;
        if (ipParts.some(p => isNaN(p) || p < 0 || p > 255))
            return false;
        if (cidrParts.some(p => isNaN(p) || p < 0 || p > 255))
            return false;
        const mask = prefixLen === 0 ? 0 : (0xFFFFFFFF << (32 - prefixLen)) >>> 0;
        const ipNum = (ipParts[0] << 24) + (ipParts[1] << 16) + (ipParts[2] << 8) + ipParts[3];
        const cidrNum = (cidrParts[0] << 24) + (cidrParts[1] << 16) + (cidrParts[2] << 8) + cidrParts[3];
        return (ipNum & mask) === (cidrNum & mask);
    }
    catch {
        return false;
    }
}
async function getHostData(hostId) {
    const hostQuery = hostId
        ? `SELECT h.*, v.vlan_tag FROM hosts h LEFT JOIN vlans v ON h.vlan_id = v.id WHERE h.id = $1`
        : `SELECT h.*, v.vlan_tag FROM hosts h LEFT JOIN vlans v ON h.vlan_id = v.id WHERE h.enabled = true`;
    const hostParams = hostId ? [hostId] : [];
    const { rows: hosts } = await pool.query(hostQuery, hostParams);
    const result = [];
    for (const host of hosts) {
        const { rows: tags } = await pool.query(`SELECT t.id, t.name FROM tags t JOIN host_tags ht ON ht.tag_id = t.id WHERE ht.host_id = $1`, [host.id]);
        result.push({
            id: host.id,
            hostname: host.hostname,
            mgmt_ip: host.mgmt_ip,
            vlan_id: host.vlan_id,
            vlan_tag: host.vlan_tag,
            os_family: host.os_family,
            environment: host.environment,
            firewall_backend: host.firewall_backend,
            tag_ids: tags.map((t) => t.id),
            tag_names: tags.map((t) => t.name),
        });
    }
    return result;
}
function evaluateCondition(condition, host) {
    const { field, operator, value } = condition;
    let fieldValue = null;
    switch (field) {
        case 'hostname':
            fieldValue = host.hostname;
            break;
        case 'mgmt_ip':
            fieldValue = host.mgmt_ip;
            break;
        case 'vlan_id':
            fieldValue = host.vlan_id;
            break;
        case 'vlan_tag':
            fieldValue = host.vlan_tag?.toString() ?? null;
            break;
        case 'os_family':
            fieldValue = host.os_family;
            break;
        case 'environment':
            fieldValue = host.environment;
            break;
        case 'firewall_backend':
            fieldValue = host.firewall_backend;
            break;
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
                // Limit regex length to prevent ReDoS
                if (value.length > 200)
                    return false;
                const regex = new RegExp(value, 'i');
                // Test with a timeout by limiting input length
                const testValue = fieldValue.length > 1000 ? fieldValue.slice(0, 1000) : fieldValue;
                return regex.test(testValue);
            }
            catch {
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
function evaluateCriteria(criteria, host) {
    if (!criteria.conditions || criteria.conditions.length === 0)
        return false;
    if (criteria.logic === 'OR') {
        return criteria.conditions.some(c => evaluateCondition(c, host));
    }
    // Default AND
    return criteria.conditions.every(c => evaluateCondition(c, host));
}
export async function evaluateRule(ruleId) {
    const { rows: rules } = await pool.query(`SELECT * FROM tag_rules WHERE id = $1`, [ruleId]);
    if (!rules[0])
        throw new Error('Tag rule not found');
    const rule = rules[0];
    const hosts = await getHostData();
    const criteria = rule.criteria;
    let matched = 0;
    for (const host of hosts) {
        const isMatch = evaluateCriteria(criteria, host);
        // Upsert result
        await pool.query(`INSERT INTO tag_rule_results (tag_rule_id, host_id, matched, evaluated_at)
       VALUES ($1, $2, $3, now())
       ON CONFLICT (tag_rule_id, host_id) DO UPDATE SET matched = $3, evaluated_at = now()`, [ruleId, host.id, isMatch]);
        if (isMatch) {
            matched++;
            // Auto-assign tag if not already present
            await pool.query(`INSERT INTO host_tags (host_id, tag_id, source, source_rule_id)
         VALUES ($1, $2, 'rule', $3)
         ON CONFLICT (host_id, tag_id) DO NOTHING`, [host.id, rule.tag_id, ruleId]);
        }
        else {
            // Remove auto-assigned tag from this rule (but not manual ones)
            await pool.query(`DELETE FROM host_tags WHERE host_id = $1 AND tag_id = $2 AND source = 'rule' AND source_rule_id = $3`, [host.id, rule.tag_id, ruleId]);
        }
    }
    return { matched, total: hosts.length };
}
export async function evaluateAllRules() {
    const { rows: rules } = await pool.query(`SELECT id FROM tag_rules WHERE enabled = true ORDER BY priority DESC`);
    let totalMatches = 0;
    for (const rule of rules) {
        const result = await evaluateRule(rule.id);
        totalMatches += result.matched;
    }
    return { rulesEvaluated: rules.length, totalMatches };
}
export async function evaluateHostAgainstRules(hostId) {
    const { rows: rules } = await pool.query(`SELECT * FROM tag_rules WHERE enabled = true ORDER BY priority DESC`);
    const hosts = await getHostData(hostId);
    if (!hosts[0])
        throw new Error('Host not found');
    const host = hosts[0];
    const tagsAssigned = [];
    for (const rule of rules) {
        const criteria = rule.criteria;
        const isMatch = evaluateCriteria(criteria, host);
        await pool.query(`INSERT INTO tag_rule_results (tag_rule_id, host_id, matched, evaluated_at)
       VALUES ($1, $2, $3, now())
       ON CONFLICT (tag_rule_id, host_id) DO UPDATE SET matched = $3, evaluated_at = now()`, [rule.id, hostId, isMatch]);
        if (isMatch) {
            const { rowCount } = await pool.query(`INSERT INTO host_tags (host_id, tag_id, source, source_rule_id)
         VALUES ($1, $2, 'rule', $3)
         ON CONFLICT (host_id, tag_id) DO NOTHING`, [hostId, rule.tag_id, rule.id]);
            if (rowCount && rowCount > 0) {
                tagsAssigned.push(rule.tag_id);
            }
        }
        else {
            await pool.query(`DELETE FROM host_tags WHERE host_id = $1 AND tag_id = $2 AND source = 'rule' AND source_rule_id = $3`, [hostId, rule.tag_id, rule.id]);
        }
    }
    return { rulesMatched: tagsAssigned.length, tagsAssigned };
}
