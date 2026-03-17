import { Router } from 'express';
import { z } from 'zod';
import { pool } from '../../db/pool.js';
import { requireAuth, requireRole } from '../../middleware/auth.js';
import { evaluateRule, evaluateAllRules, evaluateHostAgainstRules } from '../../services/tag-rule-engine.js';
export const tagRulesRouter = Router();
tagRulesRouter.use(requireAuth);
// List all tag rules
tagRulesRouter.get('/', requireRole('viewer', 'operator', 'approver', 'admin'), async (_req, res) => {
    const { rows } = await pool.query(`SELECT tr.*, t.name as tag_name,
       (SELECT COUNT(*) FROM tag_rule_results trr WHERE trr.tag_rule_id = tr.id AND trr.matched = true) as matched_count
     FROM tag_rules tr
     LEFT JOIN tags t ON t.id = tr.tag_id
     ORDER BY tr.priority DESC, tr.name ASC`);
    res.json({ tagRules: rows });
});
// Get single tag rule
tagRulesRouter.get('/:id', requireRole('viewer', 'operator', 'approver', 'admin'), async (req, res) => {
    const { rows } = await pool.query(`SELECT tr.*, t.name as tag_name FROM tag_rules tr LEFT JOIN tags t ON t.id = tr.tag_id WHERE tr.id = $1`, [req.params.id]);
    if (!rows[0])
        return res.status(404).json({ error: 'not_found' });
    // Get matched hosts
    const { rows: matchedHosts } = await pool.query(`SELECT h.id, h.hostname, h.mgmt_ip, trr.evaluated_at
     FROM tag_rule_results trr
     JOIN hosts h ON h.id = trr.host_id
     WHERE trr.tag_rule_id = $1 AND trr.matched = true
     ORDER BY h.hostname ASC`, [req.params.id]);
    res.json({ tagRule: rows[0], matchedHosts });
});
const tagRuleSchema = z.object({
    name: z.string().min(1),
    description: z.string().optional(),
    tagId: z.string().uuid(),
    enabled: z.boolean().default(true),
    priority: z.number().int().default(0),
    criteria: z.object({
        conditions: z.array(z.object({
            field: z.enum(['hostname', 'mgmt_ip', 'vlan_id', 'vlan_tag', 'os_family', 'environment', 'firewall_backend', 'tag']),
            operator: z.enum(['equals', 'not_equals', 'matches', 'contains', 'in_cidr', 'has_tag']),
            value: z.string(),
        })),
        logic: z.enum(['AND', 'OR']).default('AND'),
    }),
});
// Create tag rule
tagRulesRouter.post('/', requireRole('operator', 'admin'), async (req, res) => {
    const parsed = tagRuleSchema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: 'invalid_body', details: parsed.error.issues });
    const b = parsed.data;
    const userRes = await pool.query(`SELECT id FROM users WHERE username=$1 LIMIT 1`, [req.auth.username]);
    const userId = userRes.rows[0]?.id ?? null;
    const { rows } = await pool.query(`INSERT INTO tag_rules (name, description, tag_id, enabled, priority, criteria, created_by)
     VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`, [b.name, b.description ?? null, b.tagId, b.enabled, b.priority, JSON.stringify(b.criteria), userId]);
    await pool.query(`INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ($1, 'TAG_RULE_CREATE', 'tag_rule', $2, $3)`, [userId, rows[0].id, JSON.stringify({ name: b.name, tagId: b.tagId })]);
    res.status(201).json({ tagRule: rows[0] });
});
// Update tag rule
tagRulesRouter.put('/:id', requireRole('operator', 'admin'), async (req, res) => {
    const parsed = tagRuleSchema.partial().safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: 'invalid_body' });
    const b = parsed.data;
    const { rows } = await pool.query(`UPDATE tag_rules
     SET name = COALESCE($2, name),
         description = COALESCE($3, description),
         tag_id = COALESCE($4, tag_id),
         enabled = COALESCE($5, enabled),
         priority = COALESCE($6, priority),
         criteria = COALESCE($7, criteria),
         updated_at = now()
     WHERE id = $1
     RETURNING *`, [
        req.params.id,
        b.name ?? null,
        b.description ?? null,
        b.tagId ?? null,
        b.enabled ?? null,
        b.priority ?? null,
        b.criteria ? JSON.stringify(b.criteria) : null,
    ]);
    if (!rows[0])
        return res.status(404).json({ error: 'not_found' });
    await pool.query(`INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), $2, $3, $4, $5)`, [req.auth.username, 'TAG_RULE_UPDATE', 'tag_rule', req.params.id, JSON.stringify({ name: rows[0].name })]);
    res.json({ tagRule: rows[0] });
});
// Delete tag rule
tagRulesRouter.delete('/:id', requireRole('operator', 'admin'), async (req, res) => {
    // Remove auto-assigned tags from this rule first
    await pool.query(`DELETE FROM host_tags WHERE source = 'rule' AND source_rule_id = $1`, [req.params.id]);
    const { rowCount } = await pool.query(`DELETE FROM tag_rules WHERE id = $1`, [req.params.id]);
    if (!rowCount)
        return res.status(404).json({ error: 'not_found' });
    await pool.query(`INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), $2, $3, $4, $5)`, [req.auth.username, 'TAG_RULE_DELETE', 'tag_rule', req.params.id, JSON.stringify({ ruleId: req.params.id })]);
    res.json({ ok: true });
});
// Evaluate a single rule
tagRulesRouter.post('/:id/evaluate', requireRole('operator', 'admin'), async (req, res) => {
    try {
        const result = await evaluateRule(req.params.id);
        res.json(result);
    }
    catch (e) {
        res.status(400).json({ error: e.message });
    }
});
// Evaluate all rules
tagRulesRouter.post('/evaluate-all', requireRole('operator', 'admin'), async (_req, res) => {
    try {
        const result = await evaluateAllRules();
        res.json(result);
    }
    catch (e) {
        res.status(500).json({ error: e.message });
    }
});
// Evaluate rules for a specific host
tagRulesRouter.post('/evaluate-host/:hostId', requireRole('operator', 'admin'), async (req, res) => {
    try {
        const result = await evaluateHostAgainstRules(req.params.hostId);
        res.json(result);
    }
    catch (e) {
        res.status(400).json({ error: e.message });
    }
});
