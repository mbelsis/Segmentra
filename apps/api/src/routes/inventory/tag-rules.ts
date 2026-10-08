import { Router } from 'express';
import { z } from 'zod';

import { pool } from '../../db/pool.js';
import { requireAuth, requireRole } from '../../middleware/auth.js';
import {
  evaluateAllRules,
  evaluateHostAgainstRules,
  evaluateRule,
  previewCriteria,
  removeRuleAssignedTags,
  validateCriteria,
} from '../../services/tag-rule-engine.js';

/** Re-apply rule-assigned tags now; returns an error message instead of failing the request. */
async function reconcileNow(context: string): Promise<string | null> {
  try {
    await evaluateAllRules();
    return null;
  } catch (e: any) {
    // eslint-disable-next-line no-console
    console.error(`[Tag Rules] Re-evaluation after ${context} failed:`, e);
    return e?.message ?? 'reevaluation_failed';
  }
}

export const tagRulesRouter = Router();
tagRulesRouter.use(requireAuth);

// List all tag rules
tagRulesRouter.get('/', requireRole('viewer', 'operator', 'approver', 'admin'), async (_req, res) => {
  const { rows } = await pool.query(
    `SELECT tr.*, t.name as tag_name,
       (SELECT COUNT(*) FROM tag_rule_results trr WHERE trr.tag_rule_id = tr.id AND trr.matched = true) as matched_count
     FROM tag_rules tr
     LEFT JOIN tags t ON t.id = tr.tag_id
     ORDER BY tr.priority DESC, tr.name ASC`
  );
  res.json({ tagRules: rows });
});

// Get single tag rule
tagRulesRouter.get('/:id', requireRole('viewer', 'operator', 'approver', 'admin'), async (req, res) => {
  const { rows } = await pool.query(
    `SELECT tr.*, t.name as tag_name FROM tag_rules tr LEFT JOIN tags t ON t.id = tr.tag_id WHERE tr.id = $1`,
    [req.params.id]
  );
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });

  // Get matched hosts
  const { rows: matchedHosts } = await pool.query(
    `SELECT h.id, h.hostname, h.mgmt_ip, trr.evaluated_at
     FROM tag_rule_results trr
     JOIN hosts h ON h.id = trr.host_id
     WHERE trr.tag_rule_id = $1 AND trr.matched = true
     ORDER BY h.hostname ASC`,
    [req.params.id]
  );

  res.json({ tagRule: rows[0], matchedHosts });
});

const criteriaSchema = z.object({
  conditions: z.array(z.object({
    field: z.enum(['hostname', 'mgmt_ip', 'vlan_id', 'vlan_tag', 'os_family', 'environment', 'firewall_backend', 'tag']),
    operator: z.enum(['equals', 'not_equals', 'matches', 'contains', 'in_cidr', 'has_tag']),
    value: z.string().max(500),
  })).max(50),
  logic: z.enum(['AND', 'OR']).default('AND'),
});

const tagRuleSchema = z.object({
  name: z.string().min(1),
  description: z.string().optional(),
  tagId: z.string().uuid(),
  enabled: z.boolean().default(true),
  priority: z.number().int().default(0),
  criteria: criteriaSchema,
});

// Preview body: same shape as create, but only `criteria` is needed (tagId/name optional).
const previewSchema = tagRuleSchema.partial().extend({
  criteria: criteriaSchema,
  // An unselected tag in the form arrives as '' — treat it as "no tag" (preview doesn't need one).
  tagId: z.preprocess((v) => (v === '' || v === null ? undefined : v), z.string().uuid().optional())
});

/**
 * Preview which hosts a rule would match. Performs NO writes.
 * POST /api/tag-rules/preview  -> { hosts: Array<{ id, hostname }> }
 */
tagRulesRouter.post('/preview', requireRole('operator', 'admin'), async (req, res) => {
  const parsed = previewSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body', details: parsed.error.issues });
  const problems = validateCriteria(parsed.data.criteria);
  if (problems.length) return res.status(400).json({ error: 'invalid_criteria', message: problems.join('; '), details: problems });
  const hosts = await previewCriteria(parsed.data.criteria);
  res.json({ hosts });
});

// Create tag rule
tagRulesRouter.post('/', requireRole('operator', 'admin'), async (req, res) => {
  const parsed = tagRuleSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body', details: parsed.error.issues });
  const b = parsed.data;
  const problems = validateCriteria(b.criteria);
  if (problems.length) return res.status(400).json({ error: 'invalid_criteria', message: problems.join('; '), details: problems });

  const tagRes = await pool.query(`SELECT 1 FROM tags WHERE id = $1`, [b.tagId]);
  if (!tagRes.rows[0]) return res.status(400).json({ error: 'tag_not_found' });

  const userRes = await pool.query(`SELECT id FROM users WHERE username=$1 LIMIT 1`, [req.auth!.username]);
  const userId = userRes.rows[0]?.id ?? null;

  const { rows } = await pool.query(
    `INSERT INTO tag_rules (name, description, tag_id, enabled, priority, criteria, created_by)
     VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
    [b.name, b.description ?? null, b.tagId, b.enabled, b.priority, JSON.stringify(b.criteria), userId]
  );

  await pool.query(
    `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ($1, 'TAG_RULE_CREATE', 'tag_rule', $2, $3)`,
    [userId, rows[0].id, JSON.stringify({ name: b.name, tagId: b.tagId })]
  );

  // Apply the new rule right away (same as updates) instead of waiting for the 5-minute job.
  const reevaluationError = b.enabled ? await reconcileNow('rule create') : null;
  res.status(201).json({ tagRule: rows[0], reevaluationError });
});

// Update tag rule
tagRulesRouter.put('/:id', requireRole('operator', 'admin'), async (req, res) => {
  const parsed = tagRuleSchema.partial().safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body', details: parsed.error.issues });
  const b = parsed.data;
  if (b.criteria) {
    const problems = validateCriteria(b.criteria);
    if (problems.length) return res.status(400).json({ error: 'invalid_criteria', message: problems.join('; '), details: problems });
  }
  if (b.tagId) {
    const tagRes = await pool.query(`SELECT 1 FROM tags WHERE id = $1`, [b.tagId]);
    if (!tagRes.rows[0]) return res.status(400).json({ error: 'tag_not_found' });
  }

  const client = await pool.connect();
  let updated: any;
  let removedTags = 0;
  try {
    await client.query('BEGIN');
    const before = await client.query(`SELECT tag_id, enabled FROM tag_rules WHERE id = $1 FOR UPDATE`, [req.params.id]);
    if (!before.rows[0]) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'not_found' });
    }

    const { rows } = await client.query(
      `UPDATE tag_rules
       SET name = COALESCE($2, name),
           description = COALESCE($3, description),
           tag_id = COALESCE($4, tag_id),
           enabled = COALESCE($5, enabled),
           priority = COALESCE($6, priority),
           criteria = COALESCE($7, criteria),
           updated_at = now()
       WHERE id = $1
       RETURNING *`,
      [
        req.params.id,
        b.name ?? null,
        b.description ?? null,
        b.tagId ?? null,
        b.enabled ?? null,
        b.priority ?? null,
        b.criteria ? JSON.stringify(b.criteria) : null,
      ]
    );
    updated = rows[0];

    // Retargeted, disabled or re-scoped: drop what this rule assigned; re-evaluation below
    // re-applies the (new) tag to hosts that still match an enabled rule.
    const tagChanged = before.rows[0].tag_id !== updated.tag_id;
    const disabled = before.rows[0].enabled && !updated.enabled;
    if (tagChanged || disabled || b.criteria) {
      removedTags = await removeRuleAssignedTags(req.params.id, client);
    }

    await client.query(
      `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
       VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), $2, $3, $4, $5)`,
      [req.auth!.username, 'TAG_RULE_UPDATE', 'tag_rule', req.params.id, JSON.stringify({ name: updated.name, tagChanged, disabled, removedTags })]
    );
    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }

  const reevaluationError = removedTags > 0 || updated.enabled ? await reconcileNow('rule update') : null;
  res.json({ tagRule: updated, removedTagAssignments: removedTags, reevaluationError });
});

// Delete tag rule
tagRulesRouter.delete('/:id', requireRole('operator', 'admin'), async (req, res) => {
  const client = await pool.connect();
  let removedTags = 0;
  try {
    await client.query('BEGIN');
    // Remove auto-assigned tags from this rule first (FK is ON DELETE SET NULL, which would
    // otherwise orphan them as un-owned "rule" tags).
    removedTags = await removeRuleAssignedTags(req.params.id, client);
    const { rowCount } = await client.query(`DELETE FROM tag_rules WHERE id = $1`, [req.params.id]);
    if (!rowCount) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'not_found' });
    }
    await client.query(
      `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
       VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), $2, $3, $4, $5)`,
      [req.auth!.username, 'TAG_RULE_DELETE', 'tag_rule', req.params.id, JSON.stringify({ ruleId: req.params.id, removedTags })]
    );
    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }

  // Another enabled rule may still assign the same tag to some of those hosts.
  const reevaluationError = removedTags > 0 ? await reconcileNow('rule delete') : null;
  res.json({ ok: true, removedTagAssignments: removedTags, reevaluationError });
});

// Evaluate a single rule
tagRulesRouter.post('/:id/evaluate', requireRole('operator', 'admin'), async (req, res) => {
  try {
    const result = await evaluateRule(req.params.id);
    res.json(result);
  } catch (e: any) {
    if (e?.message === 'Tag rule not found') return res.status(404).json({ error: 'not_found' });
    throw e;
  }
});

// Evaluate all rules
tagRulesRouter.post('/evaluate-all', requireRole('operator', 'admin'), async (_req, res) => {
  const result = await evaluateAllRules();
  res.json(result);
});

// Evaluate rules for a specific host
tagRulesRouter.post('/evaluate-host/:hostId', requireRole('operator', 'admin'), async (req, res) => {
  try {
    const result = await evaluateHostAgainstRules(req.params.hostId);
    res.json(result);
  } catch (e: any) {
    if (e?.message === 'Host not found') return res.status(404).json({ error: 'not_found' });
    throw e;
  }
});
