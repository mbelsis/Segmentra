import { Router } from 'express';
import { z } from 'zod';

import { pool } from '../../db/pool.js';
import { requireAuth, requireRole } from '../../middleware/auth.js';
import { instantiateTemplate, previewInstantiation } from '../../services/template-engine.js';

export const templatesRouter = Router();
templatesRouter.use(requireAuth);

// List all templates
templatesRouter.get('/', requireRole('viewer', 'operator', 'admin'), async (req, res) => {
  const category = req.query.category ? String(req.query.category) : null;
  let query = `SELECT pt.*, t.name as target_tag_name,
    (SELECT COUNT(*) FROM policy_template_rules ptr WHERE ptr.policy_template_id = pt.id) as rule_count,
    (SELECT COUNT(*) FROM policy_sets ps WHERE ps.source_template_id = pt.id) as instantiation_count
   FROM policy_templates pt
   LEFT JOIN tags t ON t.id = pt.target_tag_id`;
  const params: any[] = [];

  if (category) {
    query += ` WHERE pt.category = $1`;
    params.push(category);
  }
  query += ` ORDER BY pt.category ASC, pt.name ASC`;

  const { rows } = await pool.query(query, params);
  res.json({ templates: rows });
});

// Get categories
templatesRouter.get('/categories', requireRole('viewer', 'operator', 'admin'), async (_req, res) => {
  const { rows } = await pool.query(
    `SELECT DISTINCT category FROM policy_templates WHERE category IS NOT NULL ORDER BY category ASC`
  );
  res.json({ categories: rows.map(r => r.category) });
});

// Get single template with rules
templatesRouter.get('/:id', requireRole('viewer', 'operator', 'admin'), async (req, res) => {
  const { rows } = await pool.query(
    `SELECT pt.*, t.name as target_tag_name FROM policy_templates pt LEFT JOIN tags t ON t.id = pt.target_tag_id WHERE pt.id = $1`,
    [req.params.id]
  );
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });

  const { rows: rules } = await pool.query(
    `SELECT * FROM policy_template_rules WHERE policy_template_id = $1 ORDER BY order_index ASC`,
    [req.params.id]
  );

  res.json({ template: rows[0], rules });
});

const templateSchema = z.object({
  name: z.string().min(1),
  description: z.string().optional(),
  category: z.string().optional(),
  targetTagId: z.string().uuid().optional().nullable(),
  autoApply: z.boolean().default(false),
  interfaceScopeType: z.enum(['ALL_INTERFACES', 'INTERFACE_ROLE', 'INTERFACE_NAME']).default('INTERFACE_ROLE'),
  interfaceScopeRoles: z.array(z.string()).optional(),
  interfaceScopeNames: z.array(z.string()).optional(),
});

// Create template
templatesRouter.post('/', requireRole('operator', 'admin'), async (req, res) => {
  const parsed = templateSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body', details: parsed.error.issues });
  const b = parsed.data;

  const userRes = await pool.query(`SELECT id FROM users WHERE username=$1 LIMIT 1`, [req.auth!.username]);
  const userId = userRes.rows[0]?.id ?? null;

  const { rows } = await pool.query(
    `INSERT INTO policy_templates (name, description, category, target_tag_id, auto_apply,
       interface_scope_type, interface_scope_roles, interface_scope_names, created_by)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
    [b.name, b.description ?? null, b.category ?? null, b.targetTagId ?? null, b.autoApply,
     b.interfaceScopeType, b.interfaceScopeRoles ?? null, b.interfaceScopeNames ?? null, userId]
  );

  await pool.query(
    `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ($1, 'TEMPLATE_CREATE', 'policy_template', $2, $3)`,
    [userId, rows[0].id, JSON.stringify({ name: b.name })]
  );

  res.status(201).json({ template: rows[0] });
});

// Update template
templatesRouter.put('/:id', requireRole('operator', 'admin'), async (req, res) => {
  const parsed = templateSchema.partial().safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });
  const b = parsed.data;

  const { rows } = await pool.query(
    `UPDATE policy_templates
     SET name = COALESCE($2, name),
         description = COALESCE($3, description),
         category = COALESCE($4, category),
         target_tag_id = COALESCE($5, target_tag_id),
         auto_apply = COALESCE($6, auto_apply),
         interface_scope_type = COALESCE($7, interface_scope_type),
         interface_scope_roles = COALESCE($8, interface_scope_roles),
         interface_scope_names = COALESCE($9, interface_scope_names),
         updated_at = now()
     WHERE id = $1 RETURNING *`,
    [req.params.id, b.name ?? null, b.description ?? null, b.category ?? null,
     b.targetTagId ?? null, b.autoApply ?? null, b.interfaceScopeType ?? null,
     b.interfaceScopeRoles ?? null, b.interfaceScopeNames ?? null]
  );
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });

  await pool.query(
    `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), $2, $3, $4, $5)`,
    [req.auth!.username, 'TEMPLATE_UPDATE', 'policy_template', req.params.id, JSON.stringify({ name: rows[0].name })]
  );

  res.json({ template: rows[0] });
});

// Delete template
templatesRouter.delete('/:id', requireRole('operator', 'admin'), async (req, res) => {
  const { rowCount } = await pool.query(`DELETE FROM policy_templates WHERE id = $1`, [req.params.id]);
  if (!rowCount) return res.status(404).json({ error: 'not_found' });

  await pool.query(
    `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), $2, $3, $4, $5)`,
    [req.auth!.username, 'TEMPLATE_DELETE', 'policy_template', req.params.id, JSON.stringify({ templateId: req.params.id })]
  );

  res.json({ ok: true });
});

// Template rules CRUD
const templateRuleSchema = z.object({
  orderIndex: z.number().int().default(0),
  direction: z.enum(['IN', 'OUT', 'BOTH']).default('IN'),
  action: z.enum(['ALLOW', 'DENY']).default('ALLOW'),
  protocol: z.enum(['tcp', 'udp', 'icmp', 'any']).default('tcp'),
  ports: z.string().optional().nullable(),
  sourceType: z.enum(['CIDR', 'TAG', 'VLAN', 'HOST']).default('CIDR'),
  sourceValue: z.string().default('0.0.0.0/0'),
  logMode: z.enum(['NONE', 'LOG', 'LOG_RATE_LIMITED']).default('NONE'),
  comment: z.string().optional(),
  usePolicyInterfaceScope: z.boolean().default(true),
  interfaceScopeType: z.string().optional(),
  interfaceScopeRoles: z.array(z.string()).optional(),
  interfaceScopeNames: z.array(z.string()).optional(),
});

templatesRouter.get('/:id/rules', requireRole('viewer', 'operator', 'admin'), async (req, res) => {
  const { rows } = await pool.query(
    `SELECT * FROM policy_template_rules WHERE policy_template_id = $1 ORDER BY order_index ASC`,
    [req.params.id]
  );
  res.json({ rules: rows });
});

templatesRouter.post('/:id/rules', requireRole('operator', 'admin'), async (req, res) => {
  const parsed = templateRuleSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body', details: parsed.error.issues });
  const b = parsed.data;

  const { rows } = await pool.query(
    `INSERT INTO policy_template_rules
      (policy_template_id, order_index, direction, action, protocol, ports, source_type, source_value,
       log_mode, comment, use_policy_interface_scope, interface_scope_type, interface_scope_roles, interface_scope_names)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) RETURNING *`,
    [req.params.id, b.orderIndex, b.direction, b.action, b.protocol, b.ports ?? null,
     b.sourceType, b.sourceValue, b.logMode, b.comment ?? null,
     b.usePolicyInterfaceScope, b.interfaceScopeType ?? null,
     b.interfaceScopeRoles ?? null, b.interfaceScopeNames ?? null]
  );
  res.status(201).json({ rule: rows[0] });
});

templatesRouter.put('/rules/:ruleId', requireRole('operator', 'admin'), async (req, res) => {
  const parsed = templateRuleSchema.partial().safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });
  const b = parsed.data;

  const { rows } = await pool.query(
    `UPDATE policy_template_rules
     SET order_index = COALESCE($2, order_index),
         direction = COALESCE($3, direction),
         action = COALESCE($4, action),
         protocol = COALESCE($5, protocol),
         ports = COALESCE($6, ports),
         source_type = COALESCE($7, source_type),
         source_value = COALESCE($8, source_value),
         log_mode = COALESCE($9, log_mode),
         comment = COALESCE($10, comment),
         use_policy_interface_scope = COALESCE($11, use_policy_interface_scope),
         interface_scope_type = COALESCE($12, interface_scope_type),
         interface_scope_roles = COALESCE($13, interface_scope_roles),
         interface_scope_names = COALESCE($14, interface_scope_names)
     WHERE id = $1 RETURNING *`,
    [req.params.ruleId, b.orderIndex ?? null, b.direction ?? null, b.action ?? null,
     b.protocol ?? null, b.ports ?? null, b.sourceType ?? null, b.sourceValue ?? null,
     b.logMode ?? null, b.comment ?? null, b.usePolicyInterfaceScope ?? null,
     b.interfaceScopeType ?? null, b.interfaceScopeRoles ?? null, b.interfaceScopeNames ?? null]
  );
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });
  res.json({ rule: rows[0] });
});

templatesRouter.delete('/rules/:ruleId', requireRole('operator', 'admin'), async (req, res) => {
  const { rowCount } = await pool.query(`DELETE FROM policy_template_rules WHERE id = $1`, [req.params.ruleId]);
  if (!rowCount) return res.status(404).json({ error: 'not_found' });
  res.json({ ok: true });
});

// Instantiate template
templatesRouter.post('/:id/instantiate', requireRole('operator', 'admin'), async (req, res) => {
  const bodySchema = z.object({
    name: z.string().optional(),
    scopeType: z.string().optional(),
    scopeTagId: z.string().uuid().optional(),
    scopeVlanId: z.string().uuid().optional(),
    hostIds: z.array(z.string().uuid()).optional(),
  });
  const parsed = bodySchema.safeParse(req.body ?? {});
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });

  const userRes = await pool.query(`SELECT id FROM users WHERE username=$1 LIMIT 1`, [req.auth!.username]);
  const userId = userRes.rows[0]?.id ?? null;

  try {
    const result = await instantiateTemplate(req.params.id, userId, parsed.data);
    res.status(201).json(result);
  } catch (e: any) {
    res.status(400).json({ error: e.message });
  }
});

// Preview instantiation
templatesRouter.post('/:id/preview', requireRole('viewer', 'operator', 'admin'), async (req, res) => {
  try {
    const result = await previewInstantiation(req.params.id);
    res.json(result);
  } catch (e: any) {
    res.status(400).json({ error: e.message });
  }
});
