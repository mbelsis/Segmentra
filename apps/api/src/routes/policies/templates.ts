import { Router } from 'express';
import { z } from 'zod';

import { pool } from '../../db/pool.js';
import { requireAuth, requireRole } from '../../middleware/auth.js';
import { instantiateTemplate, previewInstantiation } from '../../services/template-engine.js';
import {
  interfaceNamesSchema,
  interfaceRolesSchema,
  interfaceScopeTypeSchema,
  portsSchema,
  protocolSchema,
  ruleCommentSchema,
  sourceTypeSchema,
  destinationTypeSchema,
  directionSchema,
  validateRuleSemantics
} from '../../lib/rule-validation.js';

export const templatesRouter = Router();
templatesRouter.use(requireAuth);

// List all templates
templatesRouter.get('/', requireRole('viewer', 'operator', 'approver', 'admin'), async (req, res) => {
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
templatesRouter.get('/categories', requireRole('viewer', 'operator', 'approver', 'admin'), async (_req, res) => {
  const { rows } = await pool.query(
    `SELECT DISTINCT category FROM policy_templates WHERE category IS NOT NULL ORDER BY category ASC`
  );
  res.json({ categories: rows.map(r => r.category) });
});

// Get single template with rules
templatesRouter.get('/:id', requireRole('viewer', 'operator', 'approver', 'admin'), async (req, res) => {
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
  interfaceScopeType: interfaceScopeTypeSchema.default('ALL_INTERFACES'),
  interfaceScopeRoles: interfaceRolesSchema.optional(),
  interfaceScopeNames: interfaceNamesSchema.optional(),
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
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body', details: parsed.error.issues });
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
  orderIndex: z.number().int().min(0).default(0),
  direction: directionSchema.default('IN'),
  action: z.enum(['ALLOW', 'DENY']).default('ALLOW'),
  protocol: protocolSchema.default('tcp'),
  ports: portsSchema.or(z.literal('')).optional().nullable(),
  sourceType: sourceTypeSchema.default('CIDR'),
  sourceValue: z.string().trim().min(1).default('0.0.0.0/0'),
  destinationType: destinationTypeSchema.optional().nullable(),
  destinationValue: z.string().trim().min(1).optional().nullable(),
  logMode: z.enum(['NONE', 'LOG', 'LOG_RATE_LIMITED']).default('NONE'),
  comment: ruleCommentSchema.optional().nullable(),
  usePolicyInterfaceScope: z.boolean().default(true),
  interfaceScopeType: interfaceScopeTypeSchema.optional().nullable(),
  interfaceScopeRoles: interfaceRolesSchema.optional().nullable(),
  interfaceScopeNames: interfaceNamesSchema.optional().nullable(),
});

// Partial (no defaults) for updates, so omitted fields are not overwritten with defaults
const templateRuleUpdateSchema = z.object({
  orderIndex: z.number().int().min(0),
  direction: directionSchema,
  action: z.enum(['ALLOW', 'DENY']),
  protocol: protocolSchema,
  ports: portsSchema.or(z.literal('')).nullable(),
  sourceType: sourceTypeSchema,
  sourceValue: z.string().trim().min(1),
  destinationType: destinationTypeSchema.nullable(),
  destinationValue: z.string().trim().min(1).nullable(),
  logMode: z.enum(['NONE', 'LOG', 'LOG_RATE_LIMITED']),
  comment: ruleCommentSchema.nullable(),
  usePolicyInterfaceScope: z.boolean(),
  interfaceScopeType: interfaceScopeTypeSchema.nullable(),
  interfaceScopeRoles: interfaceRolesSchema.nullable(),
  interfaceScopeNames: interfaceNamesSchema.nullable(),
}).partial();

const TEMPLATE_RULE_COLUMNS: Record<string, { column: string; nullable: boolean }> = {
  orderIndex: { column: 'order_index', nullable: false },
  direction: { column: 'direction', nullable: false },
  action: { column: 'action', nullable: false },
  protocol: { column: 'protocol', nullable: false },
  ports: { column: 'ports', nullable: true },
  sourceType: { column: 'source_type', nullable: false },
  sourceValue: { column: 'source_value', nullable: false },
  destinationType: { column: 'destination_type', nullable: true },
  destinationValue: { column: 'destination_value', nullable: true },
  logMode: { column: 'log_mode', nullable: false },
  comment: { column: 'comment', nullable: true },
  usePolicyInterfaceScope: { column: 'use_policy_interface_scope', nullable: false },
  interfaceScopeType: { column: 'interface_scope_type', nullable: true },
  interfaceScopeRoles: { column: 'interface_scope_roles', nullable: true },
  interfaceScopeNames: { column: 'interface_scope_names', nullable: true },
};

/** Validate stored template rules (DB rows) before they are instantiated into a policy. */
function validateStoredTemplateRules(rules: any[]): string[] {
  const problems: string[] = [];
  for (const r of rules) {
    const label = `Rule #${r.order_index}`;
    if (!protocolSchema.safeParse(r.protocol).success) problems.push(`${label}: invalid protocol '${r.protocol}'`);
    if (!sourceTypeSchema.safeParse(r.source_type).success) problems.push(`${label}: invalid source type '${r.source_type}'`);
    if (!directionSchema.safeParse(r.direction ?? 'IN').success) problems.push(`${label}: invalid direction '${r.direction}'`);
    if (r.interface_scope_type != null && !interfaceScopeTypeSchema.safeParse(r.interface_scope_type).success) {
      problems.push(`${label}: invalid interface scope type '${r.interface_scope_type}'`);
    }
    if (r.interface_scope_names != null && !interfaceNamesSchema.safeParse(r.interface_scope_names).success) {
      problems.push(`${label}: invalid interface name(s)`);
    }
    if (r.interface_scope_roles != null && !interfaceRolesSchema.safeParse(r.interface_scope_roles).success) {
      problems.push(`${label}: invalid interface role(s)`);
    }
    if (r.comment != null && r.comment !== '' && !ruleCommentSchema.safeParse(r.comment).success) {
      problems.push(`${label}: invalid comment`);
    }
    for (const p of validateRuleSemantics({
      protocol: r.protocol,
      ports: r.ports,
      sourceType: r.source_type,
      sourceValue: r.source_value,
      direction: r.direction ?? 'IN',
      destinationType: r.destination_type ?? null,
      destinationValue: r.destination_value ?? null
    })) {
      problems.push(`${label}: ${p}`);
    }
  }
  return problems;
}

templatesRouter.get('/:id/rules', requireRole('viewer', 'operator', 'approver', 'admin'), async (req, res) => {
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
  const problems = validateRuleSemantics({
    protocol: b.protocol,
    ports: b.ports ?? null,
    sourceType: b.sourceType,
    sourceValue: b.sourceValue,
    direction: b.direction,
    destinationType: b.destinationType ?? null,
    destinationValue: b.destinationValue ?? null
  });
  if (problems.length) return res.status(400).json({ error: 'invalid_rule', message: problems.join('; '), details: problems });
  const isForward = b.direction === 'FORWARD';

  const { rows } = await pool.query(
    `INSERT INTO policy_template_rules
      (policy_template_id, order_index, direction, action, protocol, ports, source_type, source_value,
       log_mode, comment, use_policy_interface_scope, interface_scope_type, interface_scope_roles, interface_scope_names,
       destination_type, destination_value)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16) RETURNING *`,
    [req.params.id, b.orderIndex, b.direction, b.action, b.protocol, b.ports || null,
     b.sourceType, b.sourceValue, b.logMode, b.comment ?? null,
     b.usePolicyInterfaceScope, b.interfaceScopeType ?? null,
     b.interfaceScopeRoles ?? null, b.interfaceScopeNames ?? null,
     isForward ? b.destinationType : null, isForward ? b.destinationValue : null]
  );
  res.status(201).json({ rule: rows[0] });
});

templatesRouter.put('/rules/:ruleId', requireRole('operator', 'admin'), async (req, res) => {
  const parsed = templateRuleUpdateSchema.safeParse(req.body ?? {});
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body', details: parsed.error.issues });
  const b = parsed.data as Record<string, unknown>;

  const presentKeys = Object.keys(TEMPLATE_RULE_COLUMNS).filter((k) => b[k] !== undefined);
  for (const k of presentKeys) {
    if (b[k] === null && !TEMPLATE_RULE_COLUMNS[k].nullable) {
      return res.status(400).json({ error: 'invalid_body', message: `${k} cannot be null` });
    }
  }

  const existing = await pool.query(`SELECT * FROM policy_template_rules WHERE id = $1`, [req.params.ruleId]);
  const cur = existing.rows[0];
  if (!cur) return res.status(404).json({ error: 'not_found' });

  const problems = validateRuleSemantics({
    protocol: (presentKeys.includes('protocol') ? b.protocol : cur.protocol) as string,
    ports: (presentKeys.includes('ports') ? b.ports : cur.ports) as string | null,
    sourceType: (presentKeys.includes('sourceType') ? b.sourceType : cur.source_type) as string,
    sourceValue: (presentKeys.includes('sourceValue') ? b.sourceValue : cur.source_value) as string,
    direction: (presentKeys.includes('direction') ? b.direction : cur.direction ?? 'IN') as string,
    destinationType: (presentKeys.includes('destinationType') ? b.destinationType : cur.destination_type) as string | null,
    destinationValue: (presentKeys.includes('destinationValue') ? b.destinationValue : cur.destination_value) as string | null
  });
  if (problems.length) return res.status(400).json({ error: 'invalid_rule', message: problems.join('; '), details: problems });

  if (presentKeys.length === 0) return res.json({ rule: cur });

  const sets: string[] = [];
  const params: unknown[] = [req.params.ruleId];
  for (const k of presentKeys) {
    let value = b[k];
    if (k === 'ports' && value === '') value = null;
    params.push(value);
    sets.push(`${TEMPLATE_RULE_COLUMNS[k].column} = $${params.length}`);
  }
  const { rows } = await pool.query(
    `UPDATE policy_template_rules SET ${sets.join(', ')} WHERE id = $1 RETURNING *`,
    params
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
    scopeType: z.enum(['TAG', 'VLAN', 'HOST_LIST']).optional(),
    scopeTagId: z.string().uuid().optional(),
    scopeVlanId: z.string().uuid().optional(),
    hostIds: z.array(z.string().uuid()).optional(),
  });
  const parsed = bodySchema.safeParse(req.body ?? {});
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });

  const userId = req.auth!.userId;

  // Validate the template's rules before turning them into a policy (template-engine copies them verbatim)
  const tpl = await pool.query(`SELECT id FROM policy_templates WHERE id = $1`, [req.params.id]);
  if (!tpl.rows[0]) return res.status(404).json({ error: 'not_found' });
  const { rows: tplRules } = await pool.query(
    `SELECT * FROM policy_template_rules WHERE policy_template_id = $1 ORDER BY order_index ASC`,
    [req.params.id]
  );
  const problems = validateStoredTemplateRules(tplRules);
  if (problems.length) {
    return res.status(400).json({ error: 'invalid_template_rules', message: `Template contains invalid rules: ${problems.join('; ')}`, details: problems });
  }

  try {
    const result = await instantiateTemplate(req.params.id, userId, parsed.data);
    res.status(201).json(result);
  } catch (e: any) {
    res.status(400).json({ error: e.message });
  }
});

// Preview instantiation
templatesRouter.post('/:id/preview', requireRole('viewer', 'operator', 'approver', 'admin'), async (req, res) => {
  try {
    const result = await previewInstantiation(req.params.id);
    res.json(result);
  } catch (e: any) {
    res.status(400).json({ error: e.message });
  }
});
