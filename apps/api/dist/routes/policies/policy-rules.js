import { Router } from 'express';
import { z } from 'zod';
import { pool } from '../../db/pool.js';
import { requireAuth, requireRole } from '../../middleware/auth.js';
export const policyRulesRouter = Router();
policyRulesRouter.use(requireAuth);
// GET endpoints are read-only and accessible to viewers
policyRulesRouter.get('/policy-versions/:versionId/rules', requireRole('viewer', 'operator', 'admin'), async (req, res) => {
    const { rows } = await pool.query(`SELECT * FROM policy_rules WHERE policy_version_id=$1 ORDER BY order_index ASC`, [req.params.versionId]);
    res.json({ rules: rows });
});
const ruleSchema = z.object({
    orderIndex: z.number().int().min(0),
    direction: z.enum(['IN', 'OUT', 'BOTH']).default('IN'),
    action: z.enum(['ALLOW', 'DENY']),
    protocol: z.enum(['tcp', 'udp', 'icmp', 'any']),
    ports: z.string().optional().nullable(),
    sourceType: z.enum(['CIDR', 'TAG', 'VLAN', 'HOST']),
    sourceValue: z.string().min(1),
    logMode: z.enum(['NONE', 'LOG', 'LOG_RATE_LIMITED']).default('NONE'),
    comment: z.string().optional().nullable(),
    usePolicyInterfaceScope: z.boolean().default(true),
    interfaceScopeType: z.enum(['ALL_INTERFACES', 'INTERFACE_ROLE', 'INTERFACE_NAME']).optional().nullable(),
    interfaceScopeRoles: z.array(z.string()).optional().nullable(),
    interfaceScopeNames: z.array(z.string()).optional().nullable()
});
// Write operations require operator/admin
policyRulesRouter.post('/policy-versions/:versionId/rules', requireRole('operator', 'admin'), async (req, res) => {
    // Check if version is editable (DRAFT or REJECTED status can be edited)
    const versionRes = await pool.query(`SELECT status FROM policy_versions WHERE id=$1`, [req.params.versionId]);
    if (!versionRes.rows[0])
        return res.status(404).json({ error: 'version_not_found' });
    if (versionRes.rows[0].status !== 'DRAFT' && versionRes.rows[0].status !== 'REJECTED') {
        return res.status(400).json({ error: 'version_not_editable', message: 'Only DRAFT or REJECTED versions can be edited' });
    }
    const parsed = ruleSchema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: 'invalid_body' });
    const b = parsed.data;
    const { rows } = await pool.query(`INSERT INTO policy_rules
      (policy_version_id, order_index, direction, action, protocol, ports, source_type, source_value, log_mode, comment,
       use_policy_interface_scope, interface_scope_type, interface_scope_roles, interface_scope_names)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
     RETURNING *`, [
        req.params.versionId,
        b.orderIndex,
        b.direction,
        b.action,
        b.protocol,
        b.ports ?? null,
        b.sourceType,
        b.sourceValue,
        b.logMode,
        b.comment ?? null,
        b.usePolicyInterfaceScope,
        b.interfaceScopeType ?? null,
        b.interfaceScopeRoles ?? null,
        b.interfaceScopeNames ?? null
    ]);
    await pool.query(`INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), $2, $3, $4, $5)`, [req.auth.username, 'POLICY_RULE_CREATE', 'policy_rule', rows[0].id, JSON.stringify({ versionId: req.params.versionId, direction: b.direction, action: b.action, protocol: b.protocol, ports: b.ports ?? null, sourceType: b.sourceType })]);
    res.status(201).json({ rule: rows[0] });
});
policyRulesRouter.put('/policy-rules/:ruleId', requireRole('operator', 'admin'), async (req, res) => {
    // Check if version is editable (DRAFT or REJECTED status can be edited)
    const versionRes = await pool.query(`SELECT pv.status FROM policy_versions pv
     JOIN policy_rules pr ON pr.policy_version_id = pv.id
     WHERE pr.id=$1`, [req.params.ruleId]);
    if (!versionRes.rows[0])
        return res.status(404).json({ error: 'rule_not_found' });
    if (versionRes.rows[0].status !== 'DRAFT' && versionRes.rows[0].status !== 'REJECTED') {
        return res.status(400).json({ error: 'version_not_editable', message: 'Only DRAFT or REJECTED versions can be edited' });
    }
    const parsed = ruleSchema.partial().safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: 'invalid_body' });
    const b = parsed.data;
    const { rows } = await pool.query(`UPDATE policy_rules
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
     WHERE id=$1
     RETURNING *`, [
        req.params.ruleId,
        b.orderIndex ?? null,
        b.direction ?? null,
        b.action ?? null,
        b.protocol ?? null,
        b.ports ?? null,
        b.sourceType ?? null,
        b.sourceValue ?? null,
        b.logMode ?? null,
        b.comment ?? null,
        typeof b.usePolicyInterfaceScope === 'boolean' ? b.usePolicyInterfaceScope : null,
        b.interfaceScopeType ?? null,
        b.interfaceScopeRoles ?? null,
        b.interfaceScopeNames ?? null
    ]);
    if (!rows[0])
        return res.status(404).json({ error: 'not_found' });
    await pool.query(`INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), $2, $3, $4, $5)`, [req.auth.username, 'POLICY_RULE_UPDATE', 'policy_rule', req.params.ruleId, JSON.stringify({ ruleId: req.params.ruleId })]);
    res.json({ rule: rows[0] });
});
policyRulesRouter.delete('/policy-rules/:ruleId', requireRole('operator', 'admin'), async (req, res) => {
    // Check if version is editable (DRAFT or REJECTED status can be edited)
    const versionRes = await pool.query(`SELECT pv.status FROM policy_versions pv
     JOIN policy_rules pr ON pr.policy_version_id = pv.id
     WHERE pr.id=$1`, [req.params.ruleId]);
    if (!versionRes.rows[0])
        return res.status(404).json({ error: 'rule_not_found' });
    if (versionRes.rows[0].status !== 'DRAFT' && versionRes.rows[0].status !== 'REJECTED') {
        return res.status(400).json({ error: 'version_not_editable', message: 'Only DRAFT or REJECTED versions can be edited' });
    }
    const { rowCount } = await pool.query(`DELETE FROM policy_rules WHERE id=$1`, [req.params.ruleId]);
    if (!rowCount)
        return res.status(404).json({ error: 'not_found' });
    await pool.query(`INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), $2, $3, $4, $5)`, [req.auth.username, 'POLICY_RULE_DELETE', 'policy_rule', req.params.ruleId, JSON.stringify({ ruleId: req.params.ruleId })]);
    res.json({ ok: true });
});
