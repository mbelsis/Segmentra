import { Router } from 'express';
import { z } from 'zod';
import { pool } from '../db/pool.js';
import { requireAuth, requireRole } from '../middleware/auth.js';
export const enforcementPointsRouter = Router();
enforcementPointsRouter.use(requireAuth);
// List enforcement points
enforcementPointsRouter.get('/', requireRole('viewer', 'operator', 'admin'), async (_req, res) => {
    const { rows } = await pool.query(`SELECT ep.*,
       (SELECT COUNT(*)::int FROM enforcement_acls ea WHERE ea.enforcement_point_id = ep.id) as acl_count
     FROM enforcement_points ep ORDER BY ep.name ASC`);
    res.json({ enforcementPoints: rows });
});
// Get single enforcement point
enforcementPointsRouter.get('/:id', requireRole('viewer', 'operator', 'admin'), async (req, res) => {
    const { rows } = await pool.query(`SELECT * FROM enforcement_points WHERE id = $1`, [req.params.id]);
    if (!rows[0])
        return res.status(404).json({ error: 'not_found' });
    const { rows: acls } = await pool.query(`SELECT ea.*, pv.version_number, ps.name as policy_set_name
     FROM enforcement_acls ea
     LEFT JOIN policy_versions pv ON pv.id = ea.policy_version_id
     LEFT JOIN policy_sets ps ON ps.id = pv.policy_set_id
     WHERE ea.enforcement_point_id = $1 ORDER BY ea.created_at DESC`, [req.params.id]);
    res.json({ enforcementPoint: rows[0], acls });
});
const enforcementPointSchema = z.object({
    name: z.string().min(1),
    description: z.string().optional(),
    type: z.enum(['switch_acl', 'gateway_firewall']).default('gateway_firewall'),
    vendor: z.string().optional(),
    model: z.string().optional(),
    mgmtIp: z.string().min(1),
    sshCredentialId: z.string().uuid().optional().nullable(),
    enabled: z.boolean().default(true),
});
// Create enforcement point
enforcementPointsRouter.post('/', requireRole('admin'), async (req, res) => {
    const parsed = enforcementPointSchema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: 'invalid_body', details: parsed.error.issues });
    const b = parsed.data;
    const userRes = await pool.query(`SELECT id FROM users WHERE username=$1 LIMIT 1`, [req.auth.username]);
    const userId = userRes.rows[0]?.id ?? null;
    const { rows } = await pool.query(`INSERT INTO enforcement_points (name, description, type, vendor, model, mgmt_ip, ssh_credential_id, enabled, created_by)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`, [b.name, b.description ?? null, b.type, b.vendor ?? null, b.model ?? null,
        b.mgmtIp, b.sshCredentialId ?? null, b.enabled, userId]);
    await pool.query(`INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ($1, 'ENFORCEMENT_POINT_CREATE', 'enforcement_point', $2, $3)`, [userId, rows[0].id, JSON.stringify({ name: b.name, type: b.type, mgmtIp: b.mgmtIp })]);
    res.status(201).json({ enforcementPoint: rows[0] });
});
// Update enforcement point
enforcementPointsRouter.put('/:id', requireRole('admin'), async (req, res) => {
    const parsed = enforcementPointSchema.partial().safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: 'invalid_body' });
    const b = parsed.data;
    const { rows } = await pool.query(`UPDATE enforcement_points
     SET name = COALESCE($2, name),
         description = COALESCE($3, description),
         type = COALESCE($4, type),
         vendor = COALESCE($5, vendor),
         model = COALESCE($6, model),
         mgmt_ip = COALESCE($7, mgmt_ip),
         ssh_credential_id = COALESCE($8, ssh_credential_id),
         enabled = COALESCE($9, enabled)
     WHERE id = $1 RETURNING *`, [req.params.id, b.name ?? null, b.description ?? null, b.type ?? null,
        b.vendor ?? null, b.model ?? null, b.mgmtIp ?? null,
        b.sshCredentialId ?? null, b.enabled ?? null]);
    if (!rows[0])
        return res.status(404).json({ error: 'not_found' });
    await pool.query(`INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), $2, $3, $4, $5)`, [req.auth.username, 'ENFORCEMENT_POINT_UPDATE', 'enforcement_point', req.params.id, JSON.stringify({ name: rows[0].name })]);
    res.json({ enforcementPoint: rows[0] });
});
// Delete enforcement point
enforcementPointsRouter.delete('/:id', requireRole('admin'), async (req, res) => {
    const { rowCount } = await pool.query(`DELETE FROM enforcement_points WHERE id = $1`, [req.params.id]);
    if (!rowCount)
        return res.status(404).json({ error: 'not_found' });
    await pool.query(`INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), $2, $3, $4, $5)`, [req.auth.username, 'ENFORCEMENT_POINT_DELETE', 'enforcement_point', req.params.id, JSON.stringify({ pointId: req.params.id })]);
    res.json({ ok: true });
});
// Deploy ACL to enforcement point
enforcementPointsRouter.post('/:id/deploy-acl', requireRole('operator', 'admin'), async (req, res) => {
    const bodySchema = z.object({
        policyVersionId: z.string().uuid(),
        aclName: z.string().min(1),
        aclConfig: z.string().min(1),
    });
    const parsed = bodySchema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: 'invalid_body' });
    const b = parsed.data;
    const { rows: ep } = await pool.query(`SELECT * FROM enforcement_points WHERE id = $1`, [req.params.id]);
    if (!ep[0])
        return res.status(404).json({ error: 'not_found' });
    const crypto = await import('node:crypto');
    const hash = crypto.createHash('sha256').update(b.aclConfig).digest('hex');
    const { rows } = await pool.query(`INSERT INTO enforcement_acls (enforcement_point_id, policy_version_id, acl_name, acl_config, status, deployed_hash, deployed_at)
     VALUES ($1, $2, $3, $4, 'DEPLOYED', $5, now()) RETURNING *`, [req.params.id, b.policyVersionId, b.aclName, b.aclConfig, hash]);
    const userRes = await pool.query(`SELECT id FROM users WHERE username=$1 LIMIT 1`, [req.auth.username]);
    const userId = userRes.rows[0]?.id ?? null;
    await pool.query(`INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ($1, 'ACL_DEPLOY', 'enforcement_acl', $2, $3)`, [userId, rows[0].id, JSON.stringify({ enforcementPointId: req.params.id, aclName: b.aclName })]);
    res.status(201).json({ acl: rows[0] });
});
// List ACLs for enforcement point
enforcementPointsRouter.get('/:id/acls', requireRole('viewer', 'operator', 'admin'), async (req, res) => {
    const { rows } = await pool.query(`SELECT ea.*, pv.version_number, ps.name as policy_set_name
     FROM enforcement_acls ea
     LEFT JOIN policy_versions pv ON pv.id = ea.policy_version_id
     LEFT JOIN policy_sets ps ON ps.id = pv.policy_set_id
     WHERE ea.enforcement_point_id = $1 ORDER BY ea.created_at DESC`, [req.params.id]);
    res.json({ acls: rows });
});
