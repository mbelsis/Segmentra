import { Router } from 'express';
import { z } from 'zod';
import { pool } from '../../db/pool.js';
import { requireAuth, requireRole } from '../../middleware/auth.js';
export const vlansRouter = Router();
vlansRouter.use(requireAuth);
// GET endpoints are read-only and accessible to viewers
vlansRouter.get('/', requireRole('viewer', 'operator', 'admin'), async (_req, res) => {
    const { rows } = await pool.query(`SELECT * FROM vlans ORDER BY vlan_tag ASC`);
    res.json({ vlans: rows });
});
const vlanSchema = z.object({
    vlanTag: z.number().int().min(1).max(4094),
    name: z.string().min(1),
    description: z.string().optional(),
    subnet: z.string().optional()
});
// Write operations require operator/admin
vlansRouter.post('/', requireRole('operator', 'admin'), async (req, res) => {
    const parsed = vlanSchema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: 'invalid_body' });
    const { rows } = await pool.query(`INSERT INTO vlans (vlan_tag, name, description, subnet) VALUES ($1, $2, $3, $4) RETURNING *`, [parsed.data.vlanTag, parsed.data.name, parsed.data.description ?? null, parsed.data.subnet ?? null]);
    await pool.query(`INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), $2, $3, $4, $5)`, [req.auth.username, 'VLAN_CREATE', 'vlan', rows[0].id, JSON.stringify({ name: parsed.data.name, vlanTag: parsed.data.vlanTag })]);
    res.status(201).json({ vlan: rows[0] });
});
vlansRouter.put('/:id', requireRole('operator', 'admin'), async (req, res) => {
    const parsed = vlanSchema.partial().safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: 'invalid_body' });
    const { rows } = await pool.query(`UPDATE vlans
     SET vlan_tag = COALESCE($2, vlan_tag),
         name = COALESCE($3, name),
         description = COALESCE($4, description),
         subnet = COALESCE($5, subnet)
     WHERE id=$1
     RETURNING *`, [
        req.params.id,
        parsed.data.vlanTag ?? null,
        parsed.data.name ?? null,
        parsed.data.description ?? null,
        parsed.data.subnet ?? null
    ]);
    if (!rows[0])
        return res.status(404).json({ error: 'not_found' });
    await pool.query(`INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), $2, $3, $4, $5)`, [req.auth.username, 'VLAN_UPDATE', 'vlan', req.params.id, JSON.stringify({ vlanId: req.params.id, changes: parsed.data })]);
    res.json({ vlan: rows[0] });
});
vlansRouter.delete('/:id', requireRole('operator', 'admin'), async (req, res) => {
    const { rowCount } = await pool.query(`DELETE FROM vlans WHERE id=$1`, [req.params.id]);
    if (!rowCount)
        return res.status(404).json({ error: 'not_found' });
    await pool.query(`INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), $2, $3, $4, $5)`, [req.auth.username, 'VLAN_DELETE', 'vlan', req.params.id, JSON.stringify({ vlanId: req.params.id })]);
    res.json({ ok: true });
});
