import { Router } from 'express';
import { z } from 'zod';
import { pool } from '../../db/pool.js';
import { requireAuth, requireRole } from '../../middleware/auth.js';
export const vlansRouter = Router();
vlansRouter.use(requireAuth, requireRole('operator', 'admin'));
vlansRouter.get('/', async (_req, res) => {
    const { rows } = await pool.query(`SELECT * FROM vlans ORDER BY vlan_tag ASC`);
    res.json({ vlans: rows });
});
const vlanSchema = z.object({
    vlanTag: z.number().int().min(1).max(4094),
    name: z.string().min(1),
    description: z.string().optional()
});
vlansRouter.post('/', async (req, res) => {
    const parsed = vlanSchema.safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: 'invalid_body' });
    const { rows } = await pool.query(`INSERT INTO vlans (vlan_tag, name, description) VALUES ($1, $2, $3) RETURNING *`, [parsed.data.vlanTag, parsed.data.name, parsed.data.description ?? null]);
    res.status(201).json({ vlan: rows[0] });
});
vlansRouter.put('/:id', async (req, res) => {
    const parsed = vlanSchema.partial().safeParse(req.body);
    if (!parsed.success)
        return res.status(400).json({ error: 'invalid_body' });
    const { rows } = await pool.query(`UPDATE vlans
     SET vlan_tag = COALESCE($2, vlan_tag),
         name = COALESCE($3, name),
         description = COALESCE($4, description)
     WHERE id=$1
     RETURNING *`, [
        req.params.id,
        parsed.data.vlanTag ?? null,
        parsed.data.name ?? null,
        parsed.data.description ?? null
    ]);
    if (!rows[0])
        return res.status(404).json({ error: 'not_found' });
    res.json({ vlan: rows[0] });
});
vlansRouter.delete('/:id', async (req, res) => {
    const { rowCount } = await pool.query(`DELETE FROM vlans WHERE id=$1`, [req.params.id]);
    if (!rowCount)
        return res.status(404).json({ error: 'not_found' });
    res.json({ ok: true });
});
