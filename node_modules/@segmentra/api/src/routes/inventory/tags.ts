import { Router } from 'express';
import { z } from 'zod';

import { pool } from '../../db/pool.js';
import { requireAuth, requireRole } from '../../middleware/auth.js';

export const tagsRouter = Router();
tagsRouter.use(requireAuth, requireRole('operator', 'admin'));

tagsRouter.get('/', async (_req, res) => {
  const { rows } = await pool.query(`SELECT * FROM tags ORDER BY name ASC`);
  res.json({ tags: rows });
});

const tagSchema = z.object({
  name: z.string().min(1),
  description: z.string().optional()
});

tagsRouter.post('/', async (req, res) => {
  const parsed = tagSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });
  const { rows } = await pool.query(
    `INSERT INTO tags (name, description) VALUES ($1, $2) RETURNING *`,
    [parsed.data.name, parsed.data.description ?? null]
  );
  res.status(201).json({ tag: rows[0] });
});

tagsRouter.put('/:id', async (req, res) => {
  const parsed = tagSchema.partial().safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });
  const { rows } = await pool.query(
    `UPDATE tags
     SET name = COALESCE($2, name),
         description = COALESCE($3, description)
     WHERE id=$1
     RETURNING *`,
    [req.params.id, parsed.data.name ?? null, parsed.data.description ?? null]
  );
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });
  res.json({ tag: rows[0] });
});

tagsRouter.delete('/:id', async (req, res) => {
  const { rowCount } = await pool.query(`DELETE FROM tags WHERE id=$1`, [req.params.id]);
  if (!rowCount) return res.status(404).json({ error: 'not_found' });
  res.json({ ok: true });
});


