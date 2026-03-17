import { Router } from 'express';
import { z } from 'zod';

import { pool } from '../../db/pool.js';
import { requireAuth, requireRole } from '../../middleware/auth.js';

export const tagsRouter = Router();
tagsRouter.use(requireAuth);

// GET endpoints are read-only and accessible to viewers
tagsRouter.get('/', requireRole('viewer', 'operator', 'admin'), async (_req, res) => {
  const { rows } = await pool.query(`SELECT * FROM tags ORDER BY name ASC`);
  res.json({ tags: rows });
});

const tagSchema = z.object({
  name: z.string().min(1),
  description: z.string().optional()
});

// Write operations require operator/admin
tagsRouter.post('/', requireRole('operator', 'admin'), async (req, res) => {
  const parsed = tagSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });
  const { rows } = await pool.query(
    `INSERT INTO tags (name, description) VALUES ($1, $2) RETURNING *`,
    [parsed.data.name, parsed.data.description ?? null]
  );
  await pool.query(
    `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), $2, $3, $4, $5)`,
    [req.auth!.username, 'TAG_CREATE', 'tag', rows[0].id, JSON.stringify({ name: parsed.data.name })]
  );

  res.status(201).json({ tag: rows[0] });
});

tagsRouter.put('/:id', requireRole('operator', 'admin'), async (req, res) => {
  const parsed = tagSchema.partial().safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });

  // Prevent renaming system tags
  const { rows: existing } = await pool.query(`SELECT is_system, name FROM tags WHERE id=$1`, [req.params.id]);
  if (existing[0]?.is_system && parsed.data.name && parsed.data.name !== existing[0].name) {
    return res.status(400).json({ error: 'cannot_rename_system_tag', message: `The tag "${existing[0].name}" is a system tag and cannot be renamed.` });
  }

  const { rows } = await pool.query(
    `UPDATE tags
     SET name = COALESCE($2, name),
         description = COALESCE($3, description)
     WHERE id=$1
     RETURNING *`,
    [req.params.id, parsed.data.name ?? null, parsed.data.description ?? null]
  );
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });

  await pool.query(
    `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), $2, $3, $4, $5)`,
    [req.auth!.username, 'TAG_UPDATE', 'tag', req.params.id, JSON.stringify({ tagId: req.params.id, changes: parsed.data })]
  );

  res.json({ tag: rows[0] });
});

tagsRouter.delete('/:id', requireRole('operator', 'admin'), async (req, res) => {
  // Prevent deleting system tags
  const { rows: existing } = await pool.query(`SELECT is_system, name FROM tags WHERE id=$1`, [req.params.id]);
  if (existing[0]?.is_system) {
    return res.status(400).json({ error: 'cannot_delete_system_tag', message: `The tag "${existing[0].name}" is a system tag required for platform operation and cannot be deleted.` });
  }

  const { rowCount } = await pool.query(`DELETE FROM tags WHERE id=$1`, [req.params.id]);
  if (!rowCount) return res.status(404).json({ error: 'not_found' });

  await pool.query(
    `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), $2, $3, $4, $5)`,
    [req.auth!.username, 'TAG_DELETE', 'tag', req.params.id, JSON.stringify({ tagId: req.params.id })]
  );

  res.json({ ok: true });
});



