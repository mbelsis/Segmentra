import { Router } from 'express';
import { z } from 'zod';

import { pool } from '../../db/pool.js';
import { requireAuth, requireRole } from '../../middleware/auth.js';

export const policySetsRouter = Router();
policySetsRouter.use(requireAuth, requireRole('operator', 'admin'));

policySetsRouter.get('/', async (_req, res) => {
  const { rows } = await pool.query(`SELECT * FROM policy_sets ORDER BY created_at DESC`);
  res.json({ policySets: rows });
});

const createPolicySetSchema = z.object({
  name: z.string().min(1),
  description: z.string().optional(),
  scopeType: z.enum(['TAG', 'VLAN', 'HOST_LIST']),
  scopeTagId: z.string().uuid().optional().nullable(),
  scopeVlanId: z.string().uuid().optional().nullable(),
  hostIds: z.array(z.string().uuid()).optional()
});

policySetsRouter.post('/', async (req, res) => {
  const parsed = createPolicySetSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });
  const b = parsed.data;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const ps = await client.query(
      `INSERT INTO policy_sets (name, description, scope_type, scope_tag_id, scope_vlan_id, created_by)
       VALUES ($1,$2,$3,$4,$5,(SELECT id FROM users WHERE username=$6 LIMIT 1))
       RETURNING *`,
      [
        b.name,
        b.description ?? null,
        b.scopeType,
        b.scopeTagId ?? null,
        b.scopeVlanId ?? null,
        req.auth!.username
      ]
    );
    const policySet = ps.rows[0];

    if (b.scopeType === 'HOST_LIST' && b.hostIds?.length) {
      for (const hostId of b.hostIds) {
        await client.query(
          `INSERT INTO policy_set_hosts (policy_set_id, host_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`,
          [policySet.id, hostId]
        );
      }
    }

    await client.query('COMMIT');
    res.status(201).json({ policySet });
  } catch (e) {
    await client.query('ROLLBACK');
    // eslint-disable-next-line no-console
    console.error(e);
    res.status(500).json({ error: 'create_failed' });
  } finally {
    client.release();
  }
});

policySetsRouter.get('/:id', async (req, res) => {
  const { rows } = await pool.query(`SELECT * FROM policy_sets WHERE id=$1`, [req.params.id]);
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });
  res.json({ policySet: rows[0] });
});

policySetsRouter.put('/:id', async (req, res) => {
  const parsed = createPolicySetSchema.partial().safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });
  const b = parsed.data;
  const { rows } = await pool.query(
    `UPDATE policy_sets
     SET name = COALESCE($2, name),
         description = COALESCE($3, description),
         scope_type = COALESCE($4, scope_type),
         scope_tag_id = COALESCE($5, scope_tag_id),
         scope_vlan_id = COALESCE($6, scope_vlan_id)
     WHERE id=$1
     RETURNING *`,
    [req.params.id, b.name ?? null, b.description ?? null, b.scopeType ?? null, b.scopeTagId ?? null, b.scopeVlanId ?? null]
  );
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });
  res.json({ policySet: rows[0] });
});

policySetsRouter.delete('/:id', async (req, res) => {
  // soft delete not defined; hard delete for now
  const { rowCount } = await pool.query(`DELETE FROM policy_sets WHERE id=$1`, [req.params.id]);
  if (!rowCount) return res.status(404).json({ error: 'not_found' });
  res.json({ ok: true });
});


