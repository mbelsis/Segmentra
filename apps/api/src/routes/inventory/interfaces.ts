import { Router } from 'express';
import { z } from 'zod';

import { pool } from '../../db/pool.js';
import { requireAuth, requireRole } from '../../middleware/auth.js';

export const interfacesRouter = Router();
interfacesRouter.use(requireAuth);

interfacesRouter.get('/hosts/:id/interfaces', requireRole('viewer', 'operator', 'approver', 'admin'), async (req, res) => {
  const { rows } = await pool.query(`SELECT * FROM host_interfaces WHERE host_id=$1 ORDER BY name ASC`, [
    req.params.id
  ]);
  res.json({ interfaces: rows });
});

const interfaceSchema = z.object({
  name: z.string().min(1),
  role: z.string().min(1),
  ipAddress: z.string().optional().nullable(),
  cidr: z.number().int().min(0).max(128).optional().nullable(),
  vlanId: z.string().uuid().optional().nullable(),
  isPrimary: z.boolean().optional(),
  enabled: z.boolean().optional()
});

interfacesRouter.post('/hosts/:id/interfaces', requireRole('operator', 'admin'), async (req, res) => {
  const parsed = interfaceSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });
  const b = parsed.data;
  const { rows } = await pool.query(
    `INSERT INTO host_interfaces (host_id, name, role, ip_address, cidr, vlan_id, is_primary, enabled)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
     RETURNING *`,
    [
      req.params.id,
      b.name,
      b.role,
      b.ipAddress ?? null,
      b.cidr ?? null,
      b.vlanId ?? null,
      b.isPrimary ?? false,
      b.enabled ?? true
    ]
  );
  res.status(201).json({ interface: rows[0] });
});

interfacesRouter.put('/interfaces/:interfaceId', requireRole('operator', 'admin'), async (req, res) => {
  const parsed = interfaceSchema.partial().safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });
  const b = parsed.data;
  const { rows } = await pool.query(
    `UPDATE host_interfaces
     SET name = COALESCE($2, name),
         role = COALESCE($3, role),
         ip_address = COALESCE($4, ip_address),
         cidr = COALESCE($5, cidr),
         vlan_id = COALESCE($6, vlan_id),
         is_primary = COALESCE($7, is_primary),
         enabled = COALESCE($8, enabled)
     WHERE id=$1
     RETURNING *`,
    [
      req.params.interfaceId,
      b.name ?? null,
      b.role ?? null,
      b.ipAddress ?? null,
      b.cidr ?? null,
      b.vlanId ?? null,
      typeof b.isPrimary === 'boolean' ? b.isPrimary : null,
      typeof b.enabled === 'boolean' ? b.enabled : null
    ]
  );
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });
  res.json({ interface: rows[0] });
});

interfacesRouter.delete('/interfaces/:interfaceId', requireRole('operator', 'admin'), async (req, res) => {
  const { rowCount } = await pool.query(`DELETE FROM host_interfaces WHERE id=$1`, [req.params.interfaceId]);
  if (!rowCount) return res.status(404).json({ error: 'not_found' });
  res.json({ ok: true });
});



