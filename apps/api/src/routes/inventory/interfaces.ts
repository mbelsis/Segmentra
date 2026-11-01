import { Router } from 'express';
import { z } from 'zod';

import { pool } from '../../db/pool.js';
import { requireAuth, requireRole } from '../../middleware/auth.js';
import { isValidCidr } from '../../services/ip-utils.js';

export const interfacesRouter = Router();
interfacesRouter.use(requireAuth);

interfacesRouter.get('/hosts/:id/interfaces', requireRole('viewer', 'operator', 'approver', 'admin'), async (req, res) => {
  const { rows } = await pool.query(`SELECT * FROM host_interfaces WHERE host_id=$1 ORDER BY name ASC`, [
    req.params.id
  ]);
  res.json({ interfaces: rows });
});

/**
 * Same pattern as the compiler's IFACE_RE (packages/compiler/src/compile.ts, validateInterfaceName; not
 * exported there): keep in sync. A name the compiler refuses would make every deployment to the host fail.
 */
export const INTERFACE_NAME_REGEX = /^[A-Za-z0-9_.:@-]{1,15}$/;

const interfaceSchema = z.object({
  name: z.string().trim().regex(INTERFACE_NAME_REGEX, { message: 'interface name must be 1-15 characters of A-Z a-z 0-9 _ . : @ -' }),
  role: z.string().min(1),
  ipAddress: z
    .string()
    .trim()
    .refine((v) => v === '' || isValidCidr(v), { message: 'ipAddress must be an IP address' })
    .optional()
    .nullable(),
  cidr: z.number().int().min(0).max(128).optional().nullable(),
  vlanId: z.string().uuid().optional().nullable(),
  isPrimary: z.boolean().optional(),
  enabled: z.boolean().optional()
});

interfacesRouter.post('/hosts/:id/interfaces', requireRole('operator', 'admin'), async (req, res) => {
  const parsed = interfaceSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body', details: parsed.error.issues });
  const b = parsed.data;
  const { rows } = await pool.query(
    `INSERT INTO host_interfaces (host_id, name, role, ip_address, cidr, vlan_id, is_primary, enabled)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
     RETURNING *`,
    [
      req.params.id,
      b.name,
      b.role,
      b.ipAddress || null,
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
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body', details: parsed.error.issues });
  const b = parsed.data;
  // undefined = keep; an explicit null clears ip_address / cidr / vlan_id (COALESCE alone could never clear them).
  const { rows } = await pool.query(
    `UPDATE host_interfaces
     SET name = COALESCE($2, name),
         role = COALESCE($3, role),
         ip_address = CASE WHEN $9::boolean THEN $4::inet ELSE ip_address END,
         cidr = CASE WHEN $10::boolean THEN $5::int ELSE cidr END,
         vlan_id = CASE WHEN $11::boolean THEN $6::uuid ELSE vlan_id END,
         is_primary = COALESCE($7, is_primary),
         enabled = COALESCE($8, enabled)
     WHERE id=$1
     RETURNING *`,
    [
      req.params.interfaceId,
      b.name ?? null,
      b.role ?? null,
      b.ipAddress || null,
      b.cidr ?? null,
      b.vlanId ?? null,
      typeof b.isPrimary === 'boolean' ? b.isPrimary : null,
      typeof b.enabled === 'boolean' ? b.enabled : null,
      b.ipAddress !== undefined,
      b.cidr !== undefined,
      b.vlanId !== undefined
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



