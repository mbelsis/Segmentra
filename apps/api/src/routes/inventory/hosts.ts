import { Router } from 'express';
import { z } from 'zod';

import { pool } from '../../db/pool.js';
import { requireAuth, requireRole } from '../../middleware/auth.js';

export const hostsRouter = Router();

hostsRouter.use(requireAuth, requireRole('operator', 'admin'));

hostsRouter.get('/', async (req, res) => {
  const hostname = String(req.query.hostname ?? '');
  const tag = String(req.query.tag ?? '');
  const vlan = String(req.query.vlan ?? '');
  const ip = String(req.query.ip ?? '');
  const env = String(req.query.env ?? '');
  const backend = String(req.query.backend ?? '');

  const where: string[] = ['h.enabled = true'];
  const params: any[] = [];

  if (hostname) {
    params.push(`%${hostname}%`);
    where.push(`h.hostname ILIKE $${params.length}`);
  }
  if (ip) {
    params.push(ip);
    where.push(`h.mgmt_ip::text = $${params.length}`);
  }
  if (env) {
    params.push(env);
    where.push(`h.environment = $${params.length}`);
  }
  if (backend) {
    params.push(backend);
    where.push(`h.firewall_backend = $${params.length}`);
  }
  if (vlan) {
    params.push(vlan);
    where.push(`v.vlan_tag::text = $${params.length}`);
  }
  if (tag) {
    params.push(tag);
    where.push(`t.name = $${params.length}`);
  }

  const sql = `
    SELECT DISTINCT h.*
    FROM hosts h
    LEFT JOIN vlans v ON v.id = h.vlan_id
    LEFT JOIN host_tags ht ON ht.host_id = h.id
    LEFT JOIN tags t ON t.id = ht.tag_id
    WHERE ${where.join(' AND ')}
    ORDER BY h.hostname ASC
  `;

  const { rows } = await pool.query(sql, params);
  res.json({ hosts: rows });
});

const createHostSchema = z.object({
  hostname: z.string().min(1),
  mgmtIp: z.string().optional(),
  sshPort: z.number().int().min(1).max(65535).optional(),
  environment: z.string().optional(),
  osFamily: z.string().optional(),
  firewallBackend: z.enum(['nftables', 'iptables', 'auto']).optional(),
  vlanId: z.string().uuid().nullable().optional(),
  enabled: z.boolean().optional()
});

hostsRouter.post('/', async (req, res) => {
  const parsed = createHostSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });
  const b = parsed.data;

  const { rows } = await pool.query(
    `INSERT INTO hosts (hostname, mgmt_ip, ssh_port, environment, os_family, firewall_backend, vlan_id, enabled)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
     RETURNING *`,
    [
      b.hostname,
      b.mgmtIp ?? null,
      b.sshPort ?? 22,
      b.environment ?? null,
      b.osFamily ?? null,
      b.firewallBackend ?? 'auto',
      b.vlanId ?? null,
      b.enabled ?? true
    ]
  );
  res.status(201).json({ host: rows[0] });
});

hostsRouter.get('/:id', async (req, res) => {
  const { rows } = await pool.query(`SELECT * FROM hosts WHERE id=$1`, [req.params.id]);
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });
  res.json({ host: rows[0] });
});

const updateHostSchema = createHostSchema.partial();

hostsRouter.put('/:id', async (req, res) => {
  const parsed = updateHostSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });
  const b = parsed.data;

  const { rows } = await pool.query(
    `UPDATE hosts
     SET hostname = COALESCE($2, hostname),
         mgmt_ip = COALESCE($3, mgmt_ip),
         ssh_port = COALESCE($4, ssh_port),
         environment = COALESCE($5, environment),
         os_family = COALESCE($6, os_family),
         firewall_backend = COALESCE($7, firewall_backend),
         vlan_id = COALESCE($8, vlan_id),
         enabled = COALESCE($9, enabled),
         updated_at = now()
     WHERE id=$1
     RETURNING *`,
    [
      req.params.id,
      b.hostname ?? null,
      b.mgmtIp ?? null,
      b.sshPort ?? null,
      b.environment ?? null,
      b.osFamily ?? null,
      b.firewallBackend ?? null,
      b.vlanId ?? null,
      typeof b.enabled === 'boolean' ? b.enabled : null
    ]
  );
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });
  res.json({ host: rows[0] });
});

hostsRouter.delete('/:id', async (req, res) => {
  const { rowCount } = await pool.query(`UPDATE hosts SET enabled=false, updated_at=now() WHERE id=$1`, [
    req.params.id
  ]);
  if (!rowCount) return res.status(404).json({ error: 'not_found' });
  res.json({ ok: true });
});


