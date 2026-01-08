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
  const enabled = req.query.enabled !== undefined ? req.query.enabled === 'true' || req.query.enabled === '1' : undefined;
  const page = Math.max(1, parseInt(String(req.query.page ?? '1'), 10));
  const limit = Math.min(100, Math.max(1, parseInt(String(req.query.limit ?? '50'), 10)));
  const offset = (page - 1) * limit;

  const where: string[] = [];
  const params: any[] = [];

  if (hostname) {
    params.push(`%${hostname}%`);
    where.push(`h.hostname ILIKE $${params.length}`);
  }
  if (ip) {
    params.push(`%${ip}%`);
    where.push(`(h.mgmt_ip::text ILIKE $${params.length} OR h.hostname ILIKE $${params.length})`);
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
  if (enabled !== undefined) {
    params.push(enabled);
    where.push(`h.enabled = $${params.length}`);
  }

  const whereClause = where.length > 0 ? `WHERE ${where.join(' AND ')}` : '';

  // Get total count
  const countSql = `
    SELECT COUNT(DISTINCT h.id) as total
    FROM hosts h
    LEFT JOIN vlans v ON v.id = h.vlan_id
    LEFT JOIN host_tags ht ON ht.host_id = h.id
    LEFT JOIN tags t ON t.id = ht.tag_id
    ${whereClause}
  `;
  const countResult = await pool.query(countSql, params);
  const total = parseInt(countResult.rows[0].total, 10);

  // Get paginated hosts
  const sql = `
    SELECT DISTINCT h.*, v.vlan_tag, v.name as vlan_name
    FROM hosts h
    LEFT JOIN vlans v ON v.id = h.vlan_id
    LEFT JOIN host_tags ht ON ht.host_id = h.id
    LEFT JOIN tags t ON t.id = ht.tag_id
    ${whereClause}
    ORDER BY h.hostname ASC
    LIMIT $${params.length + 1} OFFSET $${params.length + 2}
  `;

  const { rows } = await pool.query(sql, [...params, limit, offset]);
  
  // Group hosts and collect their tags
  const hostMap = new Map();
  for (const row of rows) {
    if (!hostMap.has(row.id)) {
      hostMap.set(row.id, {
        ...row,
        tags: []
      });
    }
  }
  
  // Get tags for all hosts
  const hostIds = Array.from(hostMap.keys());
  if (hostIds.length > 0) {
    const tagRows = await pool.query(
      `SELECT ht.host_id, t.id, t.name
       FROM host_tags ht
       JOIN tags t ON t.id = ht.tag_id
       WHERE ht.host_id = ANY($1::uuid[])`,
      [hostIds]
    );
    for (const tagRow of tagRows.rows) {
      const host = hostMap.get(tagRow.host_id);
      if (host) {
        host.tags.push({ id: tagRow.id, name: tagRow.name });
      }
    }
  }
  
  res.json({ 
    hosts: Array.from(hostMap.values()),
    pagination: {
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit)
    }
  });
});

const createHostSchema = z.object({
  hostname: z.string().min(1),
  mgmtIp: z.string().optional(),
  sshPort: z.number().int().min(1).max(65535).optional(),
  environment: z.string().optional(),
  osFamily: z.string().optional(),
  firewallBackend: z.enum(['nftables', 'iptables', 'auto']).optional(),
  vlanId: z.string().uuid().nullable().optional(),
  tagIds: z.array(z.string().uuid()).optional().default([]),
  enabled: z.boolean().optional()
});

hostsRouter.post('/', async (req, res) => {
  const parsed = createHostSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });
  const b = parsed.data;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    
    const { rows } = await client.query(
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
    const host = rows[0];
    
    // Add tags
    if (b.tagIds && b.tagIds.length > 0) {
      for (const tagId of b.tagIds) {
        await client.query(
          `INSERT INTO host_tags (host_id, tag_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
          [host.id, tagId]
        );
      }
    }
    
    await client.query('COMMIT');
    
    // Fetch host with tags and VLAN
    const hostWithTags = await client.query(
      `SELECT h.*, v.vlan_tag, v.name as vlan_name
       FROM hosts h
       LEFT JOIN vlans v ON v.id = h.vlan_id
       WHERE h.id = $1`,
      [host.id]
    );
    const tagRows = await client.query(
      `SELECT t.id, t.name FROM host_tags ht JOIN tags t ON t.id = ht.tag_id WHERE ht.host_id = $1`,
      [host.id]
    );
    
    res.status(201).json({ 
      host: {
        ...hostWithTags.rows[0],
        tags: tagRows.rows
      }
    });
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
});

hostsRouter.get('/:id', async (req, res) => {
  const { rows } = await pool.query(
    `SELECT h.*, v.vlan_tag, v.name as vlan_name
     FROM hosts h
     LEFT JOIN vlans v ON v.id = h.vlan_id
     WHERE h.id=$1`,
    [req.params.id]
  );
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });
  
  const tagRows = await pool.query(
    `SELECT t.id, t.name FROM host_tags ht JOIN tags t ON t.id = ht.tag_id WHERE ht.host_id = $1`,
    [req.params.id]
  );
  
  res.json({ 
    host: {
      ...rows[0],
      tags: tagRows.rows
    }
  });
});

const updateHostSchema = createHostSchema.partial();

hostsRouter.put('/:id', async (req, res) => {
  const parsed = updateHostSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });
  const b = parsed.data;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    
    const { rows } = await client.query(
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
    if (!rows[0]) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'not_found' });
    }
    
    // Update tags if provided
    if (b.tagIds !== undefined) {
      // Remove all existing tags
      await client.query(`DELETE FROM host_tags WHERE host_id = $1`, [req.params.id]);
      // Add new tags
      if (b.tagIds.length > 0) {
        for (const tagId of b.tagIds) {
          await client.query(
            `INSERT INTO host_tags (host_id, tag_id) VALUES ($1, $2)`,
            [req.params.id, tagId]
          );
        }
      }
    }
    
    await client.query('COMMIT');
    
    // Fetch updated host with tags and VLAN
    const hostWithTags = await client.query(
      `SELECT h.*, v.vlan_tag, v.name as vlan_name
       FROM hosts h
       LEFT JOIN vlans v ON v.id = h.vlan_id
       WHERE h.id = $1`,
      [req.params.id]
    );
    const tagRows = await client.query(
      `SELECT t.id, t.name FROM host_tags ht JOIN tags t ON t.id = ht.tag_id WHERE ht.host_id = $1`,
      [req.params.id]
    );
    
    res.json({ 
      host: {
        ...hostWithTags.rows[0],
        tags: tagRows.rows
      }
    });
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
});

hostsRouter.delete('/:id', async (req, res) => {
  const { rowCount } = await pool.query(`DELETE FROM hosts WHERE id=$1`, [
    req.params.id
  ]);
  if (!rowCount) return res.status(404).json({ error: 'not_found' });
  res.json({ ok: true });
});

// Bulk operations
const bulkOperationSchema = z.object({
  hostIds: z.array(z.string().uuid()).min(1)
});

hostsRouter.post('/bulk/delete', async (req, res) => {
  const parsed = bulkOperationSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });
  
  const { rowCount } = await pool.query(
    `DELETE FROM hosts WHERE id = ANY($1::uuid[])`,
    [parsed.data.hostIds]
  );
  res.json({ ok: true, deleted: rowCount });
});

hostsRouter.post('/bulk/assign-vlan', async (req, res) => {
  const parsed = bulkOperationSchema.extend({
    vlanId: z.string().uuid().nullable()
  }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });
  
  const { rowCount } = await pool.query(
    `UPDATE hosts SET vlan_id = $1, updated_at = now() WHERE id = ANY($2::uuid[])`,
    [parsed.data.vlanId, parsed.data.hostIds]
  );
  res.json({ ok: true, updated: rowCount });
});

hostsRouter.post('/bulk/assign-tag', async (req, res) => {
  const parsed = bulkOperationSchema.extend({
    tagId: z.string().uuid()
  }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });
  
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    let added = 0;
    for (const hostId of parsed.data.hostIds) {
      const result = await client.query(
        `INSERT INTO host_tags (host_id, tag_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
        [hostId, parsed.data.tagId]
      );
      if (result.rowCount) added++;
    }
    await client.query('COMMIT');
    res.json({ ok: true, added });
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
});

hostsRouter.post('/bulk/set-enabled', async (req, res) => {
  const parsed = bulkOperationSchema.extend({
    enabled: z.boolean()
  }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });
  
  const { rowCount } = await pool.query(
    `UPDATE hosts SET enabled = $1, updated_at = now() WHERE id = ANY($2::uuid[])`,
    [parsed.data.enabled, parsed.data.hostIds]
  );
  res.json({ ok: true, updated: rowCount });
});


