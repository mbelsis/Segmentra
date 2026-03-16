import { Router } from 'express';
import { z } from 'zod';

import { pool } from '../db/pool.js';
import { requireAuth, requireRole } from '../middleware/auth.js';

export const flowCollectorsRouter = Router();
flowCollectorsRouter.use(requireAuth);

// List flow collectors
flowCollectorsRouter.get('/', requireRole('viewer', 'operator', 'admin'), async (_req, res) => {
  const { rows } = await pool.query(
    `SELECT fc.*,
       (SELECT COUNT(*)::int FROM iot_observed_flows iof WHERE iof.collector_id = fc.id) as flow_count
     FROM flow_collectors fc ORDER BY fc.name ASC`
  );
  res.json({ collectors: rows });
});

// Get single collector
flowCollectorsRouter.get('/:id', requireRole('viewer', 'operator', 'admin'), async (req, res) => {
  const { rows } = await pool.query(`SELECT * FROM flow_collectors WHERE id = $1`, [req.params.id]);
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });

  const { rows: recentFlows } = await pool.query(
    `SELECT * FROM iot_observed_flows WHERE collector_id = $1 ORDER BY last_seen_at DESC LIMIT 50`,
    [req.params.id]
  );

  res.json({ collector: rows[0], recentFlows });
});

const collectorSchema = z.object({
  name: z.string().min(1),
  description: z.string().optional(),
  type: z.enum(['netflow_v5', 'netflow_v9', 'sflow', 'ipfix', 'span_analyzer']).default('netflow_v5'),
  listenAddress: z.string().default('0.0.0.0'),
  listenPort: z.number().int().min(1).max(65535).default(2055),
  config: z.record(z.any()).default({}),
  enabled: z.boolean().default(false),
});

// Create collector
flowCollectorsRouter.post('/', requireRole('admin'), async (req, res) => {
  const parsed = collectorSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body', details: parsed.error.issues });
  const b = parsed.data;

  const userRes = await pool.query(`SELECT id FROM users WHERE username=$1 LIMIT 1`, [req.auth!.username]);
  const userId = userRes.rows[0]?.id ?? null;

  const { rows } = await pool.query(
    `INSERT INTO flow_collectors (name, description, type, listen_address, listen_port, config, enabled, created_by)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
    [b.name, b.description ?? null, b.type, b.listenAddress, b.listenPort,
     JSON.stringify(b.config), b.enabled, userId]
  );

  await pool.query(
    `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ($1, 'FLOW_COLLECTOR_CREATE', 'flow_collector', $2, $3)`,
    [userId, rows[0].id, JSON.stringify({ name: b.name, type: b.type })]
  );

  res.status(201).json({ collector: rows[0] });
});

// Update collector
flowCollectorsRouter.put('/:id', requireRole('admin'), async (req, res) => {
  const parsed = collectorSchema.partial().safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });
  const b = parsed.data;

  const { rows } = await pool.query(
    `UPDATE flow_collectors
     SET name = COALESCE($2, name),
         description = COALESCE($3, description),
         type = COALESCE($4, type),
         listen_address = COALESCE($5, listen_address),
         listen_port = COALESCE($6, listen_port),
         config = COALESCE($7, config),
         enabled = COALESCE($8, enabled)
     WHERE id = $1 RETURNING *`,
    [req.params.id, b.name ?? null, b.description ?? null, b.type ?? null,
     b.listenAddress ?? null, b.listenPort ?? null,
     b.config ? JSON.stringify(b.config) : null, b.enabled ?? null]
  );
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });

  await pool.query(
    `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), $2, $3, $4, $5)`,
    [req.auth!.username, 'FLOW_COLLECTOR_UPDATE', 'flow_collector', req.params.id, JSON.stringify({ name: rows[0].name })]
  );

  res.json({ collector: rows[0] });
});

// Delete collector
flowCollectorsRouter.delete('/:id', requireRole('admin'), async (req, res) => {
  const { rowCount } = await pool.query(`DELETE FROM flow_collectors WHERE id = $1`, [req.params.id]);
  if (!rowCount) return res.status(404).json({ error: 'not_found' });

  await pool.query(
    `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), $2, $3, $4, $5)`,
    [req.auth!.username, 'FLOW_COLLECTOR_DELETE', 'flow_collector', req.params.id, JSON.stringify({ collectorId: req.params.id })]
  );

  res.json({ ok: true });
});

// Get flows for collector
flowCollectorsRouter.get('/:id/flows', requireRole('viewer', 'operator', 'admin'), async (req, res) => {
  const limit = parseInt(String(req.query.limit ?? '100'), 10);
  const { rows } = await pool.query(
    `SELECT * FROM iot_observed_flows WHERE collector_id = $1 ORDER BY last_seen_at DESC LIMIT $2`,
    [req.params.id, limit]
  );
  res.json({ flows: rows });
});
