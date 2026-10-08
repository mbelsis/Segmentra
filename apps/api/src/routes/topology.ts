import { Router } from 'express';
import { z } from 'zod';

import { pool } from '../db/pool.js';
import { requireAuth, requireRole } from '../middleware/auth.js';
import { generatePoliciesFromTopology, autoDiscoverTopology, TopologyValidationError } from '../services/topology-to-policy.js';
import { isValidCidr, isValidPortSpec } from '../services/ip-utils.js';

export const topologyRouter = Router();
topologyRouter.use(requireAuth);

// List topology views
topologyRouter.get('/views', requireRole('viewer', 'operator', 'approver', 'admin'), async (_req, res) => {
  const { rows } = await pool.query(
    `SELECT tv.*, u.username as created_by_name,
       (SELECT COUNT(*) FROM topology_flows tf WHERE tf.topology_view_id = tv.id) as flow_count
     FROM topology_views tv
     LEFT JOIN users u ON u.id = tv.created_by
     ORDER BY tv.updated_at DESC`
  );
  res.json({ views: rows });
});

// Get single topology view with flows
topologyRouter.get('/views/:id', requireRole('viewer', 'operator', 'approver', 'admin'), async (req, res) => {
  const { rows } = await pool.query(`SELECT * FROM topology_views WHERE id = $1`, [req.params.id]);
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });

  const { rows: flows } = await pool.query(
    `SELECT * FROM topology_flows WHERE topology_view_id = $1 ORDER BY created_at ASC`,
    [req.params.id]
  );

  res.json({ view: rows[0], flows });
});

const topologyViewSchema = z.object({
  name: z.string().min(1),
  description: z.string().optional(),
  layoutData: z.any().optional(),
});

// Create topology view
topologyRouter.post('/views', requireRole('operator', 'admin'), async (req, res) => {
  const parsed = topologyViewSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });
  const b = parsed.data;

  const userRes = await pool.query(`SELECT id FROM users WHERE username=$1 LIMIT 1`, [req.auth!.username]);
  const userId = userRes.rows[0]?.id ?? null;

  const { rows } = await pool.query(
    `INSERT INTO topology_views (name, description, layout_data, created_by)
     VALUES ($1, $2, $3, $4) RETURNING *`,
    [b.name, b.description ?? null, JSON.stringify(b.layoutData ?? { nodes: [], edges: [] }), userId]
  );
  await pool.query(
    `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ($1, $2, $3, $4, $5)`,
    [userId, 'TOPOLOGY_VIEW_CREATE', 'topology_view', rows[0].id, JSON.stringify({ name: b.name })]
  );

  res.status(201).json({ view: rows[0] });
});

// Update topology view
topologyRouter.put('/views/:id', requireRole('operator', 'admin'), async (req, res) => {
  const parsed = topologyViewSchema.partial().safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });
  const b = parsed.data;

  const { rows } = await pool.query(
    `UPDATE topology_views
     SET name = COALESCE($2, name),
         description = COALESCE($3, description),
         layout_data = COALESCE($4, layout_data),
         updated_at = now()
     WHERE id = $1 RETURNING *`,
    [req.params.id, b.name ?? null, b.description ?? null, b.layoutData ? JSON.stringify(b.layoutData) : null]
  );
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });

  await pool.query(
    `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), $2, $3, $4, $5)`,
    [req.auth!.username, 'TOPOLOGY_VIEW_UPDATE', 'topology_view', req.params.id, JSON.stringify({ viewId: req.params.id })]
  );

  res.json({ view: rows[0] });
});

// Delete topology view
topologyRouter.delete('/views/:id', requireRole('operator', 'admin'), async (req, res) => {
  const { rowCount } = await pool.query(`DELETE FROM topology_views WHERE id = $1`, [req.params.id]);
  if (!rowCount) return res.status(404).json({ error: 'not_found' });

  await pool.query(
    `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), $2, $3, $4, $5)`,
    [req.auth!.username, 'TOPOLOGY_VIEW_DELETE', 'topology_view', req.params.id, JSON.stringify({ viewId: req.params.id })]
  );

  res.json({ ok: true });
});

// Topology flows CRUD
const endpointType = z.enum(['CIDR', 'TAG', 'VLAN', 'HOST']);
const uuidRe = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const flowSchema = z
  .object({
    sourceType: endpointType,
    sourceValue: z.string().trim().min(1),
    targetType: endpointType,
    targetValue: z.string().trim().min(1),
    direction: z.enum(['IN', 'OUT', 'BOTH']).default('BOTH'),
    action: z.enum(['ALLOW', 'DENY']).default('ALLOW'),
    protocol: z.enum(['tcp', 'udp', 'icmp', 'any']).default('tcp'),
    ports: z
      .string()
      .trim()
      .optional()
      .nullable()
      .transform((v) => (v ? v : null)),
    comment: z.string().max(500).optional(),
  })
  .superRefine((b, ctx) => {
    const checkEndpoint = (type: string, value: string, field: 'sourceValue' | 'targetValue') => {
      if (type === 'CIDR') {
        if (!isValidCidr(value)) ctx.addIssue({ code: z.ZodIssueCode.custom, path: [field], message: 'invalid_cidr' });
      } else if (!uuidRe.test(value)) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: [field], message: 'invalid_uuid' });
      }
    };
    checkEndpoint(b.sourceType, b.sourceValue, 'sourceValue');
    checkEndpoint(b.targetType, b.targetValue, 'targetValue');
    if (b.ports) {
      if (b.protocol !== 'tcp' && b.protocol !== 'udp') {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['ports'], message: 'ports_require_tcp_or_udp' });
      } else if (!isValidPortSpec(b.ports)) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['ports'], message: 'invalid_ports' });
      }
    }
  });

topologyRouter.post('/views/:id/flows', requireRole('operator', 'admin'), async (req, res) => {
  const parsed = flowSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body', details: parsed.error.flatten() });
  const b = parsed.data;

  const viewRes = await pool.query(`SELECT 1 FROM topology_views WHERE id = $1`, [req.params.id]);
  if (!viewRes.rows[0]) return res.status(404).json({ error: 'not_found' });

  const { rows } = await pool.query(
    `INSERT INTO topology_flows
      (topology_view_id, source_type, source_value, target_type, target_value, direction, action, protocol, ports, comment)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING *`,
    [req.params.id, b.sourceType, b.sourceValue, b.targetType, b.targetValue,
     b.direction, b.action, b.protocol, b.ports ?? null, b.comment ?? null]
  );
  res.status(201).json({ flow: rows[0] });
});

topologyRouter.delete('/flows/:flowId', requireRole('operator', 'admin'), async (req, res) => {
  const { rowCount } = await pool.query(`DELETE FROM topology_flows WHERE id = $1`, [req.params.flowId]);
  if (!rowCount) return res.status(404).json({ error: 'not_found' });
  res.json({ ok: true });
});

// Generate policies from topology
topologyRouter.post('/views/:id/generate-policies', requireRole('operator', 'admin'), async (req, res) => {
  const userRes = await pool.query(`SELECT id FROM users WHERE username=$1 LIMIT 1`, [req.auth!.username]);
  const userId = userRes.rows[0]?.id ?? null;
  const policySetName = typeof req.body?.name === 'string' && req.body.name.trim() ? req.body.name.trim() : undefined;

  try {
    const result = await generatePoliciesFromTopology(req.params.id, userId, policySetName);
    res.status(201).json(result);
  } catch (e: any) {
    if (e instanceof TopologyValidationError) {
      return res.status(400).json({ error: e.code, message: e.message, details: e.details });
    }
    throw e;
  }
});

// Auto-discover topology from existing inventory and policies
topologyRouter.get('/auto-discover', requireRole('viewer', 'operator', 'approver', 'admin'), async (_req, res) => {
  try {
    const result = await autoDiscoverTopology();
    res.json(result);
  } catch (e: any) {
    res.status(500).json({ error: 'auto_discover_failed', message: e?.message });
  }
});
