import { Router } from 'express';
import { z } from 'zod';

import { pool } from '../db/pool.js';
import { requireAuth, requireRole } from '../middleware/auth.js';

export const iotAssetsRouter = Router();
iotAssetsRouter.use(requireAuth);

// List IoT assets
iotAssetsRouter.get('/', requireRole('viewer', 'operator', 'admin'), async (req, res) => {
  const assetType = req.query.assetType ? String(req.query.assetType) : null;
  const zone = req.query.zone ? String(req.query.zone) : null;
  const vlanId = req.query.vlanId ? String(req.query.vlanId) : null;

  let query = `SELECT ia.*, v.name as vlan_name, v.vlan_tag,
    (SELECT array_agg(t.name) FROM iot_asset_tags iat JOIN tags t ON t.id = iat.tag_id WHERE iat.asset_id = ia.id) as tag_names
   FROM iot_assets ia
   LEFT JOIN vlans v ON v.id = ia.vlan_id
   WHERE 1=1`;
  const params: any[] = [];
  let idx = 1;

  if (assetType) {
    query += ` AND ia.asset_type = $${idx++}`;
    params.push(assetType);
  }
  if (zone) {
    query += ` AND ia.zone = $${idx++}`;
    params.push(zone);
  }
  if (vlanId) {
    query += ` AND ia.vlan_id = $${idx++}`;
    params.push(vlanId);
  }
  query += ` ORDER BY ia.name ASC`;

  const { rows } = await pool.query(query, params);
  res.json({ assets: rows });
});

// Get single IoT asset
iotAssetsRouter.get('/:id', requireRole('viewer', 'operator', 'admin'), async (req, res) => {
  const { rows } = await pool.query(
    `SELECT ia.*, v.name as vlan_name, v.vlan_tag FROM iot_assets ia
     LEFT JOIN vlans v ON v.id = ia.vlan_id WHERE ia.id = $1`,
    [req.params.id]
  );
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });

  // Get observed flows
  const { rows: flows } = await pool.query(
    `SELECT * FROM iot_observed_flows
     WHERE source_ip = $1 OR dest_ip = $1
     ORDER BY last_seen_at DESC LIMIT 100`,
    [rows[0].ip_address]
  );

  // Get tags
  const { rows: tags } = await pool.query(
    `SELECT t.* FROM tags t JOIN iot_asset_tags iat ON iat.tag_id = t.id WHERE iat.asset_id = $1`,
    [req.params.id]
  );

  res.json({ asset: rows[0], observedFlows: flows, tags });
});

const iotAssetSchema = z.object({
  name: z.string().min(1),
  description: z.string().optional(),
  assetType: z.enum(['plc', 'hmi', 'sensor', 'camera', 'printer', 'hvac', 'medical', 'other']).default('sensor'),
  vendor: z.string().optional(),
  model: z.string().optional(),
  firmwareVersion: z.string().optional(),
  macAddress: z.string().optional(),
  ipAddress: z.string().optional(),
  vlanId: z.string().uuid().optional().nullable(),
  zone: z.string().optional(),
  criticality: z.enum(['critical', 'high', 'medium', 'low']).default('medium'),
  fingerprint: z.record(z.any()).optional(),
  discoveredBy: z.string().optional(),
  enabled: z.boolean().default(true),
});

// Create IoT asset
iotAssetsRouter.post('/', requireRole('operator', 'admin'), async (req, res) => {
  const parsed = iotAssetSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body', details: parsed.error.issues });
  const b = parsed.data;

  const { rows } = await pool.query(
    `INSERT INTO iot_assets (name, description, asset_type, vendor, model, firmware_version, mac_address, ip_address, vlan_id, zone, criticality, fingerprint, discovered_by, enabled)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) RETURNING *`,
    [b.name, b.description ?? null, b.assetType, b.vendor ?? null, b.model ?? null,
     b.firmwareVersion ?? null, b.macAddress ?? null, b.ipAddress ?? null, b.vlanId ?? null,
     b.zone ?? null, b.criticality, JSON.stringify(b.fingerprint ?? {}),
     b.discoveredBy ?? null, b.enabled]
  );

  const userRes = await pool.query(`SELECT id FROM users WHERE username=$1 LIMIT 1`, [req.auth!.username]);
  const userId = userRes.rows[0]?.id ?? null;
  await pool.query(
    `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ($1, 'IOT_ASSET_CREATE', 'iot_asset', $2, $3)`,
    [userId, rows[0].id, JSON.stringify({ name: b.name, assetType: b.assetType })]
  );

  res.status(201).json({ asset: rows[0] });
});

// Update IoT asset
iotAssetsRouter.put('/:id', requireRole('operator', 'admin'), async (req, res) => {
  const parsed = iotAssetSchema.partial().safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });
  const b = parsed.data;

  const { rows } = await pool.query(
    `UPDATE iot_assets
     SET name = COALESCE($2, name),
         description = COALESCE($3, description),
         asset_type = COALESCE($4, asset_type),
         vendor = COALESCE($5, vendor),
         model = COALESCE($6, model),
         firmware_version = COALESCE($7, firmware_version),
         mac_address = COALESCE($8, mac_address),
         ip_address = COALESCE($9, ip_address),
         vlan_id = COALESCE($10, vlan_id),
         zone = COALESCE($11, zone),
         criticality = COALESCE($12, criticality),
         fingerprint = COALESCE($13, fingerprint),
         enabled = COALESCE($14, enabled),
         updated_at = now()
     WHERE id = $1 RETURNING *`,
    [req.params.id, b.name ?? null, b.description ?? null, b.assetType ?? null,
     b.vendor ?? null, b.model ?? null, b.firmwareVersion ?? null, b.macAddress ?? null,
     b.ipAddress ?? null, b.vlanId ?? null, b.zone ?? null, b.criticality ?? null,
     b.fingerprint ? JSON.stringify(b.fingerprint) : null, b.enabled ?? null]
  );
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });
  res.json({ asset: rows[0] });
});

// Delete IoT asset
iotAssetsRouter.delete('/:id', requireRole('operator', 'admin'), async (req, res) => {
  const { rowCount } = await pool.query(`DELETE FROM iot_assets WHERE id = $1`, [req.params.id]);
  if (!rowCount) return res.status(404).json({ error: 'not_found' });
  res.json({ ok: true });
});

// Bulk import IoT assets
iotAssetsRouter.post('/bulk-import', requireRole('operator', 'admin'), async (req, res) => {
  const bodySchema = z.object({ assets: z.array(iotAssetSchema) });
  const parsed = bodySchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });

  let imported = 0;
  for (const asset of parsed.data.assets) {
    try {
      await pool.query(
        `INSERT INTO iot_assets (name, asset_type, vendor, model, mac_address, ip_address, vlan_id, zone, criticality, fingerprint, enabled)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
        [asset.name, asset.assetType, asset.vendor ?? null, asset.model ?? null,
         asset.macAddress ?? null, asset.ipAddress ?? null, asset.vlanId ?? null,
         asset.zone ?? null, asset.criticality, JSON.stringify(asset.fingerprint ?? {}), asset.enabled]
      );
      imported++;
    } catch {
      // Skip duplicate/invalid entries
    }
  }
  res.json({ imported, total: parsed.data.assets.length });
});

// Assign tag to IoT asset
iotAssetsRouter.post('/:id/tags', requireRole('operator', 'admin'), async (req, res) => {
  const bodySchema = z.object({ tagId: z.string().uuid() });
  const parsed = bodySchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });

  await pool.query(
    `INSERT INTO iot_asset_tags (asset_id, tag_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
    [req.params.id, parsed.data.tagId]
  );
  res.json({ ok: true });
});

// Remove tag from IoT asset
iotAssetsRouter.delete('/:id/tags/:tagId', requireRole('operator', 'admin'), async (req, res) => {
  await pool.query(
    `DELETE FROM iot_asset_tags WHERE asset_id = $1 AND tag_id = $2`,
    [req.params.id, req.params.tagId]
  );
  res.json({ ok: true });
});

// Get observed flows for an asset
iotAssetsRouter.get('/:id/flows', requireRole('viewer', 'operator', 'admin'), async (req, res) => {
  const { rows: asset } = await pool.query(`SELECT ip_address FROM iot_assets WHERE id = $1`, [req.params.id]);
  if (!asset[0]) return res.status(404).json({ error: 'not_found' });

  const { rows } = await pool.query(
    `SELECT * FROM iot_observed_flows WHERE source_ip = $1 OR dest_ip = $1 ORDER BY last_seen_at DESC LIMIT 200`,
    [asset[0].ip_address]
  );
  res.json({ flows: rows });
});

// Baseline: snapshot current traffic as allowed
iotAssetsRouter.post('/:id/baseline', requireRole('operator', 'admin'), async (req, res) => {
  const { rows: asset } = await pool.query(`SELECT * FROM iot_assets WHERE id = $1`, [req.params.id]);
  if (!asset[0]) return res.status(404).json({ error: 'not_found' });

  const { rows: flows } = await pool.query(
    `SELECT * FROM iot_observed_flows WHERE source_ip = $1 OR dest_ip = $1`,
    [asset[0].ip_address]
  );

  // Store baseline in fingerprint
  await pool.query(
    `UPDATE iot_assets SET fingerprint = jsonb_set(COALESCE(fingerprint, '{}'), '{baseline}', $2), updated_at = now() WHERE id = $1`,
    [req.params.id, JSON.stringify({ flows: flows.length, capturedAt: new Date().toISOString(), flowSummary: flows.slice(0, 50) })]
  );

  res.json({ ok: true, baselineFlows: flows.length });
});
