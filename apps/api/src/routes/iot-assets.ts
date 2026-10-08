import { Router } from 'express';
import { z } from 'zod';

import { pool } from '../db/pool.js';
import { requireAuth, requireRole } from '../middleware/auth.js';

export const iotAssetsRouter = Router();
iotAssetsRouter.use(requireAuth);

// List IoT assets with their assigned gateways
iotAssetsRouter.get('/', requireRole('viewer', 'operator', 'approver', 'admin'), async (req, res) => {
  const assetType = req.query.assetType ? String(req.query.assetType) : null;
  const zone = req.query.zone ? String(req.query.zone) : null;
  const vlanId = req.query.vlanId ? String(req.query.vlanId) : null;
  const gatewayId = req.query.gatewayId ? String(req.query.gatewayId) : null;

  let query = `SELECT ia.*, v.name as vlan_name, v.vlan_tag,
    (SELECT array_agg(t.name) FROM iot_asset_tags iat JOIN tags t ON t.id = iat.tag_id WHERE iat.asset_id = ia.id) as tag_names,
    (SELECT array_agg(json_build_object('id', h.id, 'hostname', h.hostname, 'mgmt_ip', h.mgmt_ip))
     FROM iot_asset_gateways iag JOIN hosts h ON h.id = iag.host_id WHERE iag.asset_id = ia.id) as gateways
   FROM iot_assets ia
   LEFT JOIN vlans v ON v.id = ia.vlan_id
   WHERE 1=1`;
  const params: any[] = [];
  let idx = 1;

  if (assetType) { query += ` AND ia.asset_type = $${idx++}`; params.push(assetType); }
  if (zone) { query += ` AND ia.zone = $${idx++}`; params.push(zone); }
  if (vlanId) { query += ` AND ia.vlan_id = $${idx++}`; params.push(vlanId); }
  if (gatewayId) {
    query += ` AND EXISTS (SELECT 1 FROM iot_asset_gateways iag WHERE iag.asset_id = ia.id AND iag.host_id = $${idx++})`;
    params.push(gatewayId);
  }
  query += ` ORDER BY ia.name ASC`;

  const { rows } = await pool.query(query, params);
  res.json({ assets: rows });
});

// Get single IoT asset with gateways and flows
iotAssetsRouter.get('/:id', requireRole('viewer', 'operator', 'approver', 'admin'), async (req, res) => {
  const { rows } = await pool.query(
    `SELECT ia.*, v.name as vlan_name, v.vlan_tag FROM iot_assets ia
     LEFT JOIN vlans v ON v.id = ia.vlan_id WHERE ia.id = $1`,
    [req.params.id]
  );
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });

  const { rows: gateways } = await pool.query(
    `SELECT h.id, h.hostname, h.mgmt_ip, h.firewall_backend, h.enabled
     FROM hosts h JOIN iot_asset_gateways iag ON iag.host_id = h.id
     WHERE iag.asset_id = $1 ORDER BY h.hostname`,
    [req.params.id]
  );

  const { rows: flows } = await pool.query(
    `SELECT * FROM iot_observed_flows
     WHERE source_ip = $1 OR dest_ip = $1
     ORDER BY last_seen_at DESC LIMIT 100`,
    [rows[0].ip_address]
  );

  const { rows: tags } = await pool.query(
    `SELECT t.* FROM tags t JOIN iot_asset_tags iat ON iat.tag_id = t.id WHERE iat.asset_id = $1`,
    [req.params.id]
  );

  res.json({ asset: rows[0], gateways, observedFlows: flows, tags });
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
  gatewayIds: z.array(z.string().uuid()).optional(),
});

// Create IoT asset
iotAssetsRouter.post('/', requireRole('operator', 'admin'), async (req, res) => {
  const parsed = iotAssetSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body', details: parsed.error.issues });
  const b = parsed.data;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const { rows } = await client.query(
      `INSERT INTO iot_assets (name, description, asset_type, vendor, model, firmware_version, mac_address, ip_address, vlan_id, zone, criticality, fingerprint, discovered_by, enabled)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) RETURNING *`,
      [b.name, b.description ?? null, b.assetType, b.vendor ?? null, b.model ?? null,
       b.firmwareVersion ?? null, b.macAddress ?? null, b.ipAddress ?? null, b.vlanId ?? null,
       b.zone ?? null, b.criticality, JSON.stringify(b.fingerprint ?? {}),
       b.discoveredBy ?? null, b.enabled]
    );

    // Assign gateways if provided
    if (b.gatewayIds?.length) {
      for (const gid of b.gatewayIds) {
        await client.query(
          `INSERT INTO iot_asset_gateways (asset_id, host_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
          [rows[0].id, gid]
        );
      }
    }

    const userRes = await client.query(`SELECT id FROM users WHERE username=$1 LIMIT 1`, [req.auth!.username]);
    const userId = userRes.rows[0]?.id ?? null;
    await client.query(
      `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
       VALUES ($1, 'IOT_ASSET_CREATE', 'iot_asset', $2, $3)`,
      [userId, rows[0].id, JSON.stringify({ name: b.name, assetType: b.assetType, gatewayCount: b.gatewayIds?.length ?? 0 })]
    );

    await client.query('COMMIT');
    res.status(201).json({ asset: rows[0] });
  } catch (e: any) {
    await client.query('ROLLBACK').catch(() => {});
    throw e; // global handler maps FK/validation errors (e.g. unknown gateway host -> 409)
  } finally {
    client.release();
  }
});

// Update IoT asset
iotAssetsRouter.put('/:id', requireRole('operator', 'admin'), async (req, res) => {
  const parsed = iotAssetSchema.partial().safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });
  const b = parsed.data;

  const { rows } = await pool.query(
    `UPDATE iot_assets
     SET name = COALESCE($2, name), description = COALESCE($3, description),
         asset_type = COALESCE($4, asset_type), vendor = COALESCE($5, vendor),
         model = COALESCE($6, model), firmware_version = COALESCE($7, firmware_version),
         mac_address = COALESCE($8, mac_address), ip_address = COALESCE($9, ip_address),
         vlan_id = COALESCE($10, vlan_id), zone = COALESCE($11, zone),
         criticality = COALESCE($12, criticality),
         fingerprint = COALESCE($13, fingerprint), enabled = COALESCE($14, enabled),
         updated_at = now()
     WHERE id = $1 RETURNING *`,
    [req.params.id, b.name ?? null, b.description ?? null, b.assetType ?? null,
     b.vendor ?? null, b.model ?? null, b.firmwareVersion ?? null, b.macAddress ?? null,
     b.ipAddress ?? null, b.vlanId ?? null, b.zone ?? null, b.criticality ?? null,
     b.fingerprint ? JSON.stringify(b.fingerprint) : null, b.enabled ?? null]
  );
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });

  await pool.query(
    `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), 'IOT_ASSET_UPDATE', 'iot_asset', $2, $3)`,
    [req.auth!.username, req.params.id, JSON.stringify({ name: rows[0].name })]
  );

  res.json({ asset: rows[0] });
});

// Delete IoT asset
iotAssetsRouter.delete('/:id', requireRole('operator', 'admin'), async (req, res) => {
  const { rowCount } = await pool.query(`DELETE FROM iot_assets WHERE id = $1`, [req.params.id]);
  if (!rowCount) return res.status(404).json({ error: 'not_found' });

  await pool.query(
    `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), 'IOT_ASSET_DELETE', 'iot_asset', $2, $3)`,
    [req.auth!.username, req.params.id, JSON.stringify({ assetId: req.params.id })]
  );

  res.json({ ok: true });
});

// Bulk import IoT assets
iotAssetsRouter.post('/bulk-import', requireRole('operator', 'admin'), async (req, res) => {
  const bodySchema = z.object({ assets: z.array(iotAssetSchema) });
  const parsed = bodySchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });

  let imported = 0;
  const failures: Array<{ index: number; name: string; error: string }> = [];
  for (const [index, asset] of parsed.data.assets.entries()) {
    try {
      await pool.query(
        `INSERT INTO iot_assets (name, asset_type, vendor, model, mac_address, ip_address, vlan_id, zone, criticality, fingerprint, enabled)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
        [asset.name, asset.assetType, asset.vendor ?? null, asset.model ?? null,
         asset.macAddress ?? null, asset.ipAddress ?? null, asset.vlanId ?? null,
         asset.zone ?? null, asset.criticality, JSON.stringify(asset.fingerprint ?? {}), asset.enabled]
      );
      imported++;
    } catch (e: any) {
      failures.push({ index, name: asset.name, error: e?.detail || e?.message || String(e) });
    }
  }

  await pool.query(
    `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), 'IOT_ASSET_BULK_IMPORT', 'iot_asset', uuid_generate_v4(), $2)`,
    [req.auth!.username, JSON.stringify({ imported, failed: failures.length, total: parsed.data.assets.length })]
  );

  res.json({ imported, failed: failures.length, total: parsed.data.assets.length, failures });
});

// === Gateway Assignment ===

// Assign gateway(s) to an IoT asset
iotAssetsRouter.post('/:id/gateways', requireRole('operator', 'admin'), async (req, res) => {
  const bodySchema = z.object({ gatewayIds: z.array(z.string().uuid()).min(1) });
  const parsed = bodySchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });

  for (const gid of parsed.data.gatewayIds) {
    await pool.query(
      `INSERT INTO iot_asset_gateways (asset_id, host_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
      [req.params.id, gid]
    );
  }
  res.json({ ok: true, assigned: parsed.data.gatewayIds.length });
});

// Remove gateway from IoT asset
iotAssetsRouter.delete('/:id/gateways/:hostId', requireRole('operator', 'admin'), async (req, res) => {
  await pool.query(
    `DELETE FROM iot_asset_gateways WHERE asset_id = $1 AND host_id = $2`,
    [req.params.id, req.params.hostId]
  );
  res.json({ ok: true });
});

// === Gateway View ===

// List IoT gateways (hosts tagged "iot-gateway") with protected asset counts and deployed policy info
iotAssetsRouter.get('/gateways/list', requireRole('viewer', 'operator', 'approver', 'admin'), async (_req, res) => {
  const { rows } = await pool.query(
    `SELECT h.id, h.hostname, h.mgmt_ip, h.firewall_backend, h.enabled,
       (SELECT COUNT(*)::int FROM iot_asset_gateways iag WHERE iag.host_id = h.id) as protected_asset_count,
       (SELECT json_build_object(
          'deploymentId', d.id, 'status', d.status, 'policySetName', ps.name,
          'versionNumber', pv.version_number, 'deployedAt', d.finished_at
        )
        FROM deployment_hosts dh
        JOIN deployments d ON d.id = dh.deployment_id
        JOIN policy_versions pv ON pv.id = d.policy_version_id
        JOIN policy_sets ps ON ps.id = pv.policy_set_id
        WHERE dh.host_id = h.id AND dh.status = 'SUCCEEDED'
        ORDER BY d.finished_at DESC LIMIT 1
       ) as last_deployment
     FROM hosts h
     JOIN host_tags ht ON ht.host_id = h.id
     JOIN tags t ON t.id = ht.tag_id
     WHERE t.name = 'iot-gateway'
     ORDER BY h.hostname ASC`
  );
  res.json({ gateways: rows });
});

// Get single gateway with its protected assets and deployment history
iotAssetsRouter.get('/gateways/:hostId', requireRole('viewer', 'operator', 'approver', 'admin'), async (req, res) => {
  const { rows: hostRows } = await pool.query(
    `SELECT h.*, v.name as vlan_name, v.vlan_tag
     FROM hosts h LEFT JOIN vlans v ON v.id = h.vlan_id WHERE h.id = $1`,
    [req.params.hostId]
  );
  if (!hostRows[0]) return res.status(404).json({ error: 'not_found' });

  const { rows: assets } = await pool.query(
    `SELECT ia.id, ia.name, ia.asset_type, ia.vendor, ia.model, ia.ip_address, ia.zone, ia.criticality
     FROM iot_assets ia JOIN iot_asset_gateways iag ON iag.asset_id = ia.id
     WHERE iag.host_id = $1 ORDER BY ia.name`,
    [req.params.hostId]
  );

  const { rows: deployments } = await pool.query(
    `SELECT d.id, d.status, d.finished_at, d.created_at, ps.name as policy_set_name, pv.version_number
     FROM deployment_hosts dh
     JOIN deployments d ON d.id = dh.deployment_id
     JOIN policy_versions pv ON pv.id = d.policy_version_id
     JOIN policy_sets ps ON ps.id = pv.policy_set_id
     WHERE dh.host_id = $1 AND dh.status = 'SUCCEEDED'
     ORDER BY d.finished_at DESC LIMIT 10`,
    [req.params.hostId]
  );

  res.json({ gateway: hostRows[0], protectedAssets: assets, recentDeployments: deployments });
});

// === Tags ===
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

iotAssetsRouter.delete('/:id/tags/:tagId', requireRole('operator', 'admin'), async (req, res) => {
  await pool.query(
    `DELETE FROM iot_asset_tags WHERE asset_id = $1 AND tag_id = $2`,
    [req.params.id, req.params.tagId]
  );
  res.json({ ok: true });
});

// === Flows ===
iotAssetsRouter.get('/:id/flows', requireRole('viewer', 'operator', 'approver', 'admin'), async (req, res) => {
  const { rows: asset } = await pool.query(`SELECT ip_address FROM iot_assets WHERE id = $1`, [req.params.id]);
  if (!asset[0]) return res.status(404).json({ error: 'not_found' });

  const { rows } = await pool.query(
    `SELECT * FROM iot_observed_flows WHERE source_ip = $1 OR dest_ip = $1 ORDER BY last_seen_at DESC LIMIT 200`,
    [asset[0].ip_address]
  );
  res.json({ flows: rows });
});

// === Baseline ===
iotAssetsRouter.post('/:id/baseline', requireRole('operator', 'admin'), async (req, res) => {
  const { rows: asset } = await pool.query(`SELECT * FROM iot_assets WHERE id = $1`, [req.params.id]);
  if (!asset[0]) return res.status(404).json({ error: 'not_found' });

  const { rows: flows } = await pool.query(
    `SELECT * FROM iot_observed_flows WHERE source_ip = $1 OR dest_ip = $1`,
    [asset[0].ip_address]
  );

  await pool.query(
    `UPDATE iot_assets SET fingerprint = jsonb_set(COALESCE(fingerprint, '{}'), '{baseline}', $2), updated_at = now() WHERE id = $1`,
    [req.params.id, JSON.stringify({ flows: flows.length, capturedAt: new Date().toISOString(), flowSummary: flows.slice(0, 50) })]
  );

  await pool.query(
    `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), 'IOT_ASSET_BASELINE', 'iot_asset', $2, $3)`,
    [req.auth!.username, req.params.id, JSON.stringify({ assetId: req.params.id, flows: flows.length })]
  );

  res.json({ ok: true, baselineFlows: flows.length });
});
