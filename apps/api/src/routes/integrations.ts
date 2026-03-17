import { Router } from 'express';
import { z } from 'zod';

import { pool } from '../db/pool.js';
import { requireAuth, requireRole } from '../middleware/auth.js';

export const integrationsRouter = Router();
integrationsRouter.use(requireAuth);

// List integrations
integrationsRouter.get('/', requireRole('admin'), async (_req, res) => {
  const { rows } = await pool.query(
    `SELECT id, type, provider, name, description, enabled, config, last_sync_at, last_sync_status, created_at
     FROM integrations ORDER BY type ASC, name ASC`
  );
  res.json({ integrations: rows });
});

// Host vulnerabilities
integrationsRouter.get('/vulnerabilities/by-host/:hostId', requireRole('admin'), async (req, res) => {
  const { rows } = await pool.query(
    `SELECT hv.*, i.name as integration_name, i.provider as integration_provider
     FROM host_vulnerabilities hv
     JOIN integrations i ON i.id = hv.integration_id
     WHERE hv.host_id = $1
     ORDER BY CASE hv.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, hv.last_seen_at DESC`,
    [req.params.hostId]
  );
  res.json({ vulnerabilities: rows });
});

// Threat intel entries
integrationsRouter.get('/threat-intel', requireRole('admin'), async (_req, res) => {
  const { rows } = await pool.query(
    `SELECT tie.*, i.name as integration_name
     FROM threat_intel_entries tie
     JOIN integrations i ON i.id = tie.integration_id
     WHERE tie.expires_at IS NULL OR tie.expires_at > now()
     ORDER BY tie.confidence DESC`
  );
  res.json({ entries: rows });
});

// Get single integration
integrationsRouter.get('/:id', requireRole('admin'), async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id, type, provider, name, description, enabled, config, last_sync_at, last_sync_status, created_at
     FROM integrations WHERE id = $1`,
    [req.params.id]
  );
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });

  const { rows: events } = await pool.query(
    `SELECT * FROM integration_events WHERE integration_id = $1 ORDER BY created_at DESC LIMIT 50`,
    [req.params.id]
  );

  res.json({ integration: rows[0], recentEvents: events });
});

const integrationSchema = z.object({
  type: z.enum(['siem', 'soar', 'vulnerability_db', 'threat_intel']),
  provider: z.string().min(1),
  name: z.string().min(1),
  description: z.string().optional(),
  enabled: z.boolean().default(false),
  config: z.record(z.any()).default({}),
  credentialsSecretId: z.string().uuid().optional().nullable(),
});

// Create integration
integrationsRouter.post('/', requireRole('admin'), async (req, res) => {
  const parsed = integrationSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body', details: parsed.error.issues });
  const b = parsed.data;

  const userRes = await pool.query(`SELECT id FROM users WHERE username=$1 LIMIT 1`, [req.auth!.username]);
  const userId = userRes.rows[0]?.id ?? null;

  const { rows } = await pool.query(
    `INSERT INTO integrations (type, provider, name, description, enabled, config, credentials_secret_id, created_by)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
    [b.type, b.provider, b.name, b.description ?? null, b.enabled,
     JSON.stringify(b.config), b.credentialsSecretId ?? null, userId]
  );

  await pool.query(
    `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ($1, 'INTEGRATION_CREATE', 'integration', $2, $3)`,
    [userId, rows[0].id, JSON.stringify({ type: b.type, provider: b.provider, name: b.name })]
  );

  res.status(201).json({ integration: rows[0] });
});

// Update integration
integrationsRouter.put('/:id', requireRole('admin'), async (req, res) => {
  const parsed = integrationSchema.partial().safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });
  const b = parsed.data;

  const { rows } = await pool.query(
    `UPDATE integrations
     SET type = COALESCE($2, type),
         provider = COALESCE($3, provider),
         name = COALESCE($4, name),
         description = COALESCE($5, description),
         enabled = COALESCE($6, enabled),
         config = COALESCE($7, config),
         credentials_secret_id = COALESCE($8, credentials_secret_id),
         updated_at = now()
     WHERE id = $1 RETURNING *`,
    [req.params.id, b.type ?? null, b.provider ?? null, b.name ?? null,
     b.description ?? null, b.enabled ?? null, b.config ? JSON.stringify(b.config) : null,
     b.credentialsSecretId ?? null]
  );
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });

  await pool.query(
    `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), $2, $3, $4, $5)`,
    [req.auth!.username, 'INTEGRATION_UPDATE', 'integration', req.params.id, JSON.stringify({ name: rows[0].name })]
  );

  res.json({ integration: rows[0] });
});

// Delete integration
integrationsRouter.delete('/:id', requireRole('admin'), async (req, res) => {
  const { rowCount } = await pool.query(`DELETE FROM integrations WHERE id = $1`, [req.params.id]);
  if (!rowCount) return res.status(404).json({ error: 'not_found' });

  await pool.query(
    `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), $2, $3, $4, $5)`,
    [req.auth!.username, 'INTEGRATION_DELETE', 'integration', req.params.id, JSON.stringify({ integrationId: req.params.id })]
  );

  res.json({ ok: true });
});

// Test integration connectivity — dispatches to real adapter for supported types
integrationsRouter.post('/:id/test', requireRole('admin'), async (req, res) => {
  const { rows } = await pool.query(`SELECT * FROM integrations WHERE id = $1`, [req.params.id]);
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });

  try {
    if (rows[0].type === 'siem') {
      // Real test: send a test syslog message
      const { forwardAuditToSiem } = await import('../services/siem-forwarder.js');
      await forwardAuditToSiem({
        action: 'INTEGRATION_TEST',
        actorUsername: req.auth!.username,
        entityType: 'integration',
        entityId: req.params.id,
        metadata: { message: 'Segmentra SIEM connectivity test' },
      });

      await pool.query(
        `INSERT INTO integration_events (integration_id, direction, event_type, payload, status)
         VALUES ($1, 'outbound', 'connectivity_test', '{}', 'SUCCESS')`,
        [req.params.id]
      );
      await pool.query(
        `UPDATE integrations SET last_sync_at = now(), last_sync_status = 'connected' WHERE id = $1`,
        [req.params.id]
      );
      res.json({ success: true, message: 'Test syslog message sent to configured collector. Check your SIEM for the test event.' });

    } else if (rows[0].type === 'threat_intel') {
      // Real test: verify API key by checking a known safe IP
      const config = typeof rows[0].config === 'string' ? JSON.parse(rows[0].config) : rows[0].config;
      if (!config.apiKey) {
        return res.status(400).json({ error: 'missing_api_key', message: 'Set apiKey in the integration config: {"apiKey": "your-abuseipdb-key"}' });
      }
      const testResp = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=90`, {
        headers: { 'Key': config.apiKey, 'Accept': 'application/json' },
      });
      if (!testResp.ok) {
        const errText = await testResp.text().catch(() => '');
        throw new Error(`AbuseIPDB returned ${testResp.status}: ${errText}`);
      }
      const testData = await testResp.json() as any;

      await pool.query(
        `INSERT INTO integration_events (integration_id, direction, event_type, payload, status)
         VALUES ($1, 'outbound', 'connectivity_test', $2, 'SUCCESS')`,
        [req.params.id, JSON.stringify({ testIp: '8.8.8.8', result: testData.data?.abuseConfidenceScore })]
      );
      await pool.query(
        `UPDATE integrations SET last_sync_at = now(), last_sync_status = 'connected' WHERE id = $1`,
        [req.params.id]
      );
      res.json({ success: true, message: `AbuseIPDB API key is valid. Test lookup: 8.8.8.8 (confidence: ${testData.data?.abuseConfidenceScore}%)` });

    } else {
      // Other types: placeholder
      await pool.query(
        `INSERT INTO integration_events (integration_id, direction, event_type, payload, status)
         VALUES ($1, 'outbound', 'connectivity_test', '{}', 'SUCCESS')`,
        [req.params.id]
      );
      res.json({ success: true, message: 'Configuration saved. Actual connectivity testing requires a custom adapter for this provider.' });
    }
  } catch (e: any) {
    await pool.query(
      `INSERT INTO integration_events (integration_id, direction, event_type, payload, status, error_message)
       VALUES ($1, 'outbound', 'connectivity_test', '{}', 'FAILED', $2)`,
      [req.params.id, e.message]
    );
    await pool.query(
      `UPDATE integrations SET last_sync_status = 'error' WHERE id = $1`,
      [req.params.id]
    );
    res.status(500).json({ error: 'test_failed', message: e.message });
  }
});

// Sync integration — dispatches to real adapter for supported types
integrationsRouter.post('/:id/sync', requireRole('admin'), async (req, res) => {
  const { rows } = await pool.query(`SELECT * FROM integrations WHERE id = $1`, [req.params.id]);
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });

  try {
    if (rows[0].type === 'threat_intel') {
      // Real sync: AbuseIPDB threat intelligence
      const { syncAbuseIPDB } = await import('../services/threat-intel-abuseipdb.js');
      const result = await syncAbuseIPDB(req.params.id);

      await pool.query(
        `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
         VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), $2, $3, $4, $5)`,
        [req.auth!.username, 'INTEGRATION_SYNC', 'integration', req.params.id, JSON.stringify(result)]
      );

      res.json({
        success: true,
        message: `Synced ${result.fetched} entries from AbuseIPDB (${result.newEntries} new, ${result.updatedEntries} updated${result.autoBlockedRules > 0 ? `, ${result.autoBlockedRules} auto-block rules created` : ''})`,
        ...result,
      });
    } else {
      // Other types: placeholder
      await pool.query(
        `UPDATE integrations SET last_sync_at = now(), last_sync_status = 'pending_adapter' WHERE id = $1`,
        [req.params.id]
      );
      await pool.query(
        `INSERT INTO integration_events (integration_id, direction, event_type, payload, status)
         VALUES ($1, 'inbound', 'sync', '{}', 'SUCCESS')`,
        [req.params.id]
      );
      res.json({ success: true, message: 'Sync event logged. Actual data synchronization requires a custom adapter for this provider.' });
    }
  } catch (e: any) {
    await pool.query(
      `UPDATE integrations SET last_sync_at = now(), last_sync_status = 'error' WHERE id = $1`,
      [req.params.id]
    );
    await pool.query(
      `INSERT INTO integration_events (integration_id, direction, event_type, payload, status, error_message)
       VALUES ($1, 'inbound', 'sync', '{}', 'FAILED', $2)`,
      [req.params.id, e.message]
    );
    res.status(500).json({ error: 'sync_failed', message: e.message });
  }
});

// Get integration events
integrationsRouter.get('/:id/events', requireRole('admin'), async (req, res) => {
  const limit = parseInt(String(req.query.limit ?? '50'), 10);
  const { rows } = await pool.query(
    `SELECT * FROM integration_events WHERE integration_id = $1 ORDER BY created_at DESC LIMIT $2`,
    [req.params.id, limit]
  );
  res.json({ events: rows });
});
