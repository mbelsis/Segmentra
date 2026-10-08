import { Router } from 'express';
import { z } from 'zod';

import { pool } from '../db/pool.js';
import { requireAuth, requireRole } from '../middleware/auth.js';
import { sendTestToChannel, validateWebhookUrl } from '../services/notifications.js';
import {
  deleteConfigSecret,
  loadFullConfig,
  maskChannelConfig,
  mergeChannelConfig,
  storeFullConfig,
} from '../services/config-secrets.js';

/**
 * Never return webhook URLs with tokens, auth headers or custom header values. The full config
 * lives encrypted in secret_store (config_secret_id); the `config` column only holds a masked
 * display copy (masked again here for rows not yet migrated).
 */
function redactChannel<T extends { config?: unknown; config_secret_id?: unknown }>(row: T): T {
  if (!row) return row;
  const { config_secret_id: _secretId, ...rest } = row;
  return { ...rest, config: maskChannelConfig(row.config) } as unknown as T;
}

async function validateChannelConfig(type: string, config: Record<string, any>): Promise<string | null> {
  try {
    if (type === 'slack' && config.webhookUrl) await validateWebhookUrl(config.webhookUrl, { resolveDns: false });
    if (type === 'webhook' && config.url) await validateWebhookUrl(config.url, { resolveDns: false });
  } catch (e: any) {
    return e.message;
  }
  return null;
}

export const notificationsRouter = Router();
notificationsRouter.use(requireAuth);

// List channels
notificationsRouter.get('/channels', requireRole('admin'), async (_req, res) => {
  const { rows } = await pool.query(
    `SELECT nc.*,
       (SELECT COUNT(*)::int FROM notification_rules nr WHERE nr.channel_id = nc.id) as rule_count,
       (SELECT COUNT(*)::int FROM notification_log nl WHERE nl.channel_id = nc.id AND nl.status = 'FAILED' AND nl.created_at > now() - interval '24 hours') as failed_24h
     FROM notification_channels nc ORDER BY nc.name ASC`
  );
  res.json({ channels: rows.map(redactChannel) });
});

// Get channel with rules and recent log
notificationsRouter.get('/channels/:id', requireRole('admin'), async (req, res) => {
  const { rows } = await pool.query(`SELECT * FROM notification_channels WHERE id = $1`, [req.params.id]);
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });

  const { rows: rules } = await pool.query(
    `SELECT * FROM notification_rules WHERE channel_id = $1 ORDER BY event_type ASC`,
    [req.params.id]
  );

  const { rows: recentLog } = await pool.query(
    `SELECT * FROM notification_log WHERE channel_id = $1 ORDER BY created_at DESC LIMIT 25`,
    [req.params.id]
  );

  res.json({ channel: redactChannel(rows[0]), rules, recentLog });
});

const channelSchema = z.object({
  name: z.string().min(1),
  type: z.enum(['slack', 'email', 'webhook']),
  config: z.record(z.any()).default({}),
  enabled: z.boolean().default(true),
});

// Create channel
notificationsRouter.post('/channels', requireRole('admin'), async (req, res) => {
  const parsed = channelSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body', details: parsed.error.issues });
  const b = parsed.data;
  const configError = await validateChannelConfig(b.type, b.config);
  if (configError) return res.status(400).json({ error: 'invalid_webhook_url', message: configError });

  const userRes = await pool.query(`SELECT id FROM users WHERE username=$1 LIMIT 1`, [req.auth!.username]);
  const userId = userRes.rows[0]?.id ?? null;

  // Full config encrypted in secret_store; only a masked copy goes to the plain column.
  const stored = await storeFullConfig('notification_channel', b.name, b.config, null);
  let rows;
  try {
    ({ rows } = await pool.query(
      `INSERT INTO notification_channels (name, type, config, config_secret_id, enabled, created_by)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [b.name, b.type, JSON.stringify(stored.displayConfig), stored.secretId, b.enabled, userId]
    ));
  } catch (e) {
    await deleteConfigSecret(stored.secretId);
    throw e;
  }

  await pool.query(
    `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ($1, 'NOTIFICATION_CHANNEL_CREATE', 'notification_channel', $2, $3)`,
    [userId, rows[0].id, JSON.stringify({ name: b.name, type: b.type })]
  );

  res.status(201).json({ channel: redactChannel(rows[0]) });
});

// Update channel
notificationsRouter.put('/channels/:id', requireRole('admin'), async (req, res) => {
  const parsed = channelSchema.partial().safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body', details: parsed.error.issues });
  const b = parsed.data;

  const existingRes = await pool.query(`SELECT name, type, config, config_secret_id FROM notification_channels WHERE id = $1`, [req.params.id]);
  if (!existingRes.rows[0]) return res.status(404).json({ error: 'not_found' });
  let displayConfig: Record<string, any> | null = null;
  let configSecretId: string | null = null;
  if (b.config) {
    const mergedConfig = mergeChannelConfig(await loadFullConfig(existingRes.rows[0]), b.config);
    const configError = await validateChannelConfig(b.type ?? existingRes.rows[0].type, mergedConfig);
    if (configError) return res.status(400).json({ error: 'invalid_webhook_url', message: configError });
    const stored = await storeFullConfig(
      'notification_channel', b.name ?? existingRes.rows[0].name, mergedConfig, existingRes.rows[0].config_secret_id
    );
    displayConfig = stored.displayConfig;
    configSecretId = stored.secretId;
  }

  const { rows } = await pool.query(
    `UPDATE notification_channels
     SET name = COALESCE($2, name), type = COALESCE($3, type),
         config = COALESCE($4, config), enabled = COALESCE($5, enabled),
         config_secret_id = COALESCE($6, config_secret_id), updated_at = now()
     WHERE id = $1 RETURNING *`,
    [req.params.id, b.name ?? null, b.type ?? null, displayConfig ? JSON.stringify(displayConfig) : null, b.enabled ?? null,
     configSecretId]
  );
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });
  res.json({ channel: redactChannel(rows[0]) });
});

// Delete channel
notificationsRouter.delete('/channels/:id', requireRole('admin'), async (req, res) => {
  const { rows: deleted } = await pool.query(`DELETE FROM notification_channels WHERE id = $1 RETURNING config_secret_id`, [req.params.id]);
  if (!deleted[0]) return res.status(404).json({ error: 'not_found' });
  await deleteConfigSecret(deleted[0].config_secret_id);
  res.json({ ok: true });
});

// Add notification rule to channel
const ruleSchema = z.object({
  eventType: z.enum([
    'POLICY_SUBMITTED', 'POLICY_APPROVED', 'POLICY_REJECTED',
    'DEPLOYMENT_STARTED', 'DEPLOYMENT_COMPLETED', 'DEPLOYMENT_FAILED',
    'COMPLIANCE_DRIFT', 'POLICY_EXPIRING_SOON', 'POLICY_EXPIRED',
    'EXCESSIVE_RULES_DETECTED', 'AUDIT_RESTORE_FAILED',
  ]),
  enabled: z.boolean().default(true),
  filter: z.record(z.any()).optional(),
});

notificationsRouter.post('/channels/:id/rules', requireRole('admin'), async (req, res) => {
  const parsed = ruleSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body', details: parsed.error.issues });
  const b = parsed.data;

  const { rows } = await pool.query(
    `INSERT INTO notification_rules (channel_id, event_type, enabled, filter)
     VALUES ($1, $2, $3, $4) RETURNING *`,
    [req.params.id, b.eventType, b.enabled, b.filter ? JSON.stringify(b.filter) : null]
  );
  res.status(201).json({ rule: rows[0] });
});

// Delete notification rule
notificationsRouter.delete('/rules/:ruleId', requireRole('admin'), async (req, res) => {
  const { rowCount } = await pool.query(`DELETE FROM notification_rules WHERE id = $1`, [req.params.ruleId]);
  if (!rowCount) return res.status(404).json({ error: 'not_found' });
  res.json({ ok: true });
});

// Get notification log
notificationsRouter.get('/log', requireRole('admin'), async (req, res) => {
  const parsedLimit = parseInt(String(req.query.limit ?? '50'), 10);
  const limit = Number.isFinite(parsedLimit) ? Math.min(Math.max(parsedLimit, 1), 500) : 50;
  const status = req.query.status ? String(req.query.status) : null;

  let query = `SELECT nl.*, nc.name as channel_name, nc.type as channel_type
   FROM notification_log nl
   LEFT JOIN notification_channels nc ON nc.id = nl.channel_id
   WHERE 1=1`;
  const params: any[] = [];
  let idx = 1;

  if (status) {
    query += ` AND nl.status = $${idx++}`;
    params.push(status);
  }
  query += ` ORDER BY nl.created_at DESC LIMIT $${idx++}`;
  params.push(limit);

  const { rows } = await pool.query(query, params);
  res.json({ log: rows });
});

// Test channel (send directly to this specific channel, bypassing rule matching)
notificationsRouter.post('/channels/:id/test', requireRole('admin'), async (req, res) => {
  const { rows } = await pool.query(`SELECT * FROM notification_channels WHERE id = $1`, [req.params.id]);
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });

  try {
    await sendTestToChannel({
      id: rows[0].id,
      type: rows[0].type,
      config: await loadFullConfig(rows[0]),
      name: rows[0].name,
    });
    res.json({ success: true, message: `Test notification sent to ${rows[0].name} (${rows[0].type})` });
  } catch (e: any) {
    res.status(502).json({ success: false, error: 'test_failed', message: `Failed to send to ${rows[0].name}: ${e.message}` });
  }
});
