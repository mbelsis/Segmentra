import { Router } from 'express';
import { z } from 'zod';

import { pool } from '../db/pool.js';
import { requireAuth, requireRole } from '../middleware/auth.js';
import { sendTestToChannel, validateWebhookUrl } from '../services/notifications.js';
import { maskConfigSecrets, maskUrlSecrets, mergeConfigSecrets } from '../services/secret-mask.js';

const URL_KEYS = ['url', 'webhookUrl'] as const;

function parseConfig(raw: unknown): Record<string, any> {
  if (!raw) return {};
  if (typeof raw === 'string') {
    try {
      return JSON.parse(raw);
    } catch {
      return {};
    }
  }
  return raw as Record<string, any>;
}

/** Mask authHeader / tokens and secrets embedded in webhook URLs. */
function redactChannelConfig(config: unknown): Record<string, any> {
  const c = maskConfigSecrets(parseConfig(config));
  for (const k of URL_KEYS) {
    if (typeof c[k] === 'string') c[k] = maskUrlSecrets(c[k]);
  }
  if (c.customHeaders && typeof c.customHeaders === 'object') {
    c.customHeaders = Object.fromEntries(
      Object.entries(c.customHeaders).map(([k, v]) => [k, typeof v === 'string' && v.length > 0 ? `••••${v.slice(-4)}` : v])
    );
  }
  return c;
}

function redactChannel<T extends { config?: unknown }>(row: T): T {
  return row ? { ...row, config: redactChannelConfig(row.config) } : row;
}

/**
 * Apply an incoming config on top of the stored one: masked/omitted secrets keep their value,
 * and a URL equal to the masked form of the stored URL keeps the stored URL.
 */
function mergeChannelConfig(existing: Record<string, any>, incoming: Record<string, any>): Record<string, any> {
  const merged = mergeConfigSecrets(existing, incoming) as Record<string, any>;
  for (const k of URL_KEYS) {
    if (typeof incoming[k] === 'string' && typeof existing[k] === 'string' && incoming[k] !== existing[k]
        && incoming[k] === maskUrlSecrets(existing[k])) {
      merged[k] = existing[k];
    }
  }
  if (incoming.customHeaders && typeof incoming.customHeaders === 'object' && existing.customHeaders) {
    merged.customHeaders = Object.fromEntries(
      Object.entries(incoming.customHeaders).map(([k, v]) =>
        typeof v === 'string' && v.startsWith('••••') && existing.customHeaders[k] !== undefined
          ? [k, existing.customHeaders[k]]
          : [k, v]
      )
    );
  }
  return merged;
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

  const { rows } = await pool.query(
    `INSERT INTO notification_channels (name, type, config, enabled, created_by)
     VALUES ($1, $2, $3, $4, $5) RETURNING *`,
    [b.name, b.type, JSON.stringify(b.config), b.enabled, userId]
  );

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

  const existingRes = await pool.query(`SELECT type, config FROM notification_channels WHERE id = $1`, [req.params.id]);
  if (!existingRes.rows[0]) return res.status(404).json({ error: 'not_found' });
  let mergedConfig: Record<string, any> | null = null;
  if (b.config) {
    mergedConfig = mergeChannelConfig(parseConfig(existingRes.rows[0].config), b.config);
    const configError = await validateChannelConfig(b.type ?? existingRes.rows[0].type, mergedConfig);
    if (configError) return res.status(400).json({ error: 'invalid_webhook_url', message: configError });
  }

  const { rows } = await pool.query(
    `UPDATE notification_channels
     SET name = COALESCE($2, name), type = COALESCE($3, type),
         config = COALESCE($4, config), enabled = COALESCE($5, enabled), updated_at = now()
     WHERE id = $1 RETURNING *`,
    [req.params.id, b.name ?? null, b.type ?? null, mergedConfig ? JSON.stringify(mergedConfig) : null, b.enabled ?? null]
  );
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });
  res.json({ channel: redactChannel(rows[0]) });
});

// Delete channel
notificationsRouter.delete('/channels/:id', requireRole('admin'), async (req, res) => {
  const { rowCount } = await pool.query(`DELETE FROM notification_channels WHERE id = $1`, [req.params.id]);
  if (!rowCount) return res.status(404).json({ error: 'not_found' });
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
      config: rows[0].config,
      name: rows[0].name,
    });
    res.json({ success: true, message: `Test notification sent to ${rows[0].name} (${rows[0].type})` });
  } catch (e: any) {
    res.status(502).json({ success: false, error: 'test_failed', message: `Failed to send to ${rows[0].name}: ${e.message}` });
  }
});
