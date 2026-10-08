import { pool } from '../db/pool.js';
import { loadFullConfig } from './config-secrets.js';
import {
  DEFAULT_OUTBOUND_TIMEOUT_MS,
  normalizeHost,
  postJsonSafe,
  safeResolve,
  validateOutboundUrl,
  type SafeHttpResponse,
} from '../lib/safe-http.js';

/**
 * Validate an outbound webhook URL (SSRF guard). Only http/https are allowed; loopback,
 * link-local and cloud-metadata destinations are rejected unless
 * SEGMENTRA_ALLOW_PRIVATE_WEBHOOKS=true. With resolveDns (default) the hostname is also
 * resolved and every address checked — this is advisory (e.g. when saving a channel); the
 * authoritative check happens at connect time inside postJsonSafe's lookup, so DNS
 * rebinding between this check and the request cannot bypass it.
 * Throws an Error whose message starts with "invalid_webhook_url:".
 */
export async function validateWebhookUrl(rawUrl: unknown, opts: { resolveDns?: boolean } = {}): Promise<URL> {
  const url = validateOutboundUrl(rawUrl);
  if (opts.resolveDns === false || process.env.SEGMENTRA_ALLOW_PRIVATE_WEBHOOKS === 'true') return url;
  const host = normalizeHost(url.hostname);
  try {
    await safeResolve(host);
  } catch (e: any) {
    if (e?.name === 'BlockedDestinationError') throw new Error(`invalid_webhook_url: ${e.message}`);
    throw new Error(`invalid_webhook_url: cannot resolve host "${host}"`);
  }
  return url;
}

/** POST JSON with the SSRF-safe client (validated IP is the one connected to; no redirects; 10s timeout). */
async function postJson(rawUrl: string, headers: Record<string, string>, body: unknown): Promise<SafeHttpResponse> {
  try {
    return await postJsonSafe(rawUrl, headers, body, { timeoutMs: DEFAULT_OUTBOUND_TIMEOUT_MS });
  } catch (e: any) {
    if (e?.name === 'BlockedDestinationError') throw new Error(`invalid_webhook_url: ${e.message}`);
    throw e;
  }
}

function describeBadResponse(service: string, resp: SafeHttpResponse): string {
  if (resp.status >= 300 && resp.status < 400) {
    return `${service} returned redirect ${resp.status} (redirects are not followed)`;
  }
  return `${service} returned ${resp.status}`;
}

export type NotificationEventType =
  | 'POLICY_SUBMITTED'
  | 'POLICY_APPROVED'
  | 'POLICY_REJECTED'
  | 'DEPLOYMENT_STARTED'
  | 'DEPLOYMENT_COMPLETED'
  | 'DEPLOYMENT_FAILED'
  | 'COMPLIANCE_DRIFT'
  | 'POLICY_EXPIRING_SOON'
  | 'POLICY_EXPIRED'
  | 'EXCESSIVE_RULES_DETECTED'
  | 'AUDIT_RESTORE_FAILED';

interface NotificationPayload {
  eventType: NotificationEventType;
  subject: string;
  body: Record<string, any>;
}

export async function sendNotification(payload: NotificationPayload): Promise<void> {
  try {
    // Find all enabled rules matching this event type
    const { rows: rules } = await pool.query(
      `SELECT nr.*, nc.name as channel_name, nc.type as channel_type, nc.config as channel_config,
              nc.config_secret_id as channel_config_secret_id
       FROM notification_rules nr
       JOIN notification_channels nc ON nc.id = nr.channel_id
       WHERE nr.event_type = $1 AND nr.enabled = true AND nc.enabled = true`,
      [payload.eventType]
    );

    for (const rule of rules) {
      const logId = await createLogEntry(rule.channel_id, payload);

      try {
        // Full config (webhook URL, auth headers) is decrypted from secret_store.
        const channelConfig = await loadFullConfig({
          config: rule.channel_config,
          config_secret_id: rule.channel_config_secret_id,
        });
        if (rule.channel_type === 'slack') {
          await sendSlack(channelConfig, payload);
        } else if (rule.channel_type === 'email') {
          await sendEmail(channelConfig, payload);
        } else if (rule.channel_type === 'webhook') {
          await sendWebhook(channelConfig, payload);
        }

        await pool.query(
          `UPDATE notification_log SET status = 'SENT', sent_at = now() WHERE id = $1`,
          [logId]
        );
      } catch (e: any) {
        await pool.query(
          `UPDATE notification_log SET status = 'FAILED', error_message = $2 WHERE id = $1`,
          [logId, e.message]
        );
        // Don't throw — notification failures should never block the main operation
        // eslint-disable-next-line no-console
        console.error(`[Notifications] Failed to send to ${rule.channel_name}:`, e.message);
      }
    }
  } catch (e) {
    // eslint-disable-next-line no-console
    console.error('[Notifications] Error processing notification:', e);
  }
}

async function createLogEntry(channelId: string, payload: NotificationPayload): Promise<string> {
  const { rows } = await pool.query(
    `INSERT INTO notification_log (channel_id, event_type, subject, payload, status)
     VALUES ($1, $2, $3, $4, 'PENDING') RETURNING id`,
    [channelId, payload.eventType, payload.subject, JSON.stringify(payload.body)]
  );
  return rows[0].id;
}

async function sendSlack(config: any, payload: NotificationPayload): Promise<void> {
  const webhookUrl = config.webhookUrl;
  if (!webhookUrl) throw new Error('Slack webhook URL not configured');

  const color = payload.eventType.includes('FAILED') || payload.eventType.includes('DRIFT') || payload.eventType.includes('EXCESSIVE')
    ? '#a63d2f'
    : payload.eventType.includes('APPROVED') || payload.eventType.includes('COMPLETED')
    ? '#5a7a3a'
    : '#8b6914';

  const slackPayload = {
    attachments: [{
      color,
      title: payload.subject,
      text: formatBody(payload.body),
      footer: 'Segmentra',
      ts: Math.floor(Date.now() / 1000),
    }],
  };

  const resp = await postJson(webhookUrl, { 'Content-Type': 'application/json' }, slackPayload);
  if (!resp.ok) throw new Error(describeBadResponse('Slack', resp));
}

async function sendEmail(config: any, payload: NotificationPayload): Promise<void> {
  // Email sending would require an SMTP library (nodemailer)
  // For now, log the notification — SMTP integration can be added later
  const to = config.to || config.email;
  if (!to) throw new Error('Email recipient not configured');

  // No SMTP client is bundled yet. Fail loudly instead of recording the notification as SENT
  // when nothing was delivered.
  throw new Error(`Email delivery is not implemented yet (no SMTP support); nothing was sent to ${to}. Use a Slack or webhook channel.`);
}

async function sendWebhook(config: any, payload: NotificationPayload): Promise<void> {
  const url = config.url;
  if (!url) throw new Error('Webhook URL not configured');

  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (config.authHeader) {
    headers['Authorization'] = config.authHeader;
  }
  if (config.customHeaders && typeof config.customHeaders === 'object') {
    for (const [k, v] of Object.entries(config.customHeaders)) {
      if (typeof v === 'string' && /^[A-Za-z0-9-]+$/.test(k)) headers[k] = v;
    }
  }

  const resp = await postJson(url, headers, {
    event: payload.eventType,
    subject: payload.subject,
    data: payload.body,
    timestamp: new Date().toISOString(),
    source: 'segmentra',
  });
  if (!resp.ok) throw new Error(describeBadResponse('Webhook', resp));
}

/**
 * Send a test notification directly to a specific channel, bypassing rule matching.
 * This actually tests the channel's connectivity and configuration.
 */
export async function sendTestToChannel(channel: { id: string; type: string; config: any; name: string }): Promise<void> {
  const payload: NotificationPayload = {
    eventType: 'DEPLOYMENT_COMPLETED',
    subject: 'Segmentra Test Notification',
    body: {
      message: 'This is a test notification from Segmentra.',
      channel: channel.name,
      timestamp: new Date().toISOString(),
    },
  };

  const logId = await createLogEntry(channel.id, payload);

  try {
    if (channel.type === 'slack') {
      await sendSlack(channel.config, payload);
    } else if (channel.type === 'email') {
      await sendEmail(channel.config, payload);
    } else if (channel.type === 'webhook') {
      await sendWebhook(channel.config, payload);
    } else {
      throw new Error(`Unknown channel type: ${channel.type}`);
    }

    await pool.query(
      `UPDATE notification_log SET status = 'SENT', sent_at = now() WHERE id = $1`,
      [logId]
    );
  } catch (e: any) {
    await pool.query(
      `UPDATE notification_log SET status = 'FAILED', error_message = $2 WHERE id = $1`,
      [logId, e.message]
    );
    throw e; // Re-throw so caller knows it failed
  }
}

function formatBody(body: Record<string, any>): string {
  return Object.entries(body)
    .filter(([, v]) => v !== null && v !== undefined)
    .map(([k, v]) => `*${k}*: ${typeof v === 'object' ? JSON.stringify(v) : v}`)
    .join('\n');
}

/**
 * Fire-and-forget notification about a policy version (submitted / approved / rejected).
 * Never throws and never delays the caller.
 */
export function notifyPolicyVersionEvent(
  eventType: 'POLICY_SUBMITTED' | 'POLICY_APPROVED' | 'POLICY_REJECTED',
  versionId: string,
  extra: Record<string, any> = {}
): void {
  void (async () => {
    const { rows } = await pool.query(
      `SELECT ps.name AS policy_set_name, pv.version_number, pv.is_high_risk
       FROM policy_versions pv JOIN policy_sets ps ON ps.id = pv.policy_set_id WHERE pv.id = $1`,
      [versionId]
    );
    const v = rows[0];
    if (!v) return;
    const verb = eventType === 'POLICY_SUBMITTED' ? 'submitted for approval' : eventType === 'POLICY_APPROVED' ? 'approved' : 'rejected';
    await sendNotification({
      eventType,
      subject: `Policy ${v.policy_set_name} v${v.version_number} ${verb}`,
      body: { policySet: v.policy_set_name, version: v.version_number, versionId, highRisk: v.is_high_risk === true, ...extra },
    });
  })().catch((e) => {
    // eslint-disable-next-line no-console
    console.error('[Notifications] policy event failed:', e?.message ?? e);
  });
}

/**
 * Fire-and-forget notification about a deployment (started / completed / failed).
 * Never throws and never delays the caller.
 */
export function notifyDeploymentEvent(
  eventType: 'DEPLOYMENT_STARTED' | 'DEPLOYMENT_COMPLETED' | 'DEPLOYMENT_FAILED',
  deploymentId: string,
  extra: Record<string, any> = {}
): void {
  void (async () => {
    const { rows } = await pool.query(
      `SELECT d.status, d.mode, d.target_count, ps.name AS policy_set_name, pv.version_number,
              (SELECT COUNT(*)::int FROM deployment_hosts dh WHERE dh.deployment_id = d.id AND dh.status = 'SUCCEEDED') AS succeeded,
              (SELECT COUNT(*)::int FROM deployment_hosts dh WHERE dh.deployment_id = d.id AND dh.status = 'FAILED') AS failed,
              (SELECT COUNT(*)::int FROM deployment_hosts dh WHERE dh.deployment_id = d.id AND dh.status = 'SKIPPED') AS skipped
       FROM deployments d
       LEFT JOIN policy_versions pv ON pv.id = d.policy_version_id
       LEFT JOIN policy_sets ps ON ps.id = pv.policy_set_id
       WHERE d.id = $1`,
      [deploymentId]
    );
    const d = rows[0];
    if (!d) return;
    const what = eventType === 'DEPLOYMENT_STARTED' ? 'started' : eventType === 'DEPLOYMENT_COMPLETED' ? 'completed' : `finished with status ${d.status}`;
    const body: Record<string, any> = {
      deploymentId,
      policySet: d.policy_set_name,
      version: d.version_number,
      mode: d.mode,
      status: d.status,
      targets: d.target_count,
      ...extra,
    };
    if (eventType !== 'DEPLOYMENT_STARTED') Object.assign(body, { succeeded: d.succeeded, failed: d.failed, skipped: d.skipped });
    await sendNotification({
      eventType,
      subject: `Deployment of ${d.policy_set_name ?? 'policy'} v${d.version_number ?? '?'} ${what}`,
      body,
    });
  })().catch((e) => {
    // eslint-disable-next-line no-console
    console.error('[Notifications] deployment event failed:', e?.message ?? e);
  });
}
