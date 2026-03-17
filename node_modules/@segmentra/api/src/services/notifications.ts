import { pool } from '../db/pool.js';

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
  | 'EXCESSIVE_RULES_DETECTED';

interface NotificationPayload {
  eventType: NotificationEventType;
  subject: string;
  body: Record<string, any>;
}

export async function sendNotification(payload: NotificationPayload): Promise<void> {
  try {
    // Find all enabled rules matching this event type
    const { rows: rules } = await pool.query(
      `SELECT nr.*, nc.name as channel_name, nc.type as channel_type, nc.config as channel_config
       FROM notification_rules nr
       JOIN notification_channels nc ON nc.id = nr.channel_id
       WHERE nr.event_type = $1 AND nr.enabled = true AND nc.enabled = true`,
      [payload.eventType]
    );

    for (const rule of rules) {
      const logId = await createLogEntry(rule.channel_id, payload);

      try {
        if (rule.channel_type === 'slack') {
          await sendSlack(rule.channel_config, payload);
        } else if (rule.channel_type === 'email') {
          await sendEmail(rule.channel_config, payload);
        } else if (rule.channel_type === 'webhook') {
          await sendWebhook(rule.channel_config, payload);
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

  const resp = await fetch(webhookUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(slackPayload),
  });
  if (!resp.ok) throw new Error(`Slack returned ${resp.status}`);
}

async function sendEmail(config: any, payload: NotificationPayload): Promise<void> {
  // Email sending would require an SMTP library (nodemailer)
  // For now, log the notification — SMTP integration can be added later
  const to = config.to || config.email;
  if (!to) throw new Error('Email recipient not configured');

  // eslint-disable-next-line no-console
  console.log(`[Notifications] Email to ${to}: ${payload.subject}`);
  // In production: use nodemailer with config.smtpHost, config.smtpPort, etc.
}

async function sendWebhook(config: any, payload: NotificationPayload): Promise<void> {
  const url = config.url;
  if (!url) throw new Error('Webhook URL not configured');

  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (config.authHeader) {
    headers['Authorization'] = config.authHeader;
  }
  if (config.customHeaders) {
    Object.assign(headers, config.customHeaders);
  }

  const resp = await fetch(url, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      event: payload.eventType,
      subject: payload.subject,
      data: payload.body,
      timestamp: new Date().toISOString(),
      source: 'segmentra',
    }),
  });
  if (!resp.ok) throw new Error(`Webhook returned ${resp.status}`);
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
