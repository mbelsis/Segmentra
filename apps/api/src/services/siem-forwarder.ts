import dgram from 'node:dgram';
import net from 'node:net';
import { pool } from '../db/pool.js';

interface SyslogConfig {
  host: string;
  port: number;
  protocol: 'udp' | 'tcp';
  facility: number; // 1=user, 4=auth, 10=security, 13=audit, 16-23=local0-7
  severity: number; // 6=info, 4=warning, 3=error
}

/**
 * Send a syslog message (RFC 5424 format) to the configured SIEM collector.
 * Fire-and-forget — errors are logged but never block the caller.
 */
export async function forwardAuditToSiem(event: {
  action: string;
  actorUsername?: string;
  entityType: string;
  entityId: string;
  metadata?: Record<string, any>;
}): Promise<void> {
  try {
    // Find enabled SIEM integrations
    const { rows } = await pool.query(
      `SELECT config FROM integrations WHERE type = 'siem' AND enabled = true`
    );
    if (rows.length === 0) return;

    const timestamp = new Date().toISOString();
    const hostname = 'segmentra';
    const appName = 'segmentra-audit';

    // Build structured data (RFC 5424 SD-ELEMENT)
    const sdParams = [
      `action="${event.action}"`,
      `actor="${event.actorUsername || 'system'}"`,
      `entityType="${event.entityType}"`,
      `entityId="${event.entityId}"`,
    ];
    if (event.metadata) {
      // Add top-level metadata fields (limit to prevent oversized messages)
      const metaEntries = Object.entries(event.metadata).slice(0, 10);
      for (const [k, v] of metaEntries) {
        const val = typeof v === 'object' ? JSON.stringify(v) : String(v);
        // Escape SD-PARAM values per RFC 5424 (escape ", \, ])
        const escaped = val.replace(/[\\"\\]]/g, '\\$&').slice(0, 200);
        sdParams.push(`${k.replace(/[^a-zA-Z0-9_]/g, '_')}="${escaped}"`);
      }
    }
    const structuredData = `[audit@segmentra ${sdParams.join(' ')}]`;
    const msgText = `${event.action} by ${event.actorUsername || 'system'} on ${event.entityType}:${event.entityId}`;

    for (const row of rows) {
      const config = (typeof row.config === 'string' ? JSON.parse(row.config) : row.config) as Partial<SyslogConfig>;
      if (!config.host || !config.port) continue;

      const facility = config.facility ?? 13; // default: audit
      const severity = config.severity ?? 6; // default: informational
      const priority = facility * 8 + severity;
      const protocol = config.protocol ?? 'udp';

      // RFC 5424 format: <priority>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
      const syslogMsg = `<${priority}>1 ${timestamp} ${hostname} ${appName} - - ${structuredData} ${msgText}`;

      try {
        if (protocol === 'udp') {
          await sendUdp(config.host, config.port, syslogMsg);
        } else {
          await sendTcp(config.host, config.port, syslogMsg);
        }
      } catch (e: any) {
        // eslint-disable-next-line no-console
        console.error(`[SIEM] Failed to send syslog to ${config.host}:${config.port}: ${e.message}`);
      }
    }
  } catch (e) {
    // eslint-disable-next-line no-console
    console.error('[SIEM] Error in forwardAuditToSiem:', e);
  }
}

function sendUdp(host: string, port: number, message: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const client = dgram.createSocket('udp4');
    const buf = Buffer.from(message, 'utf8');
    client.send(buf, 0, buf.length, port, host, (err) => {
      client.close();
      if (err) reject(err);
      else resolve();
    });
  });
}

function sendTcp(host: string, port: number, message: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const client = new net.Socket();
    const timeout = setTimeout(() => {
      client.destroy();
      reject(new Error('TCP syslog connection timeout'));
    }, 5000);

    client.connect(port, host, () => {
      // TCP syslog: message length prefix + message + newline
      client.write(`${message.length} ${message}\n`, () => {
        clearTimeout(timeout);
        client.end();
        resolve();
      });
    });

    client.on('error', (err) => {
      clearTimeout(timeout);
      client.destroy();
      reject(err);
    });
  });
}
