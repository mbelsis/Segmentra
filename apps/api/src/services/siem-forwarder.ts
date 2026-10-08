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

export type SiemAuditEvent = {
  action: string;
  actorUsername?: string;
  entityType: string;
  entityId: string;
  metadata?: Record<string, any>;
};

/** Escape an SD-PARAM value per RFC 5424 section 6.3.3: '"', '\' and ']' must be escaped. */
export function escapeSdParamValue(value: string): string {
  return value.replace(/["\\\]]/g, '\\$&');
}

function sdParam(name: string, value: string, maxLen = 200): string {
  const safeName = name.replace(/[^a-zA-Z0-9_]/g, '_').slice(0, 32) || 'param';
  // Truncate before escaping so we never cut an escape sequence in half.
  return `${safeName}="${escapeSdParamValue(value.slice(0, maxLen))}"`;
}

export function buildSyslogMessage(event: SiemAuditEvent, config: Partial<SyslogConfig>): string {
  const timestamp = new Date().toISOString();
  const hostname = 'segmentra';
  const appName = 'segmentra-audit';

  // Build structured data (RFC 5424 SD-ELEMENT)
  const sdParams = [
    sdParam('action', event.action),
    sdParam('actor', event.actorUsername || 'system'),
    sdParam('entityType', event.entityType),
    sdParam('entityId', event.entityId),
  ];
  if (event.metadata) {
    // Add top-level metadata fields (limit to prevent oversized messages)
    const metaEntries = Object.entries(event.metadata).slice(0, 10);
    for (const [k, v] of metaEntries) {
      const val = typeof v === 'object' ? JSON.stringify(v) : String(v);
      sdParams.push(sdParam(k, val));
    }
  }
  const structuredData = `[audit@segmentra ${sdParams.join(' ')}]`;
  const msgText = `${event.action} by ${event.actorUsername || 'system'} on ${event.entityType}:${event.entityId}`;

  const facility = config.facility ?? 13; // default: audit
  const severity = config.severity ?? 6; // default: informational
  const priority = facility * 8 + severity;

  // RFC 5424 format: <priority>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
  return `<${priority}>1 ${timestamp} ${hostname} ${appName} - - ${structuredData} ${msgText}`;
}

function parseConfig(raw: unknown): Partial<SyslogConfig> {
  return (typeof raw === 'string' ? JSON.parse(raw) : raw ?? {}) as Partial<SyslogConfig>;
}

/** Send one event to one SIEM config. Throws on misconfiguration or transport errors. */
export async function sendEventToSiem(rawConfig: unknown, event: SiemAuditEvent): Promise<void> {
  const config = parseConfig(rawConfig);
  if (!config.host || !config.port) {
    throw new Error('SIEM integration config requires "host" and "port"');
  }
  const port = Number(config.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid SIEM port');
  const message = buildSyslogMessage(event, config);
  if ((config.protocol ?? 'udp') === 'udp') {
    await sendUdp(config.host, port, message);
  } else {
    await sendTcp(config.host, port, message);
  }
}

/**
 * Connectivity test for a single SIEM integration. Throws with the real error so the caller
 * can report failure (UDP can only detect local/DNS errors; TCP detects connection failures).
 */
export async function testSiemIntegration(integrationId: string, event: SiemAuditEvent): Promise<void> {
  const { rows } = await pool.query(`SELECT config FROM integrations WHERE id = $1 AND type = 'siem'`, [integrationId]);
  if (!rows[0]) throw new Error('SIEM integration not found');
  await sendEventToSiem(rows[0].config, event);
}

/**
 * Send a syslog message (RFC 5424 format) to every enabled SIEM collector.
 * Fire-and-forget — errors are logged but never block the caller.
 */
export async function forwardAuditToSiem(event: SiemAuditEvent): Promise<void> {
  try {
    // Find enabled SIEM integrations
    const { rows } = await pool.query(
      `SELECT config FROM integrations WHERE type = 'siem' AND enabled = true`
    );
    for (const row of rows) {
      const config = parseConfig(row.config);
      if (!config.host || !config.port) continue;
      try {
        await sendEventToSiem(config, event);
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
    const client = dgram.createSocket(net.isIPv6(host) ? 'udp6' : 'udp4');
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
      // TCP syslog with octet-counting framing (RFC 6587): MSG-LEN SP SYSLOG-MSG
      client.write(`${Buffer.byteLength(message, 'utf8')} ${message}`, () => {
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
