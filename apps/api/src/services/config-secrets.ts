/**
 * Encrypted storage for integration and notification-channel configuration.
 *
 * The whole config object (API keys, webhook URLs with tokens, auth headers, custom headers...)
 * is stored encrypted in secret_store (AES-256-GCM, see crypto.ts) and referenced by
 * integrations.config_secret_id / notification_channels.config_secret_id. The plain `config`
 * jsonb column only holds a MASKED copy, used for display; it is never read to talk to an
 * external system. Rows created before migration 031 are encrypted once at startup by
 * migratePlaintextConfigs().
 */
import type { PoolClient } from 'pg';

import { pool } from '../db/pool.js';
import { decryptBlob, encryptBlob } from './crypto.js';
import { MASK_PREFIX, maskConfigSecrets, maskUrlSecrets, mergeConfigSecrets } from './secret-mask.js';

export type ConfigKind = 'integration' | 'notification_channel';

const SECRET_TYPE: Record<ConfigKind, string> = {
  integration: 'INTEGRATION_CONFIG',
  notification_channel: 'NOTIFICATION_CONFIG',
};
const TABLE: Record<ConfigKind, string> = {
  integration: 'integrations',
  notification_channel: 'notification_channels',
};

type Queryable = Pick<PoolClient, 'query'>;

export function parseConfigValue(raw: unknown): Record<string, any> {
  if (!raw) return {};
  if (typeof raw === 'string') {
    try {
      const v = JSON.parse(raw);
      return v && typeof v === 'object' && !Array.isArray(v) ? v : {};
    } catch {
      return {};
    }
  }
  return typeof raw === 'object' && !Array.isArray(raw) ? (raw as Record<string, any>) : {};
}

// ---- Masking (display copies) --------------------------------------------------------------

const CHANNEL_URL_KEYS = ['url', 'webhookUrl'] as const;

/** Display copy of an integration config: sensitive keys masked. */
export function maskIntegrationConfig(config: unknown): Record<string, any> {
  return maskConfigSecrets(parseConfigValue(config));
}

/** Display copy of a channel config: authHeader/tokens, secrets in webhook URLs and custom header values masked. */
export function maskChannelConfig(config: unknown): Record<string, any> {
  const c = maskConfigSecrets(parseConfigValue(config));
  for (const k of CHANNEL_URL_KEYS) {
    if (typeof c[k] === 'string') c[k] = maskUrlSecrets(c[k]);
  }
  if (c.customHeaders && typeof c.customHeaders === 'object') {
    c.customHeaders = Object.fromEntries(
      Object.entries(c.customHeaders).map(([k, v]) => [k, typeof v === 'string' && v.length > 0 && !v.startsWith(MASK_PREFIX) ? `${MASK_PREFIX}${v.slice(-4)}` : v])
    );
  }
  return c;
}

export function maskConfigFor(kind: ConfigKind, config: unknown): Record<string, any> {
  return kind === 'integration' ? maskIntegrationConfig(config) : maskChannelConfig(config);
}

/**
 * Apply an incoming channel config on top of the stored (decrypted) one: masked/omitted secrets
 * keep their value, a URL equal to the masked form of the stored URL keeps the stored URL, and a
 * masked custom header value keeps the stored header value.
 */
export function mergeChannelConfig(existing: Record<string, any>, incoming: Record<string, any>): Record<string, any> {
  const merged = mergeConfigSecrets(existing, incoming) as Record<string, any>;
  for (const k of CHANNEL_URL_KEYS) {
    if (typeof incoming[k] === 'string' && typeof existing[k] === 'string' && incoming[k] !== existing[k]
        && incoming[k] === maskUrlSecrets(existing[k])) {
      merged[k] = existing[k];
    }
  }
  if (incoming.customHeaders && typeof incoming.customHeaders === 'object') {
    const prev = existing.customHeaders && typeof existing.customHeaders === 'object' ? existing.customHeaders : {};
    merged.customHeaders = Object.fromEntries(
      Object.entries(incoming.customHeaders)
        .map(([k, v]) => (typeof v === 'string' && v.startsWith(MASK_PREFIX)
          ? (prev[k] !== undefined ? [k, prev[k]] : null)
          : [k, v]))
        .filter((e): e is [string, unknown] => e !== null)
    );
  }
  return merged;
}

export function mergeIntegrationConfig(existing: Record<string, any>, incoming: Record<string, any>): Record<string, any> {
  return mergeConfigSecrets(existing, incoming) as Record<string, any>;
}

// ---- Encrypted storage ---------------------------------------------------------------------

/** Decrypt the full config of a row. Falls back to the plain column only for not-yet-migrated rows. */
export async function loadFullConfig(row: { config?: unknown; config_secret_id?: string | null }): Promise<Record<string, any>> {
  if (!row.config_secret_id) return parseConfigValue(row.config);
  const { rows } = await pool.query(`SELECT encrypted_blob FROM secret_store WHERE id = $1`, [row.config_secret_id]);
  if (!rows[0]) throw new Error('Encrypted configuration not found (secret_store row missing); re-enter the configuration');
  return parseConfigValue(decryptBlob(rows[0].encrypted_blob as Buffer).toString('utf8'));
}

/**
 * Encrypt a full config. Updates the existing secret_store row in place when secretId is given,
 * otherwise creates one. Returns the secret id and the masked display copy for the `config` column.
 */
export async function storeFullConfig(
  kind: ConfigKind,
  name: string,
  config: Record<string, any>,
  secretId: string | null | undefined,
  db: Queryable = pool
): Promise<{ secretId: string; displayConfig: Record<string, any> }> {
  const blob = encryptBlob(Buffer.from(JSON.stringify(config ?? {}), 'utf8'));
  if (secretId) {
    const { rowCount } = await db.query(
      `UPDATE secret_store SET encrypted_blob = $2, rotated_at = now(), is_active = true WHERE id = $1`,
      [secretId, blob]
    );
    if (rowCount) return { secretId, displayConfig: maskConfigFor(kind, config) };
  }
  const { rows } = await db.query(
    `INSERT INTO secret_store (name, type, encrypted_blob) VALUES ($1, $2, $3) RETURNING id`,
    [`${kind}:${name}`.slice(0, 200), SECRET_TYPE[kind], blob]
  );
  return { secretId: rows[0].id, displayConfig: maskConfigFor(kind, config) };
}

export async function deleteConfigSecret(secretId: string | null | undefined): Promise<void> {
  if (!secretId) return;
  await pool.query(`DELETE FROM secret_store WHERE id = $1 AND type IN ('INTEGRATION_CONFIG', 'NOTIFICATION_CONFIG')`, [secretId]);
}

/**
 * One-time, idempotent startup migration: encrypt plaintext configs left by versions before
 * migration 031 (rows with config_secret_id IS NULL and a non-empty config) and replace the
 * plain column with the masked copy. Safe with several API replicas (row lock + SKIP LOCKED).
 */
export async function migratePlaintextConfigs(): Promise<{ integrations: number; channels: number }> {
  const result = { integrations: 0, channels: 0 };
  for (const kind of ['integration', 'notification_channel'] as ConfigKind[]) {
    const table = TABLE[kind];
    for (;;) {
      const client = await pool.connect();
      let migrated = false;
      try {
        await client.query('BEGIN');
        const { rows } = await client.query(
          `SELECT id, name, config FROM ${table}
            WHERE config_secret_id IS NULL AND config IS NOT NULL AND config <> '{}'::jsonb AND config <> 'null'::jsonb
            LIMIT 1 FOR UPDATE SKIP LOCKED`
        );
        if (!rows[0]) {
          await client.query('COMMIT');
          break;
        }
        const full = parseConfigValue(rows[0].config);
        const { secretId, displayConfig } = await storeFullConfig(kind, rows[0].name, full, null, client);
        await client.query(`UPDATE ${table} SET config = $2::jsonb, config_secret_id = $3 WHERE id = $1`, [
          rows[0].id, JSON.stringify(displayConfig), secretId,
        ]);
        await client.query('COMMIT');
        migrated = true;
      } catch (e) {
        await client.query('ROLLBACK').catch(() => {});
        throw e;
      } finally {
        client.release();
      }
      if (migrated) {
        if (kind === 'integration') result.integrations++;
        else result.channels++;
      }
    }
  }
  return result;
}
