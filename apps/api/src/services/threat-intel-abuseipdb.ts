import { pool } from '../db/pool.js';

interface AbuseIPDBEntry {
  ipAddress: string;
  abuseConfidenceScore: number;
  countryCode?: string;
  totalReports?: number;
  lastReportedAt?: string;
}

/**
 * Sync threat intelligence from AbuseIPDB blacklist API.
 * Requires a free API key from https://www.abuseipdb.com/
 *
 * Integration config format:
 * {
 *   "apiKey": "your-abuseipdb-api-key",
 *   "confidenceMinimum": 90,
 *   "maxResults": 100,
 *   "expiryDays": 7,
 *   "autoBlock": false,
 *   "autoBlockPolicySetId": "uuid-of-policy-set"
 * }
 */
export async function syncAbuseIPDB(integrationId: string): Promise<{
  fetched: number;
  newEntries: number;
  updatedEntries: number;
  autoBlockedRules: number;
}> {
  const { rows } = await pool.query(
    `SELECT config FROM integrations WHERE id = $1 AND type = 'threat_intel' AND enabled = true`,
    [integrationId]
  );
  if (!rows[0]) throw new Error('Integration not found or not enabled');

  const config = typeof rows[0].config === 'string' ? JSON.parse(rows[0].config) : rows[0].config;
  if (!config.apiKey) {
    throw new Error('AbuseIPDB API key is required. Set it in config: {"apiKey": "your-key", "confidenceMinimum": 90}');
  }

  const confidenceMin = config.confidenceMinimum ?? 90;
  const maxResults = Math.min(config.maxResults ?? 100, 10000);
  const expiryDays = config.expiryDays ?? 7;

  // Call AbuseIPDB Blacklist API
  const url = `https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=${confidenceMin}&limit=${maxResults}`;
  const resp = await fetch(url, {
    headers: { 'Key': config.apiKey, 'Accept': 'application/json' },
  });

  if (!resp.ok) {
    const errorText = await resp.text().catch(() => '');
    throw new Error(`AbuseIPDB API returned ${resp.status}: ${errorText}`);
  }

  const data = await resp.json() as { data: AbuseIPDBEntry[] };
  const entries = data.data || [];
  const expiresAt = new Date(Date.now() + expiryDays * 24 * 60 * 60 * 1000);

  // Ensure unique index for upsert
  await pool.query(
    `CREATE UNIQUE INDEX IF NOT EXISTS idx_threat_intel_unique ON threat_intel_entries (integration_id, entry_type, value)`
  );

  let newEntries = 0;
  let updatedEntries = 0;

  for (const entry of entries) {
    const result = await pool.query(
      `INSERT INTO threat_intel_entries (integration_id, entry_type, value, threat_type, confidence, source_name, expires_at)
       VALUES ($1, 'ip', $2, $3, $4, 'AbuseIPDB', $5)
       ON CONFLICT (integration_id, entry_type, value)
         DO UPDATE SET confidence = EXCLUDED.confidence, expires_at = EXCLUDED.expires_at, threat_type = EXCLUDED.threat_type
       RETURNING (xmax = 0) as is_new`,
      [
        integrationId,
        entry.ipAddress,
        entry.countryCode ? `abuse (${entry.countryCode})` : 'abuse',
        entry.abuseConfidenceScore,
        expiresAt,
      ]
    );
    if (result.rows[0]?.is_new) newEntries++;
    else updatedEntries++;
  }

  // Update sync status
  await pool.query(
    `UPDATE integrations SET last_sync_at = now(), last_sync_status = 'synced' WHERE id = $1`,
    [integrationId]
  );

  await pool.query(
    `INSERT INTO integration_events (integration_id, direction, event_type, payload, status)
     VALUES ($1, 'inbound', 'threat_intel_sync', $2, 'SUCCESS')`,
    [integrationId, JSON.stringify({ fetched: entries.length, new: newEntries, updated: updatedEntries })]
  );

  // Auto-block if configured
  let autoBlockedRules = 0;
  if (config.autoBlock && config.autoBlockPolicySetId) {
    autoBlockedRules = await createAutoBlockRules(config.autoBlockPolicySetId, entries, integrationId);
  }

  return { fetched: entries.length, newEntries, updatedEntries, autoBlockedRules };
}

async function createAutoBlockRules(
  policySetId: string,
  entries: AbuseIPDBEntry[],
  integrationId: string
): Promise<number> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const { rows: latestV } = await client.query(
      `SELECT COALESCE(MAX(version_number), 0)::int AS v FROM policy_versions WHERE policy_set_id = $1`,
      [policySetId]
    );
    const nextVersion = (latestV[0]?.v ?? 0) + 1;

    const { rows: vRows } = await client.query(
      `INSERT INTO policy_versions (policy_set_id, version_number, status, change_summary, interface_scope_type)
       VALUES ($1, $2, 'DRAFT', $3, 'ALL_INTERFACES') RETURNING id`,
      [policySetId, nextVersion, `Auto-generated from AbuseIPDB threat intel (${entries.length} entries)`]
    );
    const versionId = vRows[0].id;

    const maxRules = 100;
    let ruleCount = 0;

    for (let i = 0; i < Math.min(entries.length, maxRules); i++) {
      const entry = entries[i];
      await client.query(
        `INSERT INTO policy_rules (policy_version_id, order_index, direction, action, protocol, ports, source_type, source_value, log_mode, comment)
         VALUES ($1, $2, 'IN', 'DENY', 'any', NULL, 'CIDR', $3, 'LOG', $4)`,
        [
          versionId, i,
          `${entry.ipAddress}/32`,
          `Threat Intel: AbuseIPDB confidence ${entry.abuseConfidenceScore}%${entry.countryCode ? ` (${entry.countryCode})` : ''}`,
        ]
      );
      ruleCount++;
    }

    await client.query(
      `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
       VALUES (NULL, 'THREAT_INTEL_AUTO_BLOCK', 'policy_version', $1, $2)`,
      [versionId, JSON.stringify({ integrationId, rulesCreated: ruleCount, source: 'AbuseIPDB' })]
    );

    await client.query('COMMIT');
    return ruleCount;
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}
