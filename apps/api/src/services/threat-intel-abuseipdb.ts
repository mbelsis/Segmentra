import net from 'node:net';

import { pool } from '../db/pool.js';
import { loadFullConfig } from './config-secrets.js';
import { createDraftVersion, insertRule, loadVersionRules, lockPolicySetAndGetBase } from './policy-version-clone.js';

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
export async function syncAbuseIPDB(integrationId: string, actorUserId?: string | null): Promise<{
  fetched: number;
  newEntries: number;
  updatedEntries: number;
  autoBlockedRules: number;
}> {
  const { rows } = await pool.query(
    `SELECT config, config_secret_id, created_by FROM integrations WHERE id = $1 AND type = 'threat_intel' AND enabled = true`,
    [integrationId]
  );
  if (!rows[0]) throw new Error('Integration not found or not enabled');

  // Full config (apiKey) is decrypted from secret_store.
  const config = await loadFullConfig(rows[0]);
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
    signal: AbortSignal.timeout(30000),
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
    autoBlockedRules = await createAutoBlockRules(
      config.autoBlockPolicySetId,
      entries,
      integrationId,
      actorUserId ?? rows[0].created_by ?? null
    );
  }

  return { fetched: entries.length, newEntries, updatedEntries, autoBlockedRules };
}

function normalizeBlockCidr(ip: string): string | null {
  const trimmed = String(ip ?? '').trim();
  const family = net.isIP(trimmed);
  if (family === 4) return `${trimmed}/32`;
  if (family === 6) return `${trimmed.toLowerCase()}/128`;
  return null;
}

function normalizeExistingCidr(value: string): string {
  const v = String(value ?? '').trim().toLowerCase();
  if (v.includes('/')) return v;
  const family = net.isIP(v);
  return family === 6 ? `${v}/128` : `${v}/32`;
}

const AUTO_BLOCK_SUMMARY_PREFIX = 'Auto-generated from AbuseIPDB threat intel';

/**
 * Create a new DRAFT version of the policy set that keeps every existing rule of the base
 * version (latest APPROVED/DEPLOYED, else latest) and prepends DENY rules for newly
 * reported IPs. IPs already blocked in the base version or in a newer version that is still
 * open (DRAFT / PENDING_APPROVAL) are not duplicated, and while an earlier auto-block draft is
 * still a DRAFT, new DENY rules are added to that draft instead of creating another version.
 */
async function createAutoBlockRules(
  policySetId: string,
  entries: AbuseIPDBEntry[],
  integrationId: string,
  actorUserId: string | null
): Promise<number> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const locked = await lockPolicySetAndGetBase(client, policySetId);
    if (!locked) throw new Error(`Auto-block policy set ${policySetId} not found`);
    const { base, nextVersionNumber } = locked;

    const existingRules = base ? await loadVersionRules(client, base.id) : [];
    const isInboundCidrDeny = (r: any) => r.action === 'DENY' && r.source_type === 'CIDR' && (r.direction ?? 'IN') !== 'OUT';
    const alreadyBlocked = new Set(existingRules.filter(isInboundCidrDeny).map((r) => normalizeExistingCidr(r.source_value)));

    // Versions newer than the base that are not approved yet (e.g. the draft from the last sync)
    const { rows: openVersions } = await client.query(
      `SELECT id, status, change_summary FROM policy_versions
        WHERE policy_set_id = $1 AND status IN ('DRAFT', 'PENDING_APPROVAL') AND version_number > $2
        ORDER BY version_number DESC`,
      [policySetId, base?.version_number ?? 0]
    );
    for (const v of openVersions) {
      for (const r of await loadVersionRules(client, v.id)) {
        if (isInboundCidrDeny(r)) alreadyBlocked.add(normalizeExistingCidr(r.source_value));
      }
    }
    const reusableDraft = openVersions.find(
      (v: any) => v.status === 'DRAFT' && String(v.change_summary ?? '').startsWith(AUTO_BLOCK_SUMMARY_PREFIX)
    );

    const maxRules = 100;
    const newRules: Array<{ cidr: string; entry: AbuseIPDBEntry }> = [];
    for (const entry of entries) {
      if (newRules.length >= maxRules) break;
      const cidr = normalizeBlockCidr(entry.ipAddress);
      if (!cidr || alreadyBlocked.has(cidr)) continue;
      alreadyBlocked.add(cidr);
      newRules.push({ cidr, entry });
    }

    if (newRules.length === 0) {
      await client.query('ROLLBACK');
      return 0;
    }

    let versionId: string;
    if (reusableDraft) {
      // Add to the still-open auto-block draft: shift its rules down, new DENY rules go on top.
      versionId = reusableDraft.id;
      await client.query(
        `UPDATE policy_rules SET order_index = order_index + $2 WHERE policy_version_id = $1`,
        [versionId, newRules.length]
      );
      await client.query(
        `UPDATE policy_versions SET change_summary = $2 WHERE id = $1`,
        [versionId, `${reusableDraft.change_summary}; +${newRules.length} DENY rules (${new Date().toISOString()})`]
      );
    } else {
      versionId = await createDraftVersion(client, {
        policySetId,
        versionNumber: nextVersionNumber,
        base,
        changeSummary: `${AUTO_BLOCK_SUMMARY_PREFIX}: ${newRules.length} new DENY rules prepended to v${base?.version_number ?? 0}`,
        createdBy: actorUserId,
      });
    }

    let orderIndex = 0;
    for (const { cidr, entry } of newRules) {
      await insertRule(client, versionId, orderIndex++, {
        direction: 'IN',
        action: 'DENY',
        protocol: 'any',
        ports: null,
        source_type: 'CIDR',
        source_value: cidr,
        log_mode: 'LOG',
        comment: `Threat Intel: AbuseIPDB confidence ${entry.abuseConfidenceScore}%${entry.countryCode ? ` (${entry.countryCode})` : ''}`,
      });
    }
    // New draft: keep all existing rules (all columns), shifted after the new DENY rules, preserving order.
    if (!reusableDraft) {
      for (const r of existingRules) {
        await insertRule(client, versionId, orderIndex++, r);
      }
    }

    await client.query(
      `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
       VALUES ($1, 'THREAT_INTEL_AUTO_BLOCK', 'policy_version', $2, $3)`,
      [
        actorUserId,
        versionId,
        JSON.stringify({
          integrationId,
          rulesCreated: newRules.length,
          rulesCarriedOver: reusableDraft ? 0 : existingRules.length,
          addedToExistingDraft: Boolean(reusableDraft),
          baseVersionId: base?.id ?? null,
          source: 'AbuseIPDB',
        }),
      ]
    );

    await client.query('COMMIT');
    return newRules.length;
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }
}
