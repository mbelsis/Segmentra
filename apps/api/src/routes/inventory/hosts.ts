import { Router } from 'express';
import { z } from 'zod';

import { pool } from '../../db/pool.js';
import { requireAuth, requireRole } from '../../middleware/auth.js';
import { isValidIp } from '../../services/ip-utils.js';
import { effectiveCredentialsForHosts } from '../../services/ssh-credentials.js';
import { evaluateHostAgainstRules } from '../../services/tag-rule-engine.js';
import { triggerTemplateAutoApply } from '../../services/template-engine.js';
import { countRuleReferences } from '../../lib/rule-references.js';

/** Re-run tag rules for a host after attributes changed; never fails the request. */
function reevaluateHostTags(hostId: string) {
  void evaluateHostAgainstRules(hostId).catch((e) => {
    // eslint-disable-next-line no-console
    console.error(`[Hosts] Tag rule re-evaluation for host ${hostId} failed:`, e);
  });
}

/** Hosts referenced by deployment history cannot be deleted (deployment_hosts FK has no cascade). */
async function hostsWithDeploymentHistory(hostIds: string[]): Promise<Array<{ id: string; hostname: string }>> {
  const { rows } = await pool.query(
    `SELECT DISTINCT h.id, h.hostname FROM deployment_hosts dh JOIN hosts h ON h.id = dh.host_id
      WHERE dh.host_id = ANY($1::uuid[]) ORDER BY h.hostname`,
    [hostIds]
  );
  return rows;
}

/** Attach `effective_credential` (non-secret summary, or null) to host objects, in one query. */
async function withEffectiveCredentials<T extends { id: string }>(hosts: T[]): Promise<Array<T & { effective_credential: any }>> {
  const map = await effectiveCredentialsForHosts(hosts.map((h) => String(h.id)));
  return hosts.map((h) => ({ ...h, effective_credential: map.get(String(h.id)) ?? null }));
}

/**
 * Validate an explicit SSH credential assignment (hosts.ssh_credential_id). Only admins may
 * change it (credentials are admin-managed); null clears it. Returns an error response or null.
 */
async function credentialAssignmentProblem(req: any, body: any, value: string | null | undefined): Promise<{ status: number; body: any } | null> {
  if (!Object.prototype.hasOwnProperty.call(body ?? {}, 'sshCredentialId')) return null;
  if (!req.auth?.roles?.includes('admin')) {
    return { status: 403, body: { error: 'forbidden', message: 'Only admins can change the SSH credential assigned to a host.' } };
  }
  if (value) {
    const { rows } = await pool.query(`SELECT 1 FROM ssh_credentials WHERE id = $1`, [value]);
    if (!rows[0]) return { status: 400, body: { error: 'ssh_credential_not_found', message: 'The selected SSH credential does not exist.' } };
  }
  return null;
}

export const hostsRouter = Router();

// Apply authentication to all routes
hostsRouter.use(requireAuth);

// GET endpoints are read-only and accessible to viewers
hostsRouter.get('/', requireRole('viewer', 'operator', 'approver', 'admin'), async (req, res) => {
  const hostname = String(req.query.hostname ?? '');
  const tag = String(req.query.tag ?? '');
  const vlan = String(req.query.vlan ?? '');
  const ip = String(req.query.ip ?? '');
  const env = String(req.query.env ?? '');
  const backend = String(req.query.backend ?? '');
  const enabled = req.query.enabled !== undefined ? req.query.enabled === 'true' || req.query.enabled === '1' : undefined;
  const parsedPage = parseInt(String(req.query.page ?? '1'), 10);
  const parsedLimit = parseInt(String(req.query.limit ?? '50'), 10);
  const limit = Math.min(1000, Math.max(1, Number.isFinite(parsedLimit) ? parsedLimit : 50));
  const page = Math.max(1, Number.isFinite(parsedPage) ? parsedPage : 1);
  const offset = (page - 1) * limit;

  const where: string[] = [];
  const params: any[] = [];

  if (hostname) {
    params.push(`%${hostname}%`);
    where.push(`h.hostname ILIKE $${params.length}`);
  }
  if (ip) {
    params.push(`%${ip}%`);
    where.push(`(h.mgmt_ip::text ILIKE $${params.length} OR h.hostname ILIKE $${params.length})`);
  }
  if (env) {
    params.push(env);
    where.push(`h.environment = $${params.length}`);
  }
  if (backend) {
    params.push(backend);
    where.push(`h.firewall_backend = $${params.length}`);
  }
  if (vlan) {
    params.push(vlan);
    where.push(`v.vlan_tag::text = $${params.length}`);
  }
  if (tag) {
    params.push(tag);
    where.push(`t.name = $${params.length}`);
  }
  if (enabled !== undefined) {
    params.push(enabled);
    where.push(`h.enabled = $${params.length}`);
  }

  const whereClause = where.length > 0 ? `WHERE ${where.join(' AND ')}` : '';

  // Get total count
  const countSql = `
    SELECT COUNT(DISTINCT h.id) as total
    FROM hosts h
    LEFT JOIN vlans v ON v.id = h.vlan_id
    LEFT JOIN host_tags ht ON ht.host_id = h.id
    LEFT JOIN tags t ON t.id = ht.tag_id
    ${whereClause}
  `;
  const countResult = await pool.query(countSql, params);
  const total = parseInt(countResult.rows[0].total, 10);

  // Get paginated hosts
  const sql = `
    SELECT DISTINCT h.*, v.vlan_tag, v.name as vlan_name
    FROM hosts h
    LEFT JOIN vlans v ON v.id = h.vlan_id
    LEFT JOIN host_tags ht ON ht.host_id = h.id
    LEFT JOIN tags t ON t.id = ht.tag_id
    ${whereClause}
    ORDER BY h.hostname ASC
    LIMIT $${params.length + 1} OFFSET $${params.length + 2}
  `;

  const { rows } = await pool.query(sql, [...params, limit, offset]);
  
  // Group hosts and collect their tags
  const hostMap = new Map();
  for (const row of rows) {
    if (!hostMap.has(row.id)) {
      hostMap.set(row.id, {
        ...row,
        tags: []
      });
    }
  }
  
  // Get tags for all hosts
  const hostIds = Array.from(hostMap.keys());
  if (hostIds.length > 0) {
    const tagRows = await pool.query(
      `SELECT ht.host_id, t.id, t.name, ht.source, ht.source_rule_id
       FROM host_tags ht
       JOIN tags t ON t.id = ht.tag_id
       WHERE ht.host_id = ANY($1::uuid[])
       ORDER BY t.name`,
      [hostIds]
    );
    for (const tagRow of tagRows.rows) {
      const host = hostMap.get(tagRow.host_id);
      if (host) {
        host.tags.push({ id: tagRow.id, name: tagRow.name, source: tagRow.source, sourceRuleId: tagRow.source_rule_id });
      }
    }
  }
  
  res.json({ 
    hosts: await withEffectiveCredentials(Array.from(hostMap.values())),
    pagination: {
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit)
    }
  });
});

const createHostSchema = z.object({
  hostname: z.string().min(1).max(255).regex(/^[a-zA-Z0-9._-]+$/, 'Hostname can only contain letters, numbers, dots, hyphens, and underscores'),
  mgmtIp: z
    .string()
    .trim()
    .optional()
    .refine((v) => v === undefined || v === '' || isValidIp(v), { message: 'mgmtIp must be a valid IPv4 or IPv6 address' }),
  sshPort: z.number().int().min(1).max(65535).optional(),
  environment: z.string().optional(),
  osFamily: z.string().optional(),
  firewallBackend: z.enum(['nftables', 'iptables', 'firewalld', 'ufw', 'auto']).optional(),
  vlanId: z.string().uuid().nullable().optional(),
  tagIds: z.array(z.string().uuid()).optional().default([]),
  enabled: z.boolean().optional(),
  /** Explicit SSH credential (admin only); null/omitted = automatic (by credential scope). */
  sshCredentialId: z.string().uuid().nullable().optional()
});

// Write operations require operator/admin
hostsRouter.post('/', requireRole('operator', 'admin'), async (req, res) => {
  const parsed = createHostSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body', details: parsed.error.issues });
  const b = parsed.data;
  const credProblem = await credentialAssignmentProblem(req, req.body, b.sshCredentialId);
  if (credProblem) return res.status(credProblem.status).json(credProblem.body);

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    
    const { rows } = await client.query(
      `INSERT INTO hosts (hostname, mgmt_ip, ssh_port, environment, os_family, firewall_backend, vlan_id, enabled, ssh_credential_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
       RETURNING *`,
      [
        b.hostname,
        b.mgmtIp || null,
        b.sshPort ?? 22,
        b.environment ?? null,
        b.osFamily ?? null,
        b.firewallBackend ?? 'auto',
        b.vlanId ?? null,
        b.enabled ?? true,
        b.sshCredentialId ?? null
      ]
    );
    const host = rows[0];
    
    // Add tags
    if (b.tagIds && b.tagIds.length > 0) {
      for (const tagId of b.tagIds) {
        await client.query(
          `INSERT INTO host_tags (host_id, tag_id, source) VALUES ($1, $2, 'manual') ON CONFLICT DO NOTHING`,
          [host.id, tagId]
        );
      }
    }
    
    await client.query('COMMIT');
    triggerTemplateAutoApply(b.tagIds ?? []);
    reevaluateHostTags(host.id);
    
    // Fetch host with tags and VLAN
    const hostWithTags = await client.query(
      `SELECT h.*, v.vlan_tag, v.name as vlan_name
       FROM hosts h
       LEFT JOIN vlans v ON v.id = h.vlan_id
       WHERE h.id = $1`,
      [host.id]
    );
    const tagRows = await client.query(
      `SELECT t.id, t.name FROM host_tags ht JOIN tags t ON t.id = ht.tag_id WHERE ht.host_id = $1`,
      [host.id]
    );
    
    await pool.query(
      `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
       VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), $2, $3, $4, $5)`,
      [req.auth!.username, 'HOST_CREATE', 'host', host.id, JSON.stringify({ hostname: b.hostname })]
    );

    const [hostOut] = await withEffectiveCredentials([{ ...hostWithTags.rows[0], tags: tagRows.rows }]);
    res.status(201).json({ host: hostOut });
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
});

hostsRouter.get('/:id', requireRole('viewer', 'operator', 'approver', 'admin'), async (req, res) => {
  const { rows } = await pool.query(
    `SELECT h.*, v.vlan_tag, v.name as vlan_name
     FROM hosts h
     LEFT JOIN vlans v ON v.id = h.vlan_id
     WHERE h.id=$1`,
    [req.params.id]
  );
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });
  
  const tagRows = await pool.query(
    `SELECT t.id, t.name, ht.source, ht.source_rule_id AS "sourceRuleId"
       FROM host_tags ht JOIN tags t ON t.id = ht.tag_id WHERE ht.host_id = $1 ORDER BY t.name`,
    [req.params.id]
  );
  
  const [hostOut] = await withEffectiveCredentials([{ ...rows[0], tags: tagRows.rows }]);
  res.json({ host: hostOut });
});

const updateHostSchema = createHostSchema.partial();

hostsRouter.put('/:id', requireRole('operator', 'admin'), async (req, res) => {
  const parsed = updateHostSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body', details: parsed.error.issues });
  const b = parsed.data;
  // vlanId: null explicitly clears the VLAN; omitting it keeps the current value.
  const clearVlan = Object.prototype.hasOwnProperty.call(req.body ?? {}, 'vlanId') && b.vlanId === null;
  // sshCredentialId: present (uuid or null) = set/clear the explicit assignment (admin only).
  const setCredential = Object.prototype.hasOwnProperty.call(req.body ?? {}, 'sshCredentialId');
  const credProblem = await credentialAssignmentProblem(req, req.body, b.sshCredentialId);
  if (credProblem) return res.status(credProblem.status).json(credProblem.body);

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    
    const { rows } = await client.query(
      `UPDATE hosts
       SET hostname = COALESCE($2, hostname),
           mgmt_ip = COALESCE($3, mgmt_ip),
           ssh_port = COALESCE($4, ssh_port),
           environment = COALESCE($5, environment),
           os_family = COALESCE($6, os_family),
           firewall_backend = COALESCE($7, firewall_backend),
           vlan_id = CASE WHEN $10::boolean THEN NULL ELSE COALESCE($8, vlan_id) END,
           enabled = COALESCE($9, enabled),
           ssh_credential_id = CASE WHEN $11::boolean THEN $12::uuid ELSE ssh_credential_id END,
           updated_at = now()
       WHERE id=$1
       RETURNING *`,
      [
        req.params.id,
        b.hostname ?? null,
        b.mgmtIp || null,
        b.sshPort ?? null,
        b.environment ?? null,
        b.osFamily ?? null,
        b.firewallBackend ?? null,
        b.vlanId ?? null,
        typeof b.enabled === 'boolean' ? b.enabled : null,
        clearVlan,
        setCredential,
        b.sshCredentialId ?? null
      ]
    );
    if (!rows[0]) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'not_found' });
    }
    
    // Update tags if provided. tagIds is the desired set of MANUAL tags: rule-assigned tags
    // (source='rule') are managed by tag rules and are left untouched, including their source.
    if (b.tagIds !== undefined) {
      await client.query(
        `DELETE FROM host_tags WHERE host_id = $1 AND source <> 'rule' AND NOT (tag_id = ANY($2::uuid[]))`,
        [req.params.id, b.tagIds]
      );
      for (const tagId of b.tagIds) {
        await client.query(
          `INSERT INTO host_tags (host_id, tag_id, source) VALUES ($1, $2, 'manual') ON CONFLICT (host_id, tag_id) DO NOTHING`,
          [req.params.id, tagId]
        );
      }
    }
    
    await client.query('COMMIT');
    triggerTemplateAutoApply(b.tagIds ?? []);
    reevaluateHostTags(req.params.id);
    
    // Fetch updated host with tags and VLAN
    const hostWithTags = await client.query(
      `SELECT h.*, v.vlan_tag, v.name as vlan_name
       FROM hosts h
       LEFT JOIN vlans v ON v.id = h.vlan_id
       WHERE h.id = $1`,
      [req.params.id]
    );
    const tagRows = await client.query(
      `SELECT t.id, t.name, ht.source, ht.source_rule_id AS "sourceRuleId"
         FROM host_tags ht JOIN tags t ON t.id = ht.tag_id WHERE ht.host_id = $1 ORDER BY t.name`,
      [req.params.id]
    );
    
    await pool.query(
      `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
       VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), $2, $3, $4, $5)`,
      [req.auth!.username, 'HOST_UPDATE', 'host', req.params.id, JSON.stringify({ hostname: rows[0].hostname, changes: b })]
    );

    const [hostOut] = await withEffectiveCredentials([{ ...hostWithTags.rows[0], tags: tagRows.rows }]);
    res.json({ host: hostOut });
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
});

hostsRouter.delete('/:id', requireRole('operator', 'admin'), async (req, res) => {
  const referenced = await hostsWithDeploymentHistory([req.params.id]);
  if (referenced.length > 0) {
    return res.status(409).json({
      error: 'host_has_deployment_history',
      message: 'This host has deployment history and cannot be deleted. Disable it instead.'
    });
  }
  // Rules reference hosts by id without a foreign key: deleting a referenced host would turn
  // those rules into rules matching nothing (an ALLOW stops allowing, a DENY stops denying).
  const refs = await countRuleReferences('HOST', req.params.id);
  if (refs.total > 0) {
    return res.status(409).json({
      error: 'host_in_use',
      message: `This host is used as a source or destination by ${refs.policyRules} policy rule(s) and ${refs.templateRules} template rule(s). Change those rules first, or disable the host.`,
      usage: refs
    });
  }
  let rowCount: number | null;
  try {
    ({ rowCount } = await pool.query(`DELETE FROM hosts WHERE id=$1`, [req.params.id]));
  } catch (e: any) {
    if (e?.code === '23503') {
      return res.status(409).json({ error: 'host_in_use', message: 'This host is still referenced by other records.' });
    }
    throw e;
  }
  if (!rowCount) return res.status(404).json({ error: 'not_found' });

  await pool.query(
    `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), $2, $3, $4, $5)`,
    [req.auth!.username, 'HOST_DELETE', 'host', req.params.id, JSON.stringify({ hostId: req.params.id })]
  );

  res.json({ ok: true });
});

// Bulk operations
const bulkOperationSchema = z.object({
  hostIds: z.array(z.string().uuid()).min(1)
});

hostsRouter.post('/bulk/delete', requireRole('operator', 'admin'), async (req, res) => {
  const parsed = bulkOperationSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });

  const referenced = await hostsWithDeploymentHistory(parsed.data.hostIds);
  if (referenced.length > 0) {
    return res.status(409).json({
      error: 'host_has_deployment_history',
      message: `${referenced.length} host(s) have deployment history and cannot be deleted. Disable them instead.`,
      hosts: referenced
    });
  }
  const inRules: string[] = [];
  for (const id of parsed.data.hostIds) {
    if ((await countRuleReferences('HOST', id)).total > 0) inRules.push(id);
  }
  if (inRules.length > 0) {
    return res.status(409).json({
      error: 'host_in_use',
      message: `${inRules.length} host(s) are used as a source or destination in policy or template rules and cannot be deleted. Change those rules first, or disable the hosts.`,
      hostIds: inRules
    });
  }

  let rowCount: number | null;
  try {
    ({ rowCount } = await pool.query(`DELETE FROM hosts WHERE id = ANY($1::uuid[])`, [parsed.data.hostIds]));
  } catch (e: any) {
    if (e?.code === '23503') {
      return res.status(409).json({ error: 'host_in_use', message: 'One or more hosts are still referenced by other records.' });
    }
    throw e;
  }

  await pool.query(
    `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), $2, $3, uuid_generate_v4(), $4)`,
    [req.auth!.username, 'HOST_BULK_DELETE', 'host', JSON.stringify({ count: rowCount, hostIds: parsed.data.hostIds })]
  );

  res.json({ ok: true, deleted: rowCount });
});

hostsRouter.post('/bulk/assign-vlan', requireRole('operator', 'admin'), async (req, res) => {
  const parsed = bulkOperationSchema.extend({
    vlanId: z.string().uuid().nullable()
  }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });
  
  const { rowCount } = await pool.query(
    `UPDATE hosts SET vlan_id = $1, updated_at = now() WHERE id = ANY($2::uuid[])`,
    [parsed.data.vlanId, parsed.data.hostIds]
  );

  await pool.query(
    `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), $2, $3, uuid_generate_v4(), $4)`,
    [req.auth!.username, 'HOST_BULK_ASSIGN_VLAN', 'host', JSON.stringify({ count: rowCount, vlanId: parsed.data.vlanId })]
  );

  res.json({ ok: true, updated: rowCount });
});

hostsRouter.post('/bulk/assign-tag', requireRole('operator', 'admin'), async (req, res) => {
  const parsed = bulkOperationSchema.extend({
    tagId: z.string().uuid()
  }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });
  
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    let added = 0;
    for (const hostId of parsed.data.hostIds) {
      const result = await client.query(
        `INSERT INTO host_tags (host_id, tag_id, source) VALUES ($1, $2, 'manual') ON CONFLICT DO NOTHING`,
        [hostId, parsed.data.tagId]
      );
      if (result.rowCount) added++;
    }
    await client.query('COMMIT');
    triggerTemplateAutoApply([parsed.data.tagId]);

    await pool.query(
      `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
       VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), $2, $3, uuid_generate_v4(), $4)`,
      [req.auth!.username, 'HOST_BULK_ASSIGN_TAG', 'host', JSON.stringify({ count: added, tagId: parsed.data.tagId })]
    );

    res.json({ ok: true, added });
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
});

hostsRouter.post('/bulk/import', requireRole('operator', 'admin'), async (req, res) => {
  const body = z.object({
    csvData: z.string().min(1)
  }).safeParse(req.body);
  if (!body.success) return res.status(400).json({ error: 'invalid_body' });

  // Parse CSV (simple parser - handles quoted fields)
  function parseCSV(csvText: string): string[][] {
    const lines: string[][] = [];
    const rows = csvText.split(/\r?\n/).filter(line => line.trim());
    
    for (const line of rows) {
      const fields: string[] = [];
      let current = '';
      let inQuotes = false;
      
      for (let i = 0; i < line.length; i++) {
        const char = line[i];
        if (char === '"') {
          if (inQuotes && line[i + 1] === '"') {
            current += '"';
            i++;
          } else {
            inQuotes = !inQuotes;
          }
        } else if (char === ',' && !inQuotes) {
          fields.push(current.trim());
          current = '';
        } else {
          current += char;
        }
      }
      fields.push(current.trim());
      lines.push(fields);
    }
    return lines;
  }

  const rows = parseCSV(body.data.csvData);
  if (rows.length < 2) {
    return res.status(400).json({ error: 'csv_too_short', message: 'CSV must have at least a header row and one data row' });
  }

  const header = rows[0].map(h => h.toLowerCase().trim());
  const dataRows = rows.slice(1);

  // Expected columns (flexible - can have different names)
  const hostnameIdx = header.findIndex(h => h.includes('hostname') || h.includes('host'));
  const ipIdx = header.findIndex(h => h.includes('ip') || h.includes('mgmt') || h.includes('management'));
  const sshPortIdx = header.findIndex(h => h.includes('ssh') && h.includes('port'));
  const vlanIdx = header.findIndex(h => h.includes('vlan'));
  const tagIdx = header.findIndex(h => h.includes('tag'));
  const backendIdx = header.findIndex(h => h.includes('backend') || h.includes('firewall'));
  const enabledIdx = header.findIndex(h => h.includes('enabled'));

  if (hostnameIdx === -1) {
    return res.status(400).json({ error: 'missing_hostname_column', message: 'CSV must have a hostname column' });
  }

  const results: Array<{ row: number; hostname: string; success: boolean; error?: string; warnings?: string[] }> = [];

  const importedTagIds: string[] = [];
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    // Get all VLANs and tags for lookup
    const vlanRes = await client.query(`SELECT id, name, vlan_tag FROM vlans`);
    const tagRes = await client.query(`SELECT id, name FROM tags`);
    const vlanMap = new Map<string, string>(); // name -> id
    const vlanTagMap = new Map<string, string>(); // tag number -> id
    for (const v of vlanRes.rows) {
      vlanMap.set(v.name.toLowerCase(), v.id);
      vlanTagMap.set(String(v.vlan_tag), v.id);
    }
    const tagMap = new Map<string, string>(); // name -> id
    for (const t of tagRes.rows) {
      tagMap.set(t.name.toLowerCase(), t.id);
    }

    for (let i = 0; i < dataRows.length; i++) {
      const rowNumber = i + 2;
      const row = dataRows[i];
      const hostname = row[hostnameIdx]?.trim();
      const fail = (error: string) => results.push({ row: rowNumber, hostname: hostname || `Row ${rowNumber}`, success: false, error });

      if (!hostname) {
        fail('Missing hostname');
        continue;
      }

      // Validate hostname format (same as single host creation)
      if (!/^[a-zA-Z0-9._-]+$/.test(hostname) || hostname.length > 255) {
        fail('Invalid hostname. Only letters, numbers, dots, hyphens, and underscores allowed (max 255 chars).');
        continue;
      }

      // ---- Validate the whole row before touching the database ----
      const mgmtIp = ipIdx >= 0 ? row[ipIdx]?.trim() || null : null;
      if (mgmtIp && !isValidIp(mgmtIp)) {
        fail(`Invalid management IP: ${mgmtIp}`);
        continue;
      }

      const sshPortRaw = sshPortIdx >= 0 ? row[sshPortIdx]?.trim() ?? '' : '';
      const sshPort = sshPortRaw ? Number(sshPortRaw) : 22;
      if ((sshPortRaw && !/^\d+$/.test(sshPortRaw)) || !Number.isInteger(sshPort) || sshPort < 1 || sshPort > 65535) {
        fail(`Invalid SSH port: ${sshPortRaw}`);
        continue;
      }

      let vlanId: string | null = null;
      if (vlanIdx >= 0 && row[vlanIdx]?.trim()) {
        const vlanValue = row[vlanIdx].trim();
        vlanId = vlanMap.get(vlanValue.toLowerCase()) || vlanTagMap.get(vlanValue) || null;
        if (!vlanId) {
          fail(`VLAN not found: ${vlanValue}`);
          continue;
        }
      }

      const tagIds: string[] = [];
      const missingTags: string[] = [];
      if (tagIdx >= 0 && row[tagIdx]?.trim()) {
        // Tags may be separated by ';' or '|' (or ',' inside a quoted field)
        const tagValues = row[tagIdx].split(/[,;|]/).map(t => t.trim()).filter(Boolean);
        for (const tagValue of tagValues) {
          const tagId = tagMap.get(tagValue.toLowerCase());
          if (tagId) tagIds.push(tagId);
          else missingTags.push(tagValue);
        }
      }

      const firewallBackend = backendIdx >= 0 ? (row[backendIdx]?.trim().toLowerCase() || 'auto') : 'auto';
      if (!['nftables', 'iptables', 'firewalld', 'ufw', 'auto'].includes(firewallBackend)) {
        fail(`Invalid firewall backend: ${firewallBackend}`);
        continue;
      }

      const enabledRaw = enabledIdx >= 0 ? row[enabledIdx]?.trim().toLowerCase() ?? '' : '';
      const enabled = !(enabledRaw === 'false' || enabledRaw === '0' || enabledRaw === 'no');

      // ---- Write the row inside a savepoint so one bad row can't poison the transaction ----
      await client.query('SAVEPOINT import_row');
      try {
        const hostRes = await client.query(
          `INSERT INTO hosts (hostname, mgmt_ip, ssh_port, firewall_backend, vlan_id, enabled)
           VALUES ($1, $2, $3, $4, $5, $6)
           ON CONFLICT (hostname) DO UPDATE SET
             mgmt_ip = EXCLUDED.mgmt_ip,
             ssh_port = EXCLUDED.ssh_port,
             firewall_backend = EXCLUDED.firewall_backend,
             vlan_id = EXCLUDED.vlan_id,
             enabled = EXCLUDED.enabled,
             updated_at = now()
           RETURNING id`,
          [hostname, mgmtIp, sshPort, firewallBackend, vlanId, enabled]
        );

        const hostId = hostRes.rows[0].id;

        // Replace MANUAL tags only; rule-assigned tags stay managed by tag rules.
        if (tagIdx >= 0) {
          await client.query(
            `DELETE FROM host_tags WHERE host_id = $1 AND source <> 'rule' AND NOT (tag_id = ANY($2::uuid[]))`,
            [hostId, tagIds]
          );
          for (const tagId of tagIds) {
            await client.query(
              `INSERT INTO host_tags (host_id, tag_id, source) VALUES ($1, $2, 'manual') ON CONFLICT DO NOTHING`,
              [hostId, tagId]
            );
          }
        }

        await client.query('RELEASE SAVEPOINT import_row');
        if (tagIdx >= 0) importedTagIds.push(...tagIds);
        results.push({
          row: rowNumber,
          hostname,
          success: true,
          ...(missingTags.length > 0 ? { warnings: [`Unknown tags ignored: ${missingTags.join(', ')}`] } : {})
        });
      } catch (e: any) {
        await client.query('ROLLBACK TO SAVEPOINT import_row');
        await client.query('RELEASE SAVEPOINT import_row');
        fail(e?.detail || e?.message || String(e));
      }
    }

    await client.query('COMMIT');
    triggerTemplateAutoApply(importedTagIds);

    const imported = results.filter(r => r.success).length;
    const failed = results.filter(r => !r.success).length;

    await pool.query(
      `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
       VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), $2, $3, uuid_generate_v4(), $4)`,
      [req.auth!.username, 'HOST_BULK_IMPORT', 'host', JSON.stringify({ imported, failed })]
    );

    if (imported > 0) {
      void import('../../services/tag-rule-engine.js')
        .then(({ evaluateAllRules }) => evaluateAllRules())
        .catch((e) => {
          // eslint-disable-next-line no-console
          console.error('[Hosts] Tag rule evaluation after import failed:', e);
        });
    }

    res.json({
      imported,
      failed,
      results
    });
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }
});

hostsRouter.post('/bulk/set-enabled', requireRole('operator', 'admin'), async (req, res) => {
  const parsed = bulkOperationSchema.extend({
    enabled: z.boolean()
  }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });
  
  const { rowCount } = await pool.query(
    `UPDATE hosts SET enabled = $1, updated_at = now() WHERE id = ANY($2::uuid[])`,
    [parsed.data.enabled, parsed.data.hostIds]
  );

  await pool.query(
    `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), $2, $3, uuid_generate_v4(), $4)`,
    [req.auth!.username, 'HOST_BULK_SET_ENABLED', 'host', JSON.stringify({ count: rowCount, enabled: parsed.data.enabled })]
  );

  res.json({ ok: true, updated: rowCount });
});

