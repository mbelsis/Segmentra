import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { Router } from 'express';
import { z } from 'zod';

import { compileHostPolicy } from '@segmentra/compiler';
import { runAnsiblePlaybook, runSshDeployment, checkHostReadiness, type SshHost, type SshHostInfo } from '@segmentra/executor';

import { pool } from '../db/pool.js';
import { env } from '../lib/env.js';
import { requireAuth, requireRole } from '../middleware/auth.js';
import { createAuditEvent } from '../services/audit.js';
import { readSecretPlaintext } from '../services/secrets.js';
import { checkDeploymentSafety } from '../services/safety-check.js';
import { isPolicyVersionHighRisk } from '../services/high-risk.js';

export const deploymentsRouter = Router();
deploymentsRouter.use(requireAuth);

// Host deployment timeout: 10 minutes (600000 ms)
const HOST_DEPLOYMENT_TIMEOUT_MS = 10 * 60 * 1000;

/**
 * Check for and timeout stale host deployments that have been RUNNING for too long
 * This function is exported so it can be called from the main index.ts for periodic checks
 */
export async function checkAndTimeoutStaleHosts() {
  const timeoutThreshold = new Date(Date.now() - HOST_DEPLOYMENT_TIMEOUT_MS);
  
  // Find hosts that have been RUNNING for longer than the timeout
  const staleHosts = await pool.query(
    `UPDATE deployment_hosts
     SET status='FAILED', finished_at=now(), message='Deployment timeout: Host did not respond within 10 minutes'
     WHERE status='RUNNING' 
     AND started_at < $1
     RETURNING deployment_id, host_id`,
    [timeoutThreshold]
  );

  if (staleHosts.rows.length > 0) {
    // Check if any deployments need to be updated to PARTIAL or FAILED
    const deploymentIds = [...new Set(staleHosts.rows.map((r: any) => r.deployment_id))];
    
    for (const deploymentId of deploymentIds) {
      // Check deployment status
      const depRes = await pool.query(
        `SELECT status FROM deployments WHERE id=$1`,
        [deploymentId]
      );
      
      if (depRes.rows[0]?.status === 'RUNNING') {
        // Check if all hosts are done (SUCCEEDED, FAILED, or SKIPPED)
        const hostStatusRes = await pool.query(
          `SELECT status, COUNT(*) as count
           FROM deployment_hosts
           WHERE deployment_id=$1
           GROUP BY status`,
          [deploymentId]
        );
        
        const statusCounts: Record<string, number> = {};
        for (const row of hostStatusRes.rows) {
          statusCounts[row.status] = parseInt(row.count, 10);
        }
        
        const runningCount = statusCounts['RUNNING'] || 0;
        const pendingCount = statusCounts['PENDING'] || 0;
        const pausedCount = statusCounts['PAUSED'] || 0;
        
        // If no hosts are still running/pending/paused, mark deployment as complete
        if (runningCount === 0 && pendingCount === 0 && pausedCount === 0) {
          const succeededCount = statusCounts['SUCCEEDED'] || 0;
          const failedCount = statusCounts['FAILED'] || 0;
          const skippedCount = statusCounts['SKIPPED'] || 0;
          const total = succeededCount + failedCount + skippedCount;
          
          let finalStatus: string;
          if (failedCount > 0 && succeededCount > 0) {
            finalStatus = 'PARTIAL';
            await pool.query(
              `UPDATE deployments SET status='PARTIAL', finished_at=now() WHERE id=$1`,
              [deploymentId]
            );
          } else if (failedCount === total) {
            finalStatus = 'FAILED';
            await pool.query(
              `UPDATE deployments SET status='FAILED', finished_at=now() WHERE id=$1`,
              [deploymentId]
            );
          } else {
            finalStatus = 'SUCCEEDED';
            await pool.query(
              `UPDATE deployments SET status='SUCCEEDED', finished_at=now() WHERE id=$1`,
              [deploymentId]
            );
          }

          // Create audit event for deployment completion (via timeout)
          const depRes = await pool.query(
            `SELECT d.*, ps.name as policy_set_name, pv.version_number, u.id as user_id
             FROM deployments d
             LEFT JOIN policy_versions pv ON d.policy_version_id = pv.id
             LEFT JOIN policy_sets ps ON pv.policy_set_id = ps.id
             LEFT JOIN users u ON d.created_by = u.id
             WHERE d.id=$1`,
            [deploymentId]
          );
          const dep = depRes.rows[0];
          
          if (dep) {
            const targetQuery = dep.target_query || {};
            const targetNames: { tags: string[]; vlans: string[]; hosts: string[] } = { tags: [], vlans: [], hosts: [] };
            
            if (targetQuery.tags && Array.isArray(targetQuery.tags) && targetQuery.tags.length > 0) {
              const tagRes = await pool.query(`SELECT name FROM tags WHERE id = ANY($1::uuid[])`, [targetQuery.tags]);
              targetNames.tags = tagRes.rows.map((r: any) => r.name);
            }
            
            if (targetQuery.vlans && Array.isArray(targetQuery.vlans) && targetQuery.vlans.length > 0) {
              const vlanRes = await pool.query(`SELECT name FROM vlans WHERE id = ANY($1::uuid[])`, [targetQuery.vlans]);
              targetNames.vlans = vlanRes.rows.map((r: any) => r.name);
            }
            
            if (targetQuery.hosts && Array.isArray(targetQuery.hosts) && targetQuery.hosts.length > 0) {
              const hostRes = await pool.query(`SELECT hostname FROM hosts WHERE id = ANY($1::uuid[])`, [targetQuery.hosts]);
              targetNames.hosts = hostRes.rows.map((r: any) => r.hostname);
            }

            const targetTypes: string[] = [];
            if (targetNames.tags.length > 0) targetTypes.push('Tags');
            if (targetNames.vlans.length > 0) targetTypes.push('VLANs');
            if (targetNames.hosts.length > 0) targetTypes.push('Hosts');
            const targetType = targetTypes.join(', ') || 'Unknown';

            await createAuditEvent({
              actorUserId: dep.user_id || null,
              action: 'DEPLOYMENT_FINISHED',
              entityType: 'DEPLOYMENT',
              entityId: deploymentId,
              metadata: {
                policySetName: dep.policy_set_name || 'Unknown',
                policyVersionNumber: dep.version_number || null,
                deploymentMode: dep.mode,
                targetType: targetType,
                targetTags: targetNames.tags,
                targetVlans: targetNames.vlans,
                targetHosts: targetNames.hosts,
                result: finalStatus,
                createdAt: dep.created_at,
                startedAt: dep.started_at,
                finishedAt: new Date().toISOString(),
                hostCounts: {
                  total: total,
                  succeeded: succeededCount,
                  failed: failedCount,
                  skipped: skippedCount
                },
                completedVia: 'timeout_check'
              }
            });
          }
        }
      }
    }
  }
  
  return staleHosts.rows.length;
}

const createDeploymentSchema = z.object({
  policyVersionId: z.string().uuid(),
  mode: z.enum(['CANARY', 'PROGRESSIVE', 'FULL']),
  targetQuery: z.object({
    tags: z.array(z.string().uuid()).optional().default([]),
    vlans: z.array(z.string().uuid()).optional().default([]),
    hosts: z.array(z.string().uuid()).optional().default([])
  }),
  canarySize: z.number().int().min(1).optional(),
  batchSize: z.number().int().min(1).optional(),
  scheduledAt: z.string().datetime().optional(), // ISO 8601 datetime string
  expiresAt: z.string().datetime().optional(), // ISO 8601 datetime string — when the deployment should expire
  expiryAction: z.enum(['NOTIFY_ONLY', 'REMOVE', 'REVERT']).optional().default('NOTIFY_ONLY'), // What to do on expiry
});

async function getManagementVlanCidrs(): Promise<string[]> {
  const mgmtVlanRes = await pool.query(
    `SELECT value FROM system_settings WHERE key='management_vlan_id'`
  );
  const mgmtVlanId = mgmtVlanRes.rows[0]?.value || null;
  
  if (mgmtVlanId) {
    const vlanRes = await pool.query(`SELECT subnet FROM vlans WHERE id=$1`, [mgmtVlanId]);
    if (vlanRes.rows[0]?.subnet) {
      return [vlanRes.rows[0].subnet];
    }
  }
  return [];
}

async function resolveTargets(q: { tags: string[]; vlans: string[]; hosts: string[] }) {
  const ids = new Set<string>();
  
  // Only include enabled hosts
  if (q.hosts.length) {
    const r = await pool.query(
      `SELECT id FROM hosts WHERE id = ANY($1::uuid[]) AND enabled=true`,
      [q.hosts]
    );
    r.rows.forEach((x) => ids.add(x.id));
  }

  if (q.tags.length) {
    const r = await pool.query(
      `SELECT DISTINCT h.id
       FROM hosts h
       JOIN host_tags ht ON ht.host_id=h.id
       WHERE ht.tag_id = ANY($1::uuid[]) AND h.enabled=true`,
      [q.tags]
    );
    r.rows.forEach((x) => ids.add(x.id));
  }

  if (q.vlans.length) {
    const r = await pool.query(`SELECT id FROM hosts WHERE vlan_id = ANY($1::uuid[]) AND enabled=true`, [q.vlans]);
    r.rows.forEach((x) => ids.add(x.id));
  }

  return [...ids];
}

deploymentsRouter.post('/deployments', requireRole('operator', 'admin'), async (req, res) => {
  const parsed = createDeploymentSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });
  const b = parsed.data;

  // Validate that the policy version is APPROVED
  const versionRes = await pool.query(`SELECT status FROM policy_versions WHERE id=$1`, [b.policyVersionId]);
  if (!versionRes.rows[0]) {
    return res.status(404).json({ error: 'policy_version_not_found' });
  }
  if (versionRes.rows[0].status !== 'APPROVED') {
    return res.status(400).json({ 
      error: 'policy_version_not_approved',
      message: `Policy version must be APPROVED to deploy. Current status: ${versionRes.rows[0].status}`
    });
  }

  const targetIds = await resolveTargets(b.targetQuery);
  
  if (targetIds.length === 0) {
    return res.status(400).json({ error: 'no_targets', message: 'No enabled hosts match the target query' });
  }

  // Evaluate high-risk status based on policy version and target count
  // Note: This re-evaluates in case target count changes the risk level
  const isHighRisk = await isPolicyVersionHighRisk({
    policyVersionId: b.policyVersionId,
    targetCount: targetIds.length
  });
  
  // Update policy version's is_high_risk flag if it changed
  if (isHighRisk) {
    await pool.query(
      `UPDATE policy_versions SET is_high_risk=true WHERE id=$1`,
      [b.policyVersionId]
    );
  }

  // Safety check: verify SSH access will be preserved
  const safetyCheck = await checkDeploymentSafety({
    policyVersionId: b.policyVersionId,
    hostIds: targetIds,
    userIp: req.ip
  });

  // For FULL mode deployments, require SSH access to be preserved
  if (b.mode === 'FULL' && !safetyCheck.sshAccessPreserved && safetyCheck.errors.length > 0) {
    return res.status(400).json({
      error: 'safety_check_failed',
      message: 'Deployment would block SSH access from management VLAN',
      safetyCheck
    });
  }

  // For other modes, warn but allow (user can proceed with caution)
  if (!safetyCheck.sshAccessPreserved && safetyCheck.errors.length > 0) {
    // Log warning but don't block
    // eslint-disable-next-line no-console
    console.warn(`[Safety Check] Deployment ${b.policyVersionId} may block SSH access:`, safetyCheck.errors);
  }
  
  // Get user ID
  const userRes = await pool.query(`SELECT id FROM users WHERE username=$1 LIMIT 1`, [req.auth!.username]);
  const userId = userRes.rows[0]?.id || null;

  // Get policy set and version info
  const policyInfoRes = await pool.query(
    `SELECT ps.name as policy_set_name, pv.version_number
     FROM policy_versions pv
     JOIN policy_sets ps ON ps.id = pv.policy_set_id
     WHERE pv.id=$1`,
    [b.policyVersionId]
  );
  const policyInfo = policyInfoRes.rows[0];

  // Resolve target names
  const targetNames: { tags: string[]; vlans: string[]; hosts: string[] } = { tags: [], vlans: [], hosts: [] };
  
  if (b.targetQuery.tags && b.targetQuery.tags.length > 0) {
    const tagRes = await pool.query(`SELECT name FROM tags WHERE id = ANY($1::uuid[])`, [b.targetQuery.tags]);
    targetNames.tags = tagRes.rows.map((r: any) => r.name);
  }
  
  if (b.targetQuery.vlans && b.targetQuery.vlans.length > 0) {
    const vlanRes = await pool.query(`SELECT name FROM vlans WHERE id = ANY($1::uuid[])`, [b.targetQuery.vlans]);
    targetNames.vlans = vlanRes.rows.map((r: any) => r.name);
  }
  
  if (b.targetQuery.hosts && b.targetQuery.hosts.length > 0) {
    const hostRes = await pool.query(`SELECT hostname FROM hosts WHERE id = ANY($1::uuid[])`, [b.targetQuery.hosts]);
    targetNames.hosts = hostRes.rows.map((r: any) => r.hostname);
  }

  // Determine target type
  const targetTypes: string[] = [];
  if (targetNames.tags.length > 0) targetTypes.push('Tags');
  if (targetNames.vlans.length > 0) targetTypes.push('VLANs');
  if (targetNames.hosts.length > 0) targetTypes.push('Hosts');
  const targetType = targetTypes.join(', ') || 'Unknown';

  const scheduledAt = b.scheduledAt ? new Date(b.scheduledAt) : null;
  const expiresAt = b.expiresAt ? new Date(b.expiresAt) : null;
  const expiryAction = b.expiryAction ?? 'NOTIFY_ONLY';
  const status = scheduledAt && scheduledAt > new Date() ? 'QUEUED' : 'QUEUED';

  const { rows } = await pool.query(
    `INSERT INTO deployments (policy_version_id, mode, target_query, target_count, created_by, canary_size, batch_size, scheduled_at, status, expires_at, expiry_action)
     VALUES ($1,$2,$3,$4,(SELECT id FROM users WHERE username=$5 LIMIT 1),$6,$7,$8,$9,$10,$11)
     RETURNING *`,
    [b.policyVersionId, b.mode, b.targetQuery, targetIds.length, req.auth!.username, b.canarySize ?? null, b.batchSize ?? null, scheduledAt, status, expiresAt, expiryAction]
  );
  const deployment = rows[0];

  for (const hostId of targetIds) {
    await pool.query(`INSERT INTO deployment_hosts (deployment_id, host_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, [
      deployment.id,
      hostId
    ]);
  }

  // Create audit event for deployment creation
  await createAuditEvent({
    actorUserId: userId,
    action: 'DEPLOYMENT_CREATED',
    entityType: 'DEPLOYMENT',
    entityId: deployment.id,
    ipAddress: req.ip,
    metadata: {
      policySetName: policyInfo?.policy_set_name || 'Unknown',
      policyVersionNumber: policyInfo?.version_number || null,
      deploymentMode: b.mode,
      targetType: targetType,
      targetTags: targetNames.tags,
      targetVlans: targetNames.vlans,
      targetHosts: targetNames.hosts,
      targetCount: targetIds.length,
      createdAt: deployment.created_at,
      canarySize: b.canarySize || null,
      batchSize: b.batchSize || null
    }
  });

  res.status(201).json({ deployment });
});

deploymentsRouter.get('/deployments', requireRole('viewer', 'operator', 'approver', 'admin'), async (req, res) => {
  // Check for stale hosts before returning deployments
  await checkAndTimeoutStaleHosts();
  
  // Parse query parameters
  const search = req.query.search as string | undefined;
  const mode = req.query.mode as string | undefined;
  const status = req.query.status as string | undefined;
  const tag = req.query.tag as string | undefined;
  const vlan = req.query.vlan as string | undefined;
  const fromDate = req.query.fromDate as string | undefined;
  const toDate = req.query.toDate as string | undefined;
  const sortBy = (req.query.sortBy as string) || 'created_at';
  const sortOrder = (req.query.sortOrder as string) || 'DESC';
  const page = parseInt(req.query.page as string) || 1;
  const limit = Math.min(parseInt(req.query.limit as string) || 50, 100); // Max 100 per page
  const offset = (page - 1) * limit;

  // Build WHERE clause
  const conditions: string[] = [];
  const params: any[] = [];
  let paramIndex = 1;

  // Search by policy version ID or deployment ID
  if (search) {
    conditions.push(`(d.id::text ILIKE $${paramIndex} OR d.policy_version_id::text ILIKE $${paramIndex})`);
    params.push(`%${search}%`);
    paramIndex++;
  }

  // Filter by mode
  if (mode && ['CANARY', 'PROGRESSIVE', 'FULL'].includes(mode)) {
    conditions.push(`d.mode = $${paramIndex}`);
    params.push(mode);
    paramIndex++;
  }

  // Filter by status
  if (status) {
    conditions.push(`d.status = $${paramIndex}`);
    params.push(status);
    paramIndex++;
  }

  // Filter by date range
  if (fromDate) {
    conditions.push(`d.created_at >= $${paramIndex}::timestamptz`);
    params.push(fromDate);
    paramIndex++;
  }
  if (toDate) {
    conditions.push(`d.created_at <= $${paramIndex}::timestamptz`);
    params.push(toDate);
    paramIndex++;
  }

  // Filter by tag (requires join with hosts and host_tags)
  if (tag) {
    conditions.push(`EXISTS (
      SELECT 1 FROM deployment_hosts dh2
      JOIN hosts h2 ON h2.id = dh2.host_id
      JOIN host_tags ht ON ht.host_id = h2.id
      JOIN tags t ON t.id = ht.tag_id
      WHERE dh2.deployment_id = d.id AND t.name = $${paramIndex}
    )`);
    params.push(tag);
    paramIndex++;
  }

  // Filter by VLAN (requires join with hosts)
  if (vlan) {
    conditions.push(`EXISTS (
      SELECT 1 FROM deployment_hosts dh3
      JOIN hosts h3 ON h3.id = dh3.host_id
      JOIN vlans v ON v.id = h3.vlan_id
      WHERE dh3.deployment_id = d.id AND (v.name = $${paramIndex} OR v.vlan_tag::text = $${paramIndex})
    )`);
    params.push(vlan);
    paramIndex++;
  }

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

  // Validate sortBy and sortOrder
  const validSortColumns = ['created_at', 'started_at', 'finished_at', 'status', 'mode', 'target_count'];
  const sortColumn = validSortColumns.includes(sortBy) ? sortBy : 'created_at';
  const sortDir = sortOrder.toUpperCase() === 'ASC' ? 'ASC' : 'DESC';

  // Get total count for pagination
  const countRes = await pool.query(`SELECT COUNT(*) as total FROM deployments d ${whereClause}`, params);
  const total = parseInt(countRes.rows[0].total, 10);

  // Get paginated results
  const query = `
    SELECT d.*
    FROM deployments d
    ${whereClause}
    ORDER BY d.${sortColumn} ${sortDir}
    LIMIT $${paramIndex} OFFSET $${paramIndex + 1}
  `;
  params.push(limit, offset);
  
  const { rows } = await pool.query(query, params);
  
  res.json({ 
    deployments: rows,
    pagination: {
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit)
    }
  });
});

deploymentsRouter.get('/deployments/:deploymentId', requireRole('viewer', 'operator', 'approver', 'admin'), async (req, res) => {
  const { rows } = await pool.query(`SELECT * FROM deployments WHERE id=$1`, [req.params.deploymentId]);
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });
  res.json({ deployment: rows[0] });
});

deploymentsRouter.get('/deployments/:deploymentId/hosts', requireRole('viewer', 'operator', 'approver', 'admin'), async (req, res) => {
  // Check for stale hosts before returning host status
  await checkAndTimeoutStaleHosts();
  
  const { rows } = await pool.query(
    `SELECT dh.*, h.hostname, h.mgmt_ip
     FROM deployment_hosts dh
     JOIN hosts h ON h.id = dh.host_id
     WHERE dh.deployment_id=$1
     ORDER BY h.hostname ASC`,
    [req.params.deploymentId]
  );
  res.json({ hosts: rows });
});

deploymentsRouter.get('/deployments/:deploymentId/artifacts', requireRole('viewer', 'operator', 'approver', 'admin'), async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id, bundle_path, bundle_hash, manifest, created_at
     FROM deployment_artifacts
     WHERE deployment_id=$1
     ORDER BY created_at DESC`,
    [req.params.deploymentId]
  );
  res.json({ artifacts: rows });
});

deploymentsRouter.get('/executions/:executionId/logs', requireRole('viewer', 'operator', 'approver', 'admin'), async (req, res) => {
  const { rows } = await pool.query(
    `SELECT stdout_path, stderr_path FROM execution_runs WHERE id=$1`,
    [req.params.executionId]
  );
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });
  const stdout = rows[0].stdout_path && fs.existsSync(rows[0].stdout_path) ? fs.readFileSync(rows[0].stdout_path, 'utf8') : '';
  const stderr = rows[0].stderr_path && fs.existsSync(rows[0].stderr_path) ? fs.readFileSync(rows[0].stderr_path, 'utf8') : '';
  res.json({ stdout, stderr });
});

async function generateBundle(deploymentId: string) {
  const bundleDir = path.join(env.BUNDLES_DIR, deploymentId);
  const hostRulesDir = path.join(bundleDir, 'host_rules');
  fs.mkdirSync(hostRulesDir, { recursive: true });

  const depRes = await pool.query(`SELECT * FROM deployments WHERE id=$1`, [deploymentId]);
  const dep = depRes.rows[0];
  if (!dep) throw new Error('deployment_not_found');

  // Only process enabled hosts - mark disabled hosts as SKIPPED
  await pool.query(
    `UPDATE deployment_hosts 
     SET status='SKIPPED', finished_at=now(), message='Host is disabled'
     WHERE deployment_id=$1 
     AND host_id IN (SELECT id FROM hosts WHERE enabled=false)`,
    [deploymentId]
  );

  const hostRows = await pool.query(
    `SELECT h.id, h.hostname, h.mgmt_ip, h.ssh_port, h.firewall_backend
     FROM deployment_hosts dh
     JOIN hosts h ON h.id = dh.host_id
     WHERE dh.deployment_id=$1 AND h.enabled=true`,
    [deploymentId]
  );

  const vRes = await pool.query(
    `SELECT interface_scope_type, interface_scope_roles, interface_scope_names
     FROM policy_versions WHERE id=$1`,
    [dep.policy_version_id]
  );
  const v = vRes.rows[0];
  if (!v) throw new Error('policy_version_not_found');

  const rRes = await pool.query(
    `SELECT order_index, direction, action, protocol, ports, source_type, source_value, log_mode, comment,
            use_policy_interface_scope, interface_scope_type, interface_scope_roles, interface_scope_names
     FROM policy_rules
     WHERE policy_version_id=$1`,
    [dep.policy_version_id]
  );

  const policyInterfaceScope =
    v.interface_scope_type === 'ALL_INTERFACES'
      ? { type: 'ALL_INTERFACES' as const }
      : v.interface_scope_type === 'INTERFACE_NAME'
        ? { type: 'INTERFACE_NAME' as const, names: (v.interface_scope_names ?? []) as string[] }
        : { type: 'INTERFACE_ROLE' as const, roles: (v.interface_scope_roles ?? []) as string[] };

  // resolved sets shared across hosts
  const sets: Record<string, string[]> = {};
  for (const rule of rRes.rows as any[]) {
    if (rule.source_type === 'CIDR') continue;
    const setName = `src_${rule.source_type.toLowerCase()}_${String(rule.source_value).replace(/-/g, '')}`;
    if (sets[setName]) continue;

    let ips: string[] = [];
    if (rule.source_type === 'HOST') {
      const h = await pool.query(`SELECT mgmt_ip FROM hosts WHERE id=$1`, [rule.source_value]);
      if (h.rows[0]?.mgmt_ip) ips = [String(h.rows[0].mgmt_ip)];
    } else if (rule.source_type === 'TAG') {
      const q = await pool.query(
        `SELECT h.mgmt_ip FROM hosts h
         JOIN host_tags ht ON ht.host_id=h.id
         WHERE ht.tag_id=$1 AND h.mgmt_ip IS NOT NULL AND h.enabled=true`,
        [rule.source_value]
      );
      ips = q.rows.map((x) => String(x.mgmt_ip));
    } else if (rule.source_type === 'VLAN') {
      const q = await pool.query(
        `SELECT mgmt_ip FROM hosts WHERE vlan_id=$1 AND mgmt_ip IS NOT NULL AND enabled=true`,
        [rule.source_value]
      );
      ips = q.rows.map((x) => String(x.mgmt_ip));
    }
    sets[setName] = ips;
  }

  const manifest = {
    deployment_id: deploymentId,
    policy_version_id: dep.policy_version_id,
    interface_scope: policyInterfaceScope,
    target_count: dep.target_count
  };
  fs.writeFileSync(path.join(bundleDir, 'manifest.json'), JSON.stringify(manifest, null, 2));

  // pick GLOBAL ssh credential for v1 (needed for auto-detection and bundle generation)
  const credRes = await pool.query(
    `SELECT * FROM ssh_credentials WHERE scope_type='GLOBAL' ORDER BY created_at DESC LIMIT 1`
  );
  const cred = credRes.rows[0];
  if (!cred) throw new Error('missing_ssh_credential');
  const keyPem = (await readSecretPlaintext(cred.private_key_secret_id)).toString('utf8');
  const keyPath = path.join(bundleDir, 'ssh_key');
  fs.writeFileSync(keyPath, keyPem, { encoding: 'utf8', mode: 0o600 });
  
  // Create temp key for auto-detection (will be cleaned up)
  // Use os.tmpdir() for temporary keys to avoid dependency on BUNDLES_DIR existing
  const tempKeyPath = path.join(os.tmpdir(), `segmentra_deployment_key_${deploymentId}_${Date.now()}`);
  fs.writeFileSync(tempKeyPath, keyPem, { encoding: 'utf8', mode: 0o600 });

  const inventoryLines: string[] = ['[all]'];
  const hostPolicyHashes: Map<string, string> = new Map(); // host_id -> policy hash

  try {
    for (const h of hostRows.rows as any[]) {
      const ifsRes = await pool.query(`SELECT name, role, enabled FROM host_interfaces WHERE host_id=$1`, [h.id]);
      
      // Auto-detect backend if set to 'auto' or null
      let backend: 'nftables' | 'iptables';
      if (h.firewall_backend === 'iptables') {
        backend = 'iptables';
      } else if (h.firewall_backend === 'auto' || !h.firewall_backend) {
        // Perform auto-detection via SSH
        try {
          const sshHostInfo: SshHostInfo = {
            hostname: h.hostname,
            ip: String(h.mgmt_ip),
            port: h.ssh_port || 22,
            username: cred.username,
            privateKeyPath: tempKeyPath
          };
          const readinessResult = await checkHostReadiness(sshHostInfo);
          backend = readinessResult.backend === 'iptables' ? 'iptables' : 'nftables';
          
          // Update host's firewall_backend if auto-detected
          if (readinessResult.backend !== 'unknown') {
            await pool.query(
              `UPDATE hosts SET firewall_backend=$1 WHERE id=$2`,
              [readinessResult.backend, h.id]
            );
          }
        } catch (detectionError: any) {
          // If detection fails, default to nftables (as before)
          // eslint-disable-next-line no-console
          console.warn(`[Auto-detection failed for ${h.hostname}, defaulting to nftables]`, detectionError.message);
          backend = 'nftables';
        }
      } else {
        // Explicitly set to nftables
        backend = 'nftables';
      }

      const rules = (rRes.rows as any[]).map((r) => {
        const ruleScope =
          r.interface_scope_type === 'ALL_INTERFACES'
            ? { type: 'ALL_INTERFACES' as const }
            : r.interface_scope_type === 'INTERFACE_NAME'
              ? { type: 'INTERFACE_NAME' as const, names: (r.interface_scope_names ?? []) as string[] }
              : r.interface_scope_type === 'INTERFACE_ROLE'
                ? { type: 'INTERFACE_ROLE' as const, roles: (r.interface_scope_roles ?? []) as string[] }
                : undefined;
        const remote = r.source_type === 'CIDR'
          ? ({ kind: 'CIDR' as const })
          : ({ kind: 'SET' as const, setName: `src_${r.source_type.toLowerCase()}_${String(r.source_value).replace(/-/g, '')}` });
        return {
          orderIndex: Number(r.order_index),
          direction: (r.direction ?? 'IN') as 'IN' | 'OUT' | 'BOTH',
          action: r.action,
          protocol: r.protocol,
          ports: r.ports,
          sourceType: r.source_type,
          sourceValue: r.source_value,
          logMode: r.log_mode,
          comment: r.comment,
          usePolicyInterfaceScope: Boolean(r.use_policy_interface_scope),
          interfaceScope: ruleScope,
          remote
        };
      });

      const compiled = compileHostPolicy({
        host: {
          id: h.id,
          hostname: h.hostname,
          mgmtIp: h.mgmt_ip ? String(h.mgmt_ip) : null,
          firewallBackend: backend,
          interfaces: ifsRes.rows.map((i: any) => ({ name: i.name, role: i.role, enabled: i.enabled }))
        },
        policyInterfaceScope,
        rules,
        sets,
        baseline: { mgmtSshCidrs: await getManagementVlanCidrs() }
      });

      const ext = compiled.backend === 'nftables' ? 'nft' : 'iptables';
      const policyFileHostPath = path.join(hostRulesDir, `${h.hostname}.${ext}`);
      fs.writeFileSync(policyFileHostPath, compiled.text, 'utf8');
      
      // Store hash of compiled policy for this host (for drift detection)
      const policyHash = crypto.createHash('sha256').update(compiled.text, 'utf8').digest('hex');
      hostPolicyHashes.set(h.id, policyHash);

      // Ansible runner sees bundle at /bundles/<deploymentId>/...
      const policyFileRunnerPath = `/bundles/${deploymentId}/host_rules/${h.hostname}.${ext}`;

      inventoryLines.push(
        `${h.hostname} ansible_host=${String(h.mgmt_ip)} ansible_port=${h.ssh_port} ansible_user=${cred.username} ansible_ssh_private_key_file=/bundles/${deploymentId}/ssh_key ansible_become=yes ansible_become_method=sudo segmentra_policy_file=${policyFileRunnerPath}`
      );
    }
  } finally {
    // Clean up temp key file used for auto-detection
    if (fs.existsSync(tempKeyPath)) {
      try {
        fs.unlinkSync(tempKeyPath);
      } catch (e) {
        // Ignore cleanup errors
      }
    }
  }

  fs.writeFileSync(path.join(bundleDir, 'inventory.ini'), inventoryLines.join('\n') + '\n', 'utf8');

  // Calculate bundle hash from manifest JSON (SHA-256)
  const manifestJson = JSON.stringify(manifest);
  const bundleHash = crypto.createHash('sha256').update(manifestJson, 'utf8').digest('hex');

  // artifacts row
  await pool.query(
    `INSERT INTO deployment_artifacts (deployment_id, bundle_path, bundle_hash, manifest)
     VALUES ($1,$2,$3,$4)`,
    [deploymentId, bundleDir, bundleHash, manifest]
  );

  return { bundleDir, hostPolicyHashes };
}

/**
 * Core deployment start logic, extracted so it can be called from both the
 * POST /start route handler and the scheduled-deployment background job.
 *
 * Returns { ok, exitCode, executionId } on success.
 * Throws on failure (caller is responsible for error handling).
 *
 * @param ipAddress - optional IP of the requesting user (for audit trail)
 */
export async function executeDeploymentStart(
  deploymentId: string,
  ipAddress?: string
): Promise<{ ok: boolean; exitCode: number; executionId: string }> {
    // Check for and timeout stale hosts before starting
    await checkAndTimeoutStaleHosts();

    // Mark disabled hosts as SKIPPED before starting
    await pool.query(
    `UPDATE deployment_hosts
     SET status='SKIPPED', finished_at=now(), message='Host is disabled'
     WHERE deployment_id=$1
     AND host_id IN (SELECT id FROM hosts WHERE enabled=false)
     AND status='PENDING'`,
    [deploymentId]
  );

    await pool.query(`UPDATE deployments SET status='RUNNING', started_at=now() WHERE id=$1`, [deploymentId]);
    // Only mark enabled hosts as RUNNING
    await pool.query(
    `UPDATE deployment_hosts
     SET status='RUNNING', started_at=now()
     WHERE deployment_id=$1
     AND host_id IN (SELECT id FROM hosts WHERE enabled=true)
     AND status='PENDING'`,
      [deploymentId]
    );

    const { bundleDir, hostPolicyHashes } = await generateBundle(deploymentId);

    // Get executor setting
    const executorRes = await pool.query(
      `SELECT value FROM system_settings WHERE key='deployment_executor'`
    );
    const executor = executorRes.rows[0]?.value ?? 'ansible';

    const stdoutPath = path.join(bundleDir, executor === 'ssh' ? 'ssh.stdout.log' : 'ansible.stdout.log');
    const stderrPath = path.join(bundleDir, executor === 'ssh' ? 'ssh.stderr.log' : 'ansible.stderr.log');

    let ok = false;
    let exitCode = 1;
    let executionId: string;

    if (executor === 'ssh') {
    // SSH Direct executor
    const executionIdRes = await pool.query(
      `INSERT INTO execution_runs (deployment_id, executor_type, command)
       VALUES ($1,'ssh_direct',$2)
       RETURNING id`,
      [deploymentId, 'ssh/scp direct execution']
    );
    executionId = executionIdRes.rows[0].id;

    // Get SSH credential
    const credRes = await pool.query(
      `SELECT * FROM ssh_credentials WHERE scope_type='GLOBAL' ORDER BY created_at DESC LIMIT 1`
    );
    const cred = credRes.rows[0];
    if (!cred) {
      await pool.query(`UPDATE execution_runs SET status='DONE', finished_at=now() WHERE id=$1`, [executionId]);
      await pool.query(`UPDATE deployments SET status='FAILED', finished_at=now() WHERE id=$1`, [deploymentId]);
      throw new Error('missing_ssh_credential');
    }

    const keyPem = (await readSecretPlaintext(cred.private_key_secret_id)).toString('utf8');
    const keyPath = path.join(bundleDir, 'ssh_key');
    fs.writeFileSync(keyPath, keyPem, { encoding: 'utf8', mode: 0o600 });

    // Get hosts and policy files (only enabled hosts)
    const hostRows = await pool.query(
      `SELECT h.id, h.hostname, h.mgmt_ip, h.ssh_port, h.firewall_backend
       FROM deployment_hosts dh
       JOIN hosts h ON h.id = dh.host_id
       WHERE dh.deployment_id=$1 AND h.enabled=true`,
      [deploymentId]
    );

    const sshHosts: SshHost[] = [];
    for (const h of hostRows.rows as any[]) {
      const backend = h.firewall_backend === 'iptables' ? 'iptables' : 'nftables';
      const ext = backend === 'nftables' ? 'nft' : 'iptables';
      const policyFilePath = path.join(bundleDir, 'host_rules', `${h.hostname}.${ext}`);

      if (fs.existsSync(policyFilePath)) {
        sshHosts.push({
          hostname: h.hostname,
          ip: String(h.mgmt_ip),
          port: h.ssh_port || 22,
          username: cred.username,
          privateKeyPath: keyPath,
          policyFilePath,
          backend
        });
      }
    }

    const results = await runSshDeployment({
      hosts: sshHosts,
      stdoutPath,
      stderrPath
    });

    // Update deployment_hosts based on results
    const failedHosts = results.filter(r => !r.success);
    ok = failedHosts.length === 0;
    exitCode = ok ? 0 : 1;

    for (const result of results) {
      const host = hostRows.rows.find((h: any) => h.hostname === result.hostname);
      if (host) {
        const policyHash = result.success ? hostPolicyHashes.get(host.id) || null : null;
        await pool.query(
          `UPDATE deployment_hosts
           SET status=$2, finished_at=now(), message=$3, applied_hash=$5
           WHERE deployment_id=$1 AND host_id=$4`,
          [deploymentId, result.success ? 'SUCCEEDED' : 'FAILED', result.success ? 'ok' : 'ssh_failed', host.id, policyHash]
        );
      }
    }

    await pool.query(
      `UPDATE execution_runs
       SET exit_code=$2, stdout_path=$3, stderr_path=$4, finished_at=now(), status='DONE'
       WHERE id=$1`,
      [executionId, exitCode, stdoutPath, stderrPath]
    );
    } else {
    // Ansible executor (default)
    const executionIdRes = await pool.query(
      `INSERT INTO execution_runs (deployment_id, executor_type, command)
       VALUES ($1,'ansible_cli',$2)
       RETURNING id`,
      [deploymentId, 'docker exec ... ansible-playbook']
    );
    executionId = executionIdRes.rows[0].id;

    const result = await runAnsiblePlaybook({
      runnerContainer: env.ANSIBLE_RUNNER_CONTAINER,
      inventoryPath: `/bundles/${deploymentId}/inventory.ini`,
      playbookPath: `/runner/playbooks/apply-firewall.yml`,
      stdoutPath,
      stderrPath
    });

    exitCode = result.exitCode;
    ok = exitCode === 0;

    await pool.query(
      `UPDATE execution_runs
       SET exit_code=$2, stdout_path=$3, stderr_path=$4, finished_at=now(), status='DONE'
       WHERE id=$1`,
      [executionId, exitCode, stdoutPath, stderrPath]
    );

    // Only update enabled hosts that were RUNNING (disabled hosts are already SKIPPED)
    // For Ansible, we need to update each host individually to set applied_hash
    if (ok) {
      const hostRows = await pool.query(
        `SELECT h.id FROM deployment_hosts dh
         JOIN hosts h ON h.id = dh.host_id
         WHERE dh.deployment_id=$1 AND dh.status='RUNNING' AND h.enabled=true`,
        [deploymentId]
      );
      for (const hostRow of hostRows.rows) {
        const policyHash = hostPolicyHashes.get(hostRow.id) || null;
        await pool.query(
          `UPDATE deployment_hosts
           SET status='SUCCEEDED', finished_at=now(), message='ok', applied_hash=$3
           WHERE deployment_id=$1 AND host_id=$2`,
          [deploymentId, hostRow.id, policyHash]
        );
      }
    } else {
      await pool.query(
        `UPDATE deployment_hosts
         SET status='FAILED', finished_at=now(), message='ansible_failed'
         WHERE deployment_id=$1 AND status='RUNNING'`,
        [deploymentId]
      );
    }

    // Get final host status counts to determine deployment status
    const hostStatusRes = await pool.query(
      `SELECT status, COUNT(*) as count
       FROM deployment_hosts
       WHERE deployment_id=$1
       GROUP BY status`,
      [deploymentId]
    );

    const statusCounts: Record<string, number> = {};
    for (const row of hostStatusRes.rows) {
      statusCounts[row.status] = parseInt(row.count, 10);
    }

    const succeededCount = statusCounts['SUCCEEDED'] || 0;
    const failedCount = statusCounts['FAILED'] || 0;
    const skippedCount = statusCounts['SKIPPED'] || 0;
    const total = succeededCount + failedCount + skippedCount;

    // Determine final status
    let finalStatus: string;
    if (failedCount > 0 && succeededCount > 0) {
      finalStatus = 'PARTIAL';
    } else if (failedCount === total || (failedCount > 0 && succeededCount === 0)) {
      finalStatus = 'FAILED';
    } else {
      finalStatus = 'SUCCEEDED';
    }

    await pool.query(
      `UPDATE deployments SET status=$2, finished_at=now() WHERE id=$1`,
      [deploymentId, finalStatus]
    );

    // Get deployment info for audit
    const depRes = await pool.query(
      `SELECT d.*, ps.name as policy_set_name, pv.version_number, u.id as user_id
       FROM deployments d
       LEFT JOIN policy_versions pv ON d.policy_version_id = pv.id
       LEFT JOIN policy_sets ps ON pv.policy_set_id = ps.id
       LEFT JOIN users u ON d.created_by = u.id
       WHERE d.id=$1`,
      [deploymentId]
    );
    const dep = depRes.rows[0];

    // Resolve target names for audit
    const targetQuery = dep.target_query || {};
    const targetNames: { tags: string[]; vlans: string[]; hosts: string[] } = { tags: [], vlans: [], hosts: [] };

    if (targetQuery.tags && Array.isArray(targetQuery.tags) && targetQuery.tags.length > 0) {
      const tagRes = await pool.query(`SELECT name FROM tags WHERE id = ANY($1::uuid[])`, [targetQuery.tags]);
      targetNames.tags = tagRes.rows.map((r: any) => r.name);
    }

    if (targetQuery.vlans && Array.isArray(targetQuery.vlans) && targetQuery.vlans.length > 0) {
      const vlanRes = await pool.query(`SELECT name FROM vlans WHERE id = ANY($1::uuid[])`, [targetQuery.vlans]);
      targetNames.vlans = vlanRes.rows.map((r: any) => r.name);
    }

    if (targetQuery.hosts && Array.isArray(targetQuery.hosts) && targetQuery.hosts.length > 0) {
      const hostRes = await pool.query(`SELECT hostname FROM hosts WHERE id = ANY($1::uuid[])`, [targetQuery.hosts]);
      targetNames.hosts = hostRes.rows.map((r: any) => r.hostname);
    }

    const targetTypes: string[] = [];
    if (targetNames.tags.length > 0) targetTypes.push('Tags');
    if (targetNames.vlans.length > 0) targetTypes.push('VLANs');
    if (targetNames.hosts.length > 0) targetTypes.push('Hosts');
    const targetType = targetTypes.join(', ') || 'Unknown';

    // Create audit event for deployment completion
    await createAuditEvent({
      actorUserId: dep.user_id || null,
      action: 'DEPLOYMENT_FINISHED',
      entityType: 'DEPLOYMENT',
      entityId: deploymentId,
      ipAddress: ipAddress,
      metadata: {
        policySetName: dep.policy_set_name || 'Unknown',
        policyVersionNumber: dep.version_number || null,
        deploymentMode: dep.mode,
        targetType: targetType,
        targetTags: targetNames.tags,
        targetVlans: targetNames.vlans,
        targetHosts: targetNames.hosts,
        result: finalStatus,
        createdAt: dep.created_at,
        startedAt: dep.started_at,
        finishedAt: new Date().toISOString(),
        hostCounts: {
          total: total,
          succeeded: succeededCount,
          failed: failedCount,
          skipped: skippedCount
        }
      }
    });
    }

    return { ok, exitCode, executionId: executionId! };
}

deploymentsRouter.post('/deployments/:deploymentId/start', requireRole('operator', 'admin'), async (req, res) => {
  const deploymentId = req.params.deploymentId;

  try {
    const result = await executeDeploymentStart(deploymentId, req.ip);
    res.json(result);
  } catch (error: any) {
    // eslint-disable-next-line no-console
    console.error('[Deployment Start Error]', error);

    // Update deployment status to FAILED if it was set to RUNNING
    await pool.query(
      `UPDATE deployments SET status='FAILED', finished_at=now() WHERE id=$1 AND status='RUNNING'`,
      [deploymentId]
    );

    // Update all RUNNING hosts to FAILED
    await pool.query(
      `UPDATE deployment_hosts SET status='FAILED', finished_at=now(), message=$2 WHERE deployment_id=$1 AND status='RUNNING'`,
      [deploymentId, error.message || 'Deployment start failed']
    );

    // Return appropriate error response
    if (error.message === 'missing_ssh_credential') {
      return res.status(400).json({
        error: 'missing_ssh_credential',
        message: 'SSH credentials are required to start a deployment. Please configure SSH credentials in Admin → SSH Credentials.'
      });
    }

    res.status(500).json({
      error: 'deployment_start_failed',
      message: error.message || 'Failed to start deployment'
    });
  }
});

deploymentsRouter.post('/deployments/:deploymentId/pause', requireRole('operator', 'admin'), async (req, res) => {
  const deploymentId = req.params.deploymentId;
  
  // Check if deployment is running
  const depRes = await pool.query(`SELECT status FROM deployments WHERE id=$1`, [deploymentId]);
  if (!depRes.rows[0]) {
    return res.status(404).json({ error: 'deployment_not_found' });
  }
  if (depRes.rows[0].status !== 'RUNNING') {
    return res.status(400).json({ error: 'deployment_not_running', message: `Cannot pause deployment with status: ${depRes.rows[0].status}` });
  }

  // Update deployment status to PAUSED
  await pool.query(`UPDATE deployments SET status='PAUSED' WHERE id=$1`, [deploymentId]);
  
  // Mark RUNNING hosts as PAUSED, leave PENDING hosts as-is (for resume)
  await pool.query(
    `UPDATE deployment_hosts SET status='PAUSED', finished_at=now(), message='Deployment paused by user' WHERE deployment_id=$1 AND status='RUNNING'`,
    [deploymentId]
  );
  
  res.json({ ok: true });
});

deploymentsRouter.post('/deployments/:deploymentId/resume', requireRole('operator', 'admin'), async (req, res) => {
  const deploymentId = req.params.deploymentId;
  
  // Check if deployment is paused
  const depRes = await pool.query(`SELECT status FROM deployments WHERE id=$1`, [deploymentId]);
  if (!depRes.rows[0]) {
    return res.status(404).json({ error: 'deployment_not_found' });
  }
  if (depRes.rows[0].status !== 'PAUSED') {
    return res.status(400).json({ error: 'deployment_not_paused', message: `Cannot resume deployment with status: ${depRes.rows[0].status}` });
  }

  // Update deployment status back to RUNNING
  await pool.query(`UPDATE deployments SET status='RUNNING' WHERE id=$1`, [deploymentId]);
  
  // Mark PAUSED hosts back to RUNNING, and PENDING hosts remain PENDING
  await pool.query(
    `UPDATE deployment_hosts SET status='RUNNING', finished_at=null, message=null WHERE deployment_id=$1 AND status='PAUSED'`,
    [deploymentId]
  );
  
  res.json({ ok: true });
});

deploymentsRouter.post('/deployments/:deploymentId/stop', requireRole('operator', 'admin'), async (req, res) => {
  const deploymentId = req.params.deploymentId;
  
  // Check if deployment can be stopped
  const depRes = await pool.query(`SELECT status FROM deployments WHERE id=$1`, [deploymentId]);
  if (!depRes.rows[0]) {
    return res.status(404).json({ error: 'deployment_not_found' });
  }
  const currentStatus = depRes.rows[0].status;
  if (!['RUNNING', 'PAUSED'].includes(currentStatus)) {
    return res.status(400).json({ error: 'deployment_not_stoppable', message: `Cannot stop deployment with status: ${currentStatus}` });
  }

  // Update deployment status to CANCELLED
  await pool.query(`UPDATE deployments SET status='CANCELLED', finished_at=now() WHERE id=$1`, [deploymentId]);
  
  // Mark all PENDING, RUNNING, and PAUSED hosts as SKIPPED
  await pool.query(
    `UPDATE deployment_hosts SET status='SKIPPED', finished_at=now(), message='Deployment stopped by user' WHERE deployment_id=$1 AND status IN ('PENDING', 'RUNNING', 'PAUSED')`,
    [deploymentId]
  );
  
  res.json({ ok: true });
});

deploymentsRouter.post('/deployments/:deploymentId/cancel', requireRole('operator', 'admin'), async (req, res) => {
  // v1: best-effort cancellation (no process tracking yet)
  await pool.query(`UPDATE deployments SET status='CANCELLED', finished_at=now() WHERE id=$1 AND status='RUNNING'`, [
    req.params.deploymentId
  ]);
  await pool.query(`UPDATE deployment_hosts SET status='SKIPPED', finished_at=now() WHERE deployment_id=$1 AND status='PENDING'`, [
    req.params.deploymentId
  ]);
  res.json({ ok: true });
});

deploymentsRouter.post('/deployments/:deploymentId/retry-failed', requireRole('operator', 'admin'), async (req, res) => {
  await pool.query(`UPDATE deployment_hosts SET status='PENDING', started_at=null, finished_at=null, message=null WHERE deployment_id=$1 AND status='FAILED'`, [
    req.params.deploymentId
  ]);
  res.json({ ok: true });
});

/**
 * Process scheduled deployments that are ready to start.
 * Called periodically by background job.
 * Returns count of deployments processed.
 */
export async function processScheduledDeployments(): Promise<number> {
  const now = new Date();

  // Find deployments that are QUEUED and scheduled_at <= now
  const scheduledRes = await pool.query(
    `SELECT id FROM deployments
     WHERE status='QUEUED' AND scheduled_at IS NOT NULL AND scheduled_at <= $1
     ORDER BY scheduled_at ASC
     LIMIT 10`,
    [now]
  );

  let processedCount = 0;
  for (const row of scheduledRes.rows) {
    // Clear scheduled_at so this deployment is not picked up again
    await pool.query(
      `UPDATE deployments SET scheduled_at=NULL WHERE id=$1`,
      [row.id]
    );

    // Actually start the deployment using the shared execution logic
    try {
      const result = await executeDeploymentStart(row.id, undefined);
      // eslint-disable-next-line no-console
      console.log(`[Scheduled Deployments] Auto-started deployment ${row.id} — ok=${result.ok}, exitCode=${result.exitCode}`);
    } catch (error: any) {
      // eslint-disable-next-line no-console
      console.error(`[Scheduled Deployments] Failed to auto-start deployment ${row.id}:`, error.message);

      // Mark the deployment as FAILED so it doesn't remain in a stuck state
      await pool.query(
        `UPDATE deployments SET status='FAILED', finished_at=now() WHERE id=$1 AND status IN ('QUEUED', 'RUNNING')`,
        [row.id]
      );
      await pool.query(
        `UPDATE deployment_hosts SET status='FAILED', finished_at=now(), message=$2 WHERE deployment_id=$1 AND status IN ('PENDING', 'RUNNING')`,
        [row.id, error.message || 'Scheduled deployment start failed']
      );
    }

    processedCount++;
  }

  return processedCount;
}


