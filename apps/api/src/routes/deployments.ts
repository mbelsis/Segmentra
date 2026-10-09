import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { Router } from 'express';
import { z } from 'zod';

import { compileHostPolicy, firewallBackend, type FirewallBackend, type RuleDirection } from '@segmentra/compiler';
import { SEGMENTRA_MANAGER_PY } from '@segmentra/executor';
import { parseAnsibleRecap, runAnsiblePlaybook, runSshDeployment, checkHostReadiness, checkHostPersistence, checkPrivateKey, persistenceSummary, readHostFirewallRules, type AnsibleAgentKey, type PersistenceResult, type SshHost, type SshHostInfo } from '@segmentra/executor';

import { pool } from '../db/pool.js';
import { env } from '../lib/env.js';
import { requireAuth, requireRole } from '../middleware/auth.js';
import { addDestinationSets, compilerDestination, getProtectedDestinations } from '../services/forward-rules.js';
import { createAuditEvent } from '../services/audit.js';
import { getSshCredentialForHost, loadSshCredential, materializeSshCredential, sshAuthFields, type MaterializedSshCredential } from '../services/ssh-credentials.js';
import { checkDeploymentSafety } from '../services/safety-check.js';
import { isPolicyVersionHighRisk } from '../services/high-risk.js';
import { notifyDeploymentEvent } from '../services/notifications.js';

export const deploymentsRouter = Router();
deploymentsRouter.use(requireAuth);

// Host deployment timeout: 10 minutes (600000 ms)
const HOST_DEPLOYMENT_TIMEOUT_MS = 10 * 60 * 1000;

/** Policy version statuses that may be deployed. */
const DEPLOYABLE_VERSION_STATUSES = ['APPROVED', 'DEPLOYED'];

/** Deployments currently being executed by this process (guards resume while a run is winding down). */
const activeExecutions = new Set<string>();

function truncateMessage(msg: string, max = 500): string {
  const m = msg.trim();
  return m.length > max ? `${m.slice(0, max)}…` : m;
}

/** Mark the policy version DEPLOYED once a deployment of it has fully succeeded. */
/**
 * When an automatic expiry REVERT deployment finishes, record the outcome on the hosts of the
 * deployment that expired (they show REVERT_QUEUED until then).
 */
async function recordRevertOutcome(revertDeploymentId: string): Promise<void> {
  try {
    await pool.query(
      `UPDATE deployment_hosts orig
          SET expiry_status = CASE WHEN rev.status = 'SUCCEEDED' THEN 'REVERTED' ELSE 'FAILED' END,
              expiry_message = CASE WHEN rev.status = 'SUCCEEDED'
                                    THEN 'Previous version redeployed by deployment ' || d.id::text
                                    ELSE 'Automatic revert failed: ' || COALESCE(rev.message, rev.status) END,
              expiry_processed_at = now()
         FROM deployments d
         JOIN deployment_hosts rev ON rev.deployment_id = d.id
        WHERE d.id = $1
          AND d.revert_of_deployment_id IS NOT NULL
          AND orig.deployment_id = d.revert_of_deployment_id
          AND orig.host_id = rev.host_id
          AND orig.expiry_status = 'REVERT_QUEUED'
          AND rev.status IN ('SUCCEEDED', 'FAILED', 'SKIPPED')`,
      [revertDeploymentId]
    );
  } catch (e) {
    // eslint-disable-next-line no-console
    console.error('[expiry] could not record revert outcome:', (e as Error)?.message ?? e);
  }
}

async function markVersionDeployed(client: { query: (text: string, params?: any[]) => Promise<unknown> }, deploymentId: string) {
  await client.query(
    `UPDATE policy_versions SET status='DEPLOYED'
     WHERE id=(SELECT policy_version_id FROM deployments WHERE id=$1) AND status='APPROVED'`,
    [deploymentId]
  );
}

/** Fail a deployment that could not be (fully) started. Never overwrites CANCELLED/PAUSED. */
async function failDeployment(deploymentId: string, message: string) {
  const upd = await pool.query(
    `UPDATE deployments SET status='FAILED', finished_at=now(), progress=$2
     WHERE id=$1 AND status IN ('RUNNING', 'QUEUED')
     RETURNING id`,
    [deploymentId, JSON.stringify({ phase: 'failed', error: message })]
  );
  await pool.query(
    `UPDATE deployment_hosts SET status='FAILED', finished_at=now(), message=$2
     WHERE deployment_id=$1 AND status IN ('RUNNING', 'PENDING')`,
    [deploymentId, truncateMessage(message)]
  );
  if (upd.rows[0]) notifyDeploymentEvent('DEPLOYMENT_FAILED', deploymentId, { error: truncateMessage(message) });
}

/**
 * Ansible doesn't return a live ruleset hash, so read the host's Segmentra state once after a
 * successful run and store it as the drift baseline (same read/normalization as compliance).
 * Best-effort: on failure the baseline stays NULL and compliance reports 'unknown'.
 */
async function recordLiveBaseline(deploymentId: string, host: any, backend?: FirewallBackend): Promise<{ unreachable?: string }> {
  if (!host?.mgmt_ip) return {};
  let cred: MaterializedSshCredential | null = null;
  try {
    cred = await getSshCredentialForHost(host.id);
    const read = await readHostFirewallRules({
      hostname: host.hostname,
      ip: String(host.mgmt_ip),
      port: host.ssh_port || 22,
      ...sshAuthFields(cred),
      backend: backend ?? 'auto'
    });
    if (read.success && read.rulesHash) {
      await pool.query(
        `UPDATE deployment_hosts SET applied_live_hash=$3 WHERE deployment_id=$1 AND host_id=$2`,
        [deploymentId, host.id, read.rulesHash]
      );
    } else if (!read.success && /ssh: connect to host|Connection timed out|Connection refused|No route to host|kex_exchange_identification|Connection closed by/i.test(String(read.error ?? ''))) {
      // A new SSH connection fails right after the apply: the policy most likely locked
      // Segmentra out (the Ansible run itself reused its already-open connection).
      return { unreachable: String(read.error).trim().split('\n').pop() };
    }
  } catch (e) {
    // eslint-disable-next-line no-console
    console.warn(`[deployments] could not record live baseline for ${host.hostname}:`, (e as Error)?.message ?? e);
  } finally {
    cred?.cleanup();
  }
  return {};
}

/** deployment_hosts.persistence_* values for a reboot persistence result (NULLs when not reported). */
function persistenceColumns(p: PersistenceResult | undefined): [string | null, string | null, string | null] {
  if (!p) return [null, null, null];
  return [p.status, p.method, truncateMessage(persistenceSummary(p), 2000)];
}

/**
 * Ansible runs the same host scripts (persist) but its output is not parsed: read the reboot
 * persistence state of the host afterwards with a read-only check and store it. Best-effort.
 */
async function recordPersistence(deploymentId: string, host: any, backend?: FirewallBackend): Promise<void> {
  if (!host?.mgmt_ip || !backend) return;
  let cred: MaterializedSshCredential | null = null;
  try {
    cred = await getSshCredentialForHost(host.id);
    const p = await checkHostPersistence(
      { hostname: host.hostname, ip: String(host.mgmt_ip), port: host.ssh_port || 22, ...sshAuthFields(cred), backend },
      backend
    );
    const [status, method, message] = persistenceColumns(p);
    await pool.query(
      `UPDATE deployment_hosts SET persistence_status=$3, persistence_method=$4, persistence_message=$5
       WHERE deployment_id=$1 AND host_id=$2`,
      [deploymentId, host.id, status, method, p.error ? truncateMessage(`${message ?? ''} (check failed: ${p.error})`, 2000) : message]
    );
  } catch (e) {
    // eslint-disable-next-line no-console
    console.warn(`[deployments] could not record reboot persistence for ${host.hostname}:`, (e as Error)?.message ?? e);
  } finally {
    cred?.cleanup();
  }
}

/**
 * Check for and timeout stale host deployments that have been RUNNING for too long
 * This function is exported so it can be called from the main index.ts for periodic checks
 */
export async function checkAndTimeoutStaleHosts() {
  const client = await pool.connect();
  try {
  await client.query('BEGIN');
  const timeoutThreshold = new Date(Date.now() - HOST_DEPLOYMENT_TIMEOUT_MS);

  // Find hosts that have been RUNNING for longer than the timeout (with row lock)
  const staleHosts = await client.query(
    `UPDATE deployment_hosts
     SET status='FAILED', finished_at=now(), message='Deployment timeout: Host did not respond within 10 minutes'
     WHERE status='RUNNING'
     AND started_at IS NOT NULL
     AND started_at < $1
     RETURNING deployment_id, host_id`,
    [timeoutThreshold]
  );

  const finishedViaTimeout: Array<{ id: string; status: string }> = [];
  if (staleHosts.rows.length > 0) {
    // Check if any deployments need to be updated to PARTIAL or FAILED
    const deploymentIds = [...new Set(staleHosts.rows.map((r: any) => r.deployment_id))];
    
    for (const deploymentId of deploymentIds) {
      // Check deployment status
      const depRes = await client.query(
        `SELECT status FROM deployments WHERE id=$1`,
        [deploymentId]
      );

      if (depRes.rows[0]?.status === 'RUNNING') {
        // Check if all hosts are done (SUCCEEDED, FAILED, or SKIPPED)
        const hostStatusRes = await client.query(
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
            await client.query(
              `UPDATE deployments SET status='PARTIAL', finished_at=now() WHERE id=$1`,
              [deploymentId]
            );
          } else if (failedCount === total) {
            finalStatus = 'FAILED';
            await client.query(
              `UPDATE deployments SET status='FAILED', finished_at=now() WHERE id=$1`,
              [deploymentId]
            );
          } else {
            finalStatus = 'SUCCEEDED';
            await client.query(
              `UPDATE deployments SET status='SUCCEEDED', finished_at=now() WHERE id=$1`,
              [deploymentId]
            );
            await markVersionDeployed(client, deploymentId);
          }

          // Create audit event for deployment completion (via timeout)
          const depRes = await client.query(
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
              const tagRes = await client.query(`SELECT name FROM tags WHERE id = ANY($1::uuid[])`, [targetQuery.tags]);
              targetNames.tags = tagRes.rows.map((r: any) => r.name);
            }
            
            if (targetQuery.vlans && Array.isArray(targetQuery.vlans) && targetQuery.vlans.length > 0) {
              const vlanRes = await client.query(`SELECT name FROM vlans WHERE id = ANY($1::uuid[])`, [targetQuery.vlans]);
              targetNames.vlans = vlanRes.rows.map((r: any) => r.name);
            }
            
            if (targetQuery.hosts && Array.isArray(targetQuery.hosts) && targetQuery.hosts.length > 0) {
              const hostRes = await client.query(`SELECT hostname FROM hosts WHERE id = ANY($1::uuid[])`, [targetQuery.hosts]);
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
          finishedViaTimeout.push({ id: deploymentId, status: finalStatus });
        }
      }
    }
  }
  
  await client.query('COMMIT');
  for (const f of finishedViaTimeout) {
    notifyDeploymentEvent(f.status === 'SUCCEEDED' ? 'DEPLOYMENT_COMPLETED' : 'DEPLOYMENT_FAILED', f.id, { completedVia: 'timeout_check' });
    await recordRevertOutcome(f.id);
  }
  return staleHosts.rows.length;
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
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
  scheduledAt: z.string().min(1).optional(), // datetime string from browser (e.g. "2026-03-18T11:46")
  expiresAt: z.string().min(1).optional(), // datetime string from browser
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

  // Validate that the policy version is APPROVED (or already DEPLOYED elsewhere)
  const versionRes = await pool.query(`SELECT status FROM policy_versions WHERE id=$1`, [b.policyVersionId]);
  if (!versionRes.rows[0]) {
    return res.status(404).json({ error: 'policy_version_not_found' });
  }
  if (!DEPLOYABLE_VERSION_STATUSES.includes(versionRes.rows[0].status)) {
    return res.status(400).json({
      error: 'policy_version_not_approved',
      message: `Policy version must be APPROVED or DEPLOYED to deploy. Current status: ${versionRes.rows[0].status}`
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

  // Safety check: verify SSH access will be preserved (with 10s timeout to avoid blocking)
  let safetyCheck: Awaited<ReturnType<typeof checkDeploymentSafety>> | null = null;
  try {
    safetyCheck = await Promise.race([
      checkDeploymentSafety({
        policyVersionId: b.policyVersionId,
        hostIds: targetIds.slice(0, 5), // Check a sample of hosts to limit latency
        userIp: req.ip
      }),
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error('safety_check_timeout')), 10000))
    ]);
  } catch (e: any) {
    // eslint-disable-next-line no-console
    console.warn(`[Safety Check] Skipped: ${e.message}`);
  }

  // For FULL mode deployments, require SSH access to be preserved (only if check completed)
  if (safetyCheck && b.mode === 'FULL' && !safetyCheck.sshAccessPreserved && safetyCheck.errors.length > 0) {
    return res.status(400).json({
      error: 'safety_check_failed',
      message: 'Deployment would block SSH access from management VLAN',
      safetyCheck
    });
  }

  // For other modes, warn but allow (user can proceed with caution)
  if (safetyCheck && !safetyCheck.sshAccessPreserved && safetyCheck.errors.length > 0) {
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
  if (scheduledAt && isNaN(scheduledAt.getTime())) {
    return res.status(400).json({ error: 'invalid_scheduled_at', message: 'Invalid scheduled date' });
  }
  if (expiresAt && isNaN(expiresAt.getTime())) {
    return res.status(400).json({ error: 'invalid_expires_at', message: 'Invalid expiry date' });
  }
  const expiryAction = b.expiryAction ?? 'NOTIFY_ONLY';
  const status = scheduledAt && scheduledAt > new Date() ? 'SCHEDULED' : 'QUEUED';

  // High-risk deployments need a second person (approver/admin) to approve before they can start.
  const requiresApproval = isHighRisk;

  const client = await pool.connect();
  let deployment: any;
  try {
    await client.query('BEGIN');
    const { rows } = await client.query(
      `INSERT INTO deployments (policy_version_id, mode, target_query, target_count, created_by, canary_size, batch_size, scheduled_at, status, expires_at, expiry_action, requires_approval)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
       RETURNING *`,
      [b.policyVersionId, b.mode, b.targetQuery, targetIds.length, userId, b.canarySize ?? null, b.batchSize ?? null, scheduledAt, status, expiresAt, expiryAction, requiresApproval]
    );
    deployment = rows[0];
    await client.query(
      `INSERT INTO deployment_hosts (deployment_id, host_id)
       SELECT $1, unnest($2::uuid[]) ON CONFLICT DO NOTHING`,
      [deployment.id, targetIds]
    );
    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
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
      batchSize: b.batchSize || null,
      isHighRisk,
      requiresApproval
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

  // Get paginated results with creator username
  const query = `
    SELECT d.*, u.username as created_by_username, ua.username as approved_by_username
    FROM deployments d
    LEFT JOIN users u ON u.id = d.created_by
    LEFT JOIN users ua ON ua.id = d.approved_by
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
  const { rows } = await pool.query(
    `SELECT d.*, u.username AS created_by_username, u.display_name AS created_by_display_name,
            ua.username AS approved_by_username
     FROM deployments d
     LEFT JOIN users u ON u.id = d.created_by
     LEFT JOIN users ua ON ua.id = d.approved_by
     WHERE d.id=$1`,
    [req.params.deploymentId]
  );
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

/** Quote a string as a YAML double-quoted scalar (JSON strings are valid YAML 1.2 double-quoted scalars). */
function yamlQuote(value: string): string {
  return JSON.stringify(value);
}

/** Inventory hostnames double as file names (host_rules/, host_vars/); refuse anything odd. */
const SAFE_INVENTORY_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

/**
 * Write the per-host Ansible connection secrets. Key credentials are materialised once per
 * credential into <bundle>/.secrets/ (0600, dir 0700) exactly as stored — a passphrase-protected
 * key stays encrypted on disk — and referenced by runner path from the inventory. Passwords
 * never go into the INI inventory or onto a command line: the login password and the sudo
 * (become) password live in <bundle>/host_vars/<inventory_name>.yml (0600) as !unsafe strings
 * so Jinja never templates them. Key passphrases are never written anywhere: the playbook runs
 * under ssh-agent in the runner and the passphrase reaches ssh-add only through the environment
 * (see agentKeys() and runAnsiblePlaybook). Everything is removed by cleanup() after the run.
 */
export class AnsibleSecrets {
  private readonly secretsDir: string;
  private readonly hostVarsDir: string;
  private readonly keyByCred = new Map<string, MaterializedSshCredential>();
  private readonly files = new Set<string>();
  private readonly agentKeyList: AnsibleAgentKey[] = [];

  constructor(private readonly bundleDir: string, private readonly deploymentId: string) {
    this.secretsDir = path.join(bundleDir, '.secrets');
    this.hostVarsDir = path.join(bundleDir, 'host_vars');
  }

  private writeHostVars(inventoryName: string, vars: Record<string, string>) {
    fs.mkdirSync(this.hostVarsDir, { recursive: true, mode: 0o700 });
    const file = path.join(this.hostVarsDir, `${inventoryName}.yml`);
    const yaml = `---\n${Object.entries(vars).map(([k, v]) => `${k}: !unsafe ${yamlQuote(v)}`).join('\n')}\n`;
    fs.writeFileSync(file, yaml, { encoding: 'utf8', mode: 0o600 });
    fs.chmodSync(file, 0o600);
    this.files.add(file);
  }

  /** Passphrase-protected keys to load into the run's ssh-agent (runner paths). */
  agentKeys(): AnsibleAgentKey[] {
    return [...this.agentKeyList];
  }

  /** Returns the inventory connection vars for the host (no secrets inline). Throws missing_ssh_credential. */
  async connectionVarsFor(host: { id: string; inventoryName: string; port: number }): Promise<string> {
    const cred = await loadSshCredential(host.id);
    if (!cred) throw new Error('missing_ssh_credential');
    const username = String(cred.username ?? '');
    if (!username || /\s/.test(username)) throw new Error('invalid_ssh_username');
    const vars = [`ansible_user=${username}`, `ansible_port=${host.port}`];
    const authMethod = String(cred.auth_method ?? 'KEY').toUpperCase();

    if (authMethod === 'PASSWORD') {
      const m = await materializeSshCredential(cred);
      if (m.authMethod !== 'password') throw new Error('unexpected_credential_type');
      // The playbook escalates with become/sudo on every task. become password: the configured
      // sudo password (login or separate); with "sudo without password" the login password is
      // still provided (Ansible only sends it when sudo prompts).
      const become = m.sudo.mode === 'PASSWORD' ? m.sudo.password : m.password;
      this.writeHostVars(host.inventoryName, { ansible_password: m.password, ansible_become_password: become });
      vars.push('ansible_connection=ssh');
      return vars.join(' ');
    }

    const credKey = String(cred.id ?? username);
    let m = this.keyByCred.get(credKey);
    if (!m) {
      fs.mkdirSync(this.secretsDir, { recursive: true, mode: 0o700 });
      m = await materializeSshCredential(cred, this.secretsDir);
      this.keyByCred.set(credKey, m);
      if (m.authMethod === 'key' && m.keyPassphrase) {
        // ssh matches the agent's key through the public half next to the (encrypted) key file.
        const check = await checkPrivateKey(fs.readFileSync(m.privateKeyPath, 'utf8'), m.keyPassphrase);
        if (!check.ok || !check.publicKey) throw new Error('invalid_key_or_passphrase');
        const pubPath = `${m.privateKeyPath}.pub`;
        fs.writeFileSync(pubPath, `${check.publicKey}\n`, { encoding: 'utf8', mode: 0o600 });
        this.files.add(pubPath);
        this.agentKeyList.push({
          keyPath: `/bundles/${this.deploymentId}/.secrets/${path.basename(m.privateKeyPath)}`,
          passphrase: m.keyPassphrase
        });
      }
    }
    if (m.authMethod !== 'key') throw new Error('unexpected_credential_type');
    const runnerKeyPath = `/bundles/${this.deploymentId}/.secrets/${path.basename(m.privateKeyPath)}`;
    vars.push(`ansible_ssh_private_key_file=${runnerKeyPath}`);
    if (m.sudo.mode === 'PASSWORD') this.writeHostVars(host.inventoryName, { ansible_become_password: m.sudo.password });
    return vars.join(' ');
  }

  /** Delete every key file and host_vars file written for this run (best effort, idempotent). */
  cleanup() {
    for (const m of this.keyByCred.values()) m.cleanup();
    this.keyByCred.clear();
    this.agentKeyList.length = 0;
    for (const f of this.files) {
      try { fs.rmSync(f, { force: true }); } catch { /* best effort */ }
    }
    this.files.clear();
    for (const d of [this.secretsDir, this.hostVarsDir]) {
      try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
    }
  }
}

async function generateBundle(deploymentId: string, opts: { ansible: boolean } = { ansible: true }) {
  // Validate deploymentId to prevent path traversal
  if (!/^[0-9a-f-]+$/i.test(deploymentId)) {
    throw new Error('Invalid deployment ID format');
  }
  const bundleDir = path.join(env.BUNDLES_DIR, deploymentId);
  // Verify the resolved path is within BUNDLES_DIR
  const resolvedBundle = path.resolve(bundleDir);
  const resolvedBase = path.resolve(env.BUNDLES_DIR);
  if (!resolvedBundle.startsWith(resolvedBase)) {
    throw new Error('Invalid bundle path');
  }
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
     AND status='PENDING'
     AND host_id IN (SELECT id FROM hosts WHERE enabled=false)`,
    [deploymentId]
  );

  // Only hosts still waiting to be deployed (supports resume and retry-failed)
  const hostRows = await pool.query(
    `SELECT h.id, h.hostname, h.mgmt_ip, h.ssh_port, h.firewall_backend
     FROM deployment_hosts dh
     JOIN hosts h ON h.id = dh.host_id
     WHERE dh.deployment_id=$1 AND h.enabled=true AND dh.status='PENDING'
     ORDER BY h.hostname ASC`,
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
            use_policy_interface_scope, interface_scope_type, interface_scope_roles, interface_scope_names,
            destination_type, destination_value
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
  // FORWARD rule destinations (gateways): dst_* sets
  await addDestinationSets(rRes.rows, sets);

  const manifest = {
    deployment_id: deploymentId,
    policy_version_id: dep.policy_version_id,
    interface_scope: policyInterfaceScope,
    target_count: dep.target_count
  };
  fs.writeFileSync(path.join(bundleDir, 'manifest.json'), JSON.stringify(manifest, null, 2));

  const inventoryLines: string[] = ['[all]'];
  const hostPolicyHashes: Map<string, string> = new Map(); // host_id -> policy hash
  const hostPolicyFiles: Map<string, { path: string; ip6Path?: string; backend: FirewallBackend }> = new Map();
  fs.writeFileSync(path.join(bundleDir, 'segmentra-manager.py'), SEGMENTRA_MANAGER_PY, { mode: 0o600 });
  const ansibleSecrets = opts.ansible ? new AnsibleSecrets(bundleDir, deploymentId) : null;
  const mgmtSshCidrs = await getManagementVlanCidrs();

  const totalHosts = hostRows.rows.length;
  await updateProgress(deploymentId, { phase: 'checking', checked: 0, totalToCheck: totalHosts, deployed: 0, totalToDeploy: totalHosts, warnings: [] });

  const warnings: string[] = [];
  let checkedCount = 0;
  try {
  for (const h of hostRows.rows as any[]) {
      const ifsRes = await pool.query(`SELECT name, role, enabled FROM host_interfaces WHERE host_id=$1`, [h.id]);

      // Auto-detect backend if set to 'auto' or null
      let backend: FirewallBackend;
      if (h.firewall_backend && h.firewall_backend !== 'auto') {
        backend = firewallBackend(h.firewall_backend);
      } else if (h.firewall_backend === 'auto' || !h.firewall_backend) {
        // Perform auto-detection via SSH (KEY or PASSWORD credential, host-scoped preferred)
        let materialized: MaterializedSshCredential | null = null;
        try {
          materialized = await getSshCredentialForHost(h.id);
          const sshHostInfo: SshHostInfo = {
            hostname: h.hostname,
            ip: String(h.mgmt_ip),
            port: h.ssh_port || 22,
            ...sshAuthFields(materialized)
          };
          const readinessResult = await checkHostReadiness(sshHostInfo);
          if (!readinessResult.ready || readinessResult.backend === 'unknown') {
            throw new Error(`Host readiness failed: ${readinessResult.errors.join('; ')}`);
          }
          backend = readinessResult.backend;

          // Update host's firewall_backend if auto-detected
          await pool.query(
            `UPDATE hosts SET firewall_backend=$1 WHERE id=$2`,
            [readinessResult.backend, h.id]
          );
        } catch (detectionError: any) {
          if (detectionError?.message === 'missing_ssh_credential') throw detectionError;
          // eslint-disable-next-line no-console
          console.warn(`[Auto-detection failed for ${h.hostname}]`, detectionError.message);
          const message = truncateMessage(`Firewall detection failed: ${detectionError.message}`);
          warnings.push(`${h.hostname}: ${message}`);
          await pool.query(`UPDATE deployment_hosts SET status='FAILED', finished_at=now(), message=$3 WHERE deployment_id=$1 AND host_id=$2`, [deploymentId, h.id, message]);
          continue;
        } finally {
          materialized?.cleanup();
        }
      } else {
        backend = 'nftables';
      }

      checkedCount++;
      await updateProgress(deploymentId, { phase: 'checking', checked: checkedCount, totalToCheck: totalHosts, deployed: 0, totalToDeploy: totalHosts, currentHost: h.hostname, warnings });

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
          direction: (r.direction ?? 'IN') as RuleDirection,
          action: r.action,
          protocol: r.protocol,
          ports: r.ports,
          sourceType: r.source_type,
          sourceValue: r.source_value,
          logMode: r.log_mode,
          comment: r.comment,
          usePolicyInterfaceScope: Boolean(r.use_policy_interface_scope),
          interfaceScope: ruleScope,
          remote,
          ...compilerDestination(r)
        };
      });
      // IoT devices assigned to this host as a gateway: forwarded traffic to them is default-deny.
      const protectedDestinations = await getProtectedDestinations(h.id);

      let compiled: ReturnType<typeof compileHostPolicy>;
      try {
        compiled = compileHostPolicy({
          host: {
            id: h.id,
            hostname: h.hostname,
            mgmtIp: h.mgmt_ip ? String(h.mgmt_ip) : null,
            sshPort: h.ssh_port ? Number(h.ssh_port) : undefined,
            firewallBackend: backend,
            interfaces: ifsRes.rows.map((i: any) => ({ name: i.name, role: i.role, enabled: i.enabled }))
          },
          policyInterfaceScope,
          rules,
          sets,
          baseline: { mgmtSshCidrs },
          protectedDestinations
        });
      } catch (compileError: any) {
        if (compileError?.name !== 'CompileError') throw compileError;
        // Invalid policy for this host: fail just this host with a clear message and keep going.
        const message = truncateMessage(`Policy compile error: ${compileError.message}`);
        warnings.push(`${h.hostname}: ${message}`);
        await pool.query(
          `UPDATE deployment_hosts SET status='FAILED', finished_at=now(), message=$3
           WHERE deployment_id=$1 AND host_id=$2`,
          [deploymentId, h.id, message]
        );
        continue;
      }

      // Ansible connection vars (host-scoped credential first, KEY or PASSWORD)
      let connectionVars = '';
      if (ansibleSecrets) {
        if (!SAFE_INVENTORY_NAME.test(String(h.hostname))) {
          const message = `Hostname "${h.hostname}" cannot be used as an Ansible inventory name`;
          warnings.push(`${h.hostname}: ${message}`);
          await pool.query(
            `UPDATE deployment_hosts SET status='FAILED', finished_at=now(), message=$3
             WHERE deployment_id=$1 AND host_id=$2`,
            [deploymentId, h.id, message]
          );
          continue;
        }
        try {
          connectionVars = await ansibleSecrets.connectionVarsFor({ id: h.id, inventoryName: h.hostname, port: Number(h.ssh_port) || 22 });
        } catch (credError: any) {
          const message = truncateMessage(`SSH credential error: ${credError?.message ?? String(credError)}`);
          warnings.push(`${h.hostname}: ${message}`);
          await pool.query(
            `UPDATE deployment_hosts SET status='FAILED', finished_at=now(), message=$3
             WHERE deployment_id=$1 AND host_id=$2`,
            [deploymentId, h.id, message]
          );
          continue;
        }
      }

      const ext = compiled.backend === 'nftables' ? 'nft' : compiled.backend === 'iptables' ? 'iptables' : `${compiled.backend}.json`;
      const policyFileHostPath = path.join(hostRulesDir, `${h.hostname}.${ext}`);
      fs.writeFileSync(policyFileHostPath, compiled.text, 'utf8');
      let ip6PolicyFileHostPath: string | undefined;
      if (compiled.ip6tablesRules) {
        ip6PolicyFileHostPath = path.join(hostRulesDir, `${h.hostname}.ip6tables`);
        fs.writeFileSync(ip6PolicyFileHostPath, compiled.ip6tablesRules, 'utf8');
      }
      hostPolicyFiles.set(h.id, {
        path: policyFileHostPath,
        ip6Path: ip6PolicyFileHostPath,
        backend: compiled.backend
      });

      // Store hash of compiled policy for this host (for drift detection)
      const policyHash = crypto.createHash('sha256').update(compiled.text, 'utf8').digest('hex');
      hostPolicyHashes.set(h.id, policyHash);

      // Ansible runner sees bundle at /bundles/<deploymentId>/...
      const policyFileRunnerPath = `/bundles/${deploymentId}/host_rules/${h.hostname}.${ext}`;

      const ip6Var = ip6PolicyFileHostPath ? ` segmentra_ip6_policy_file=/bundles/${deploymentId}/host_rules/${h.hostname}.ip6tables` : '';
      inventoryLines.push(
        `${h.hostname} ansible_host=${String(h.mgmt_ip)} ${connectionVars} ansible_become=yes ansible_become_method=sudo segmentra_backend=${compiled.backend} segmentra_manager_script=/bundles/${deploymentId}/segmentra-manager.py segmentra_policy_file=${policyFileRunnerPath}${ip6Var}`
      );
  }

  fs.writeFileSync(path.join(bundleDir, 'inventory.ini'), inventoryLines.join('\n') + '\n', 'utf8');
  } catch (e) {
    // Never leave decrypted credentials behind when bundle generation fails.
    ansibleSecrets?.cleanup();
    throw e;
  }

  // Calculate bundle hash from manifest JSON (SHA-256)
  const manifestJson = JSON.stringify(manifest);
  const bundleHash = crypto.createHash('sha256').update(manifestJson, 'utf8').digest('hex');

  // artifacts row
  await pool.query(
    `INSERT INTO deployment_artifacts (deployment_id, bundle_path, bundle_hash, manifest)
     VALUES ($1,$2,$3,$4)`,
    [deploymentId, bundleDir, bundleHash, manifest]
  );

  return {
    bundleDir,
    hostPolicyHashes,
    hostPolicyFiles,
    hostRows: hostRows.rows as any[],
    warnings,
    cleanupSecrets: () => ansibleSecrets?.cleanup(),
    ansibleAgentKeys: () => ansibleSecrets?.agentKeys() ?? []
  };
}

async function updateProgress(deploymentId: string, progress: Record<string, any>) {
  await pool.query(`UPDATE deployments SET progress = $2 WHERE id = $1`, [deploymentId, JSON.stringify(progress)]);
}

/**
 * Atomically move a deployment into RUNNING. Only succeeds when the deployment is in one of
 * `fromStatuses` and, if it requires approval, has been approved. Returns the claimed row or null.
 */
export async function claimDeploymentForStart(deploymentId: string, fromStatuses: string[], extraWhere = ''): Promise<any | null> {
  const { rows } = await pool.query(
    `UPDATE deployments
     SET status='RUNNING', started_at=COALESCE(started_at, now()), finished_at=NULL, scheduled_at=NULL, progress=$3
     WHERE id=$1 AND status = ANY($2::text[])
       AND (requires_approval = false OR approved_by IS NOT NULL)
       ${extraWhere}
     RETURNING *`,
    [deploymentId, fromStatuses, JSON.stringify({ phase: 'starting', checked: 0, totalToCheck: 0, deployed: 0, totalToDeploy: 0, warnings: [] })]
  );
  return rows[0] ?? null;
}

/**
 * Core deployment execution logic, shared by POST /start, /resume and the scheduled-deployment job.
 * The caller must already have claimed the deployment (status RUNNING) via claimDeploymentForStart.
 * Only hosts in PENDING state are deployed.
 *
 * Returns { ok, exitCode, executionId } on success.
 * Throws on failure (caller is responsible for error handling, e.g. failDeployment()).
 *
 * @param ipAddress - optional IP of the requesting user (for audit trail)
 */
export async function executeDeploymentStart(
  deploymentId: string,
  ipAddress?: string
): Promise<{ ok: boolean; exitCode: number; executionId: string | null }> {
  activeExecutions.add(deploymentId);
  try {
    return await executeDeploymentStartInner(deploymentId, ipAddress);
  } finally {
    activeExecutions.delete(deploymentId);
  }
}

async function executeDeploymentStartInner(
  deploymentId: string,
  ipAddress?: string
): Promise<{ ok: boolean; exitCode: number; executionId: string | null }> {
    // Check for and timeout stale hosts before starting
    await checkAndTimeoutStaleHosts();

    // Re-check at execution time that the policy version is still deployable
    const versionRes = await pool.query(
      `SELECT pv.status FROM deployments d JOIN policy_versions pv ON pv.id = d.policy_version_id WHERE d.id=$1`,
      [deploymentId]
    );
    if (!versionRes.rows[0]) throw new Error('deployment_not_found');
    if (!DEPLOYABLE_VERSION_STATUSES.includes(versionRes.rows[0].status)) {
      throw new Error(`Policy version is ${versionRes.rows[0].status}; only APPROVED or DEPLOYED versions can be deployed`);
    }

    // Get executor setting
    const executorRes = await pool.query(
      `SELECT value FROM system_settings WHERE key='deployment_executor'`
    );
    const executor = executorRes.rows[0]?.value ?? 'ansible';

    // Hosts stay PENDING until their own deployment begins (so the stale-timeout only applies to hosts actually running)
    const { bundleDir, hostPolicyHashes, hostPolicyFiles, hostRows, warnings, cleanupSecrets, ansibleAgentKeys } =
      await generateBundle(deploymentId, { ansible: executor !== 'ssh' });
    try {

    const deployableHosts = hostRows.filter((h: any) => hostPolicyFiles.has(h.id));
    const deployHostCount = deployableHosts.length;
    await updateProgress(deploymentId, { phase: 'deploying', checked: deployHostCount, totalToCheck: deployHostCount, deployed: 0, totalToDeploy: deployHostCount, warnings });

    const stdoutPath = path.join(bundleDir, executor === 'ssh' ? 'ssh.stdout.log' : 'ansible.stdout.log');
    const stderrPath = path.join(bundleDir, executor === 'ssh' ? 'ssh.stderr.log' : 'ansible.stderr.log');

    let ok = false;
    let exitCode = 1;
    let executionId: string | null = null;

    if (deployHostCount === 0) {
      // Nothing to deploy (all hosts skipped or failed to compile)
      ok = false;
      exitCode = 1;
    } else if (executor === 'ssh') {
    // SSH Direct executor
    const executionIdRes = await pool.query(
      `INSERT INTO execution_runs (deployment_id, executor_type, command)
       VALUES ($1,'ssh_direct',$2)
       RETURNING id`,
      [deploymentId, 'ssh/scp direct execution']
    );
    executionId = executionIdRes.rows[0].id;

    const allStdout: string[] = [];
    const allStderr: string[] = [];
    let deployedCount = 0;
    let anyFailed = false;

    // CANARY / PROGRESSIVE rollout gates. Hosts are deployed one by one in hostname order.
    // CANARY: the first canarySize hosts (default 1) are the canary; if one of them fails, the
    // remaining hosts are not deployed. PROGRESSIVE: hosts go in batches of batchSize (default 5);
    // if a host fails, the rollout stops at the end of that batch. Halted hosts are SKIPPED with
    // a "Rollout halted:" message and are picked up again by retry-failed.
    const rolloutRes = await pool.query(
      `SELECT d.mode, d.canary_size, d.batch_size,
              (SELECT COUNT(*)::int FROM deployment_hosts dh WHERE dh.deployment_id = d.id AND dh.status IN ('SUCCEEDED', 'FAILED')) AS finished
       FROM deployments d WHERE d.id=$1`,
      [deploymentId]
    );
    const rolloutMode = String(rolloutRes.rows[0]?.mode ?? 'FULL');
    const canarySize = Math.max(1, Number(rolloutRes.rows[0]?.canary_size) || 1);
    const batchSize = Math.max(1, Number(rolloutRes.rows[0]?.batch_size) || 5);
    let finishedTotal = Number(rolloutRes.rows[0]?.finished) || 0; // includes hosts finished by an earlier (paused) run
    let batchHadFailure = false;
    const haltRollout = async (reason: string) => {
      const message = truncateMessage(`Rollout halted: ${reason}`);
      await pool.query(
        `UPDATE deployment_hosts SET status='SKIPPED', finished_at=now(), message=$2
         WHERE deployment_id=$1 AND status='PENDING'`,
        [deploymentId, message]
      );
      warnings.push(message);
      allStdout.push(`=== ${message} ===\n`);
    };

    try {
      for (const h of deployableHosts) {
        // Stop between hosts if the deployment was paused/stopped/cancelled
        const statusCheck = await pool.query(`SELECT status FROM deployments WHERE id = $1`, [deploymentId]);
        if (statusCheck.rows[0]?.status !== 'RUNNING') {
          allStdout.push(`=== ${h.hostname} ===\nNot processed (deployment ${statusCheck.rows[0]?.status ?? 'missing'})\n`);
          continue; // remaining hosts stay PENDING (resume) or were SKIPPED by /stop
        }

        // Claim this host: RUNNING with its own started_at, only if still PENDING
        const claim = await pool.query(
          `UPDATE deployment_hosts SET status='RUNNING', started_at=now(), finished_at=NULL, message=NULL
           WHERE deployment_id=$1 AND host_id=$2 AND status='PENDING' RETURNING host_id`,
          [deploymentId, h.id]
        );
        if (!claim.rows[0]) continue;

        await updateProgress(deploymentId, { phase: 'deploying', checked: deployHostCount, totalToCheck: deployHostCount, deployed: deployedCount, totalToDeploy: deployHostCount, currentHost: h.hostname, warnings });

        const policyFile = hostPolicyFiles.get(h.id)!;
        let cred: MaterializedSshCredential | null = null;
        let result: { success: boolean; stdout: string; stderr: string; exitCode: number; liveRulesHash?: string; skipped?: boolean; persistence?: PersistenceResult };
        try {
          cred = await getSshCredentialForHost(h.id, bundleDir);
          const sshHost: SshHost = {
            hostname: h.hostname,
            ip: String(h.mgmt_ip),
            port: h.ssh_port || 22,
            ...sshAuthFields(cred),
            policyFilePath: policyFile.path,
            ip6PolicyFilePath: policyFile.ip6Path,
            backend: policyFile.backend
          };
          const results = await runSshDeployment({ hosts: [sshHost] });
          result = results[0] ?? { success: false, stdout: '', stderr: 'no result returned', exitCode: 1 };
        } catch (e: any) {
          result = { success: false, stdout: '', stderr: e?.message ?? String(e), exitCode: 1 };
        } finally {
          cred?.cleanup();
        }

        allStdout.push(`=== ${h.hostname} ===\n${result.stdout}\n`);
        allStderr.push(`=== ${h.hostname} ===\n${result.stderr}\n`);

        if (!result.success) anyFailed = true;
        const policyHash = result.success ? hostPolicyHashes.get(h.id) || null : null;
        const liveHash = result.success ? (result.liveRulesHash ?? null) : null;
        const lastErrLine = String(result.stderr || '').trim().split('\n').filter(Boolean).pop() ?? '';
        const message = result.success ? 'ok' : truncateMessage(`ssh_failed${lastErrLine ? `: ${lastErrLine}` : ''}`);
        // Record the real outcome for this host (even if the deployment was paused meanwhile)
        const [persistStatus, persistMethod, persistMessage] = persistenceColumns(result.persistence);
        await pool.query(
          `UPDATE deployment_hosts
           SET status=$2, finished_at=now(), message=$3, applied_hash=$5, applied_live_hash=$6,
               persistence_status=$7, persistence_method=$8, persistence_message=$9
           WHERE deployment_id=$1 AND host_id=$4`,
          [deploymentId, result.success ? 'SUCCEEDED' : 'FAILED', message, h.id, policyHash, liveHash, persistStatus, persistMethod, persistMessage]
        );
        deployedCount++;
        finishedTotal++;

        if (rolloutMode === 'CANARY' && !result.success && finishedTotal <= canarySize) {
          await haltRollout(`canary host ${h.hostname} failed (canary size ${canarySize})`);
        } else if (rolloutMode === 'PROGRESSIVE') {
          if (!result.success) batchHadFailure = true;
          if (finishedTotal % batchSize === 0) {
            if (batchHadFailure) {
              await haltRollout(`a host in batch ${Math.ceil(finishedTotal / batchSize)} (batch size ${batchSize}) failed`);
            }
            batchHadFailure = false;
          }
        }
      }
    } finally {
      fs.writeFileSync(stdoutPath, allStdout.join('\n'), 'utf8');
      fs.writeFileSync(stderrPath, allStderr.join('\n'), 'utf8');
    }

    ok = !anyFailed;
    exitCode = ok ? 0 : 1;

    await pool.query(
      `UPDATE execution_runs
       SET exit_code=$2, stdout_path=$3, stderr_path=$4, finished_at=now(), status='DONE'
       WHERE id=$1`,
      [executionId, exitCode, stdoutPath, stderrPath]
    );
    } else {
    // Ansible executor (default) — deploys every host in the inventory in one run
    const executionIdRes = await pool.query(
      `INSERT INTO execution_runs (deployment_id, executor_type, command)
       VALUES ($1,'ansible_cli',$2)
       RETURNING id`,
      [deploymentId, 'docker exec ... ansible-playbook']
    );
    executionId = executionIdRes.rows[0].id;

    const bundleHostIds = deployableHosts.map((h: any) => h.id);
    await pool.query(
      `UPDATE deployment_hosts SET status='RUNNING', started_at=now(), finished_at=NULL, message=NULL
       WHERE deployment_id=$1 AND host_id = ANY($2::uuid[]) AND status='PENDING'`,
      [deploymentId, bundleHostIds]
    );

    let result: Awaited<ReturnType<typeof runAnsiblePlaybook>>;
    try {
      result = await runAnsiblePlaybook({
        runnerContainer: env.ANSIBLE_RUNNER_CONTAINER,
        inventoryPath: `/bundles/${deploymentId}/inventory.ini`,
        playbookPath: `/runner/playbooks/apply-firewall.yml`,
        agentKeys: ansibleAgentKeys(),
        stdoutPath,
        stderrPath
      });
    } finally {
      // Key files and password host_vars are only needed while the playbook runs.
      cleanupSecrets();
    }

    exitCode = result.exitCode;
    ok = exitCode === 0;

    await pool.query(
      `UPDATE execution_runs
       SET exit_code=$2, stdout_path=$3, stderr_path=$4, finished_at=now(), status='DONE'
       WHERE id=$1`,
      [executionId, exitCode, stdoutPath, stderrPath]
    );

    // Per-host outcome from the PLAY RECAP: the play does not abort other hosts when one fails
    // (any_errors_fatal: false), so a non-zero exit code alone must not fail every host.
    let recap = new Map<string, { ok: boolean; error?: string }>();
    try { recap = parseAnsibleRecap(fs.readFileSync(stdoutPath, 'utf8')); } catch { /* fall back to exit code */ }

    // Update every host that was in this run's inventory. Don't filter on status='RUNNING':
    // a long run may have been marked FAILED by the stale-host timeout or PAUSED meanwhile,
    // but the playbook result is the real outcome. Hosts SKIPPED by a stop are left alone.
    for (const hostId of bundleHostIds) {
      const hostname = deployableHosts.find((h: any) => h.id === hostId)?.hostname;
      const outcome = hostname ? recap.get(String(hostname)) : undefined;
      const hostOk = result.timedOut ? false : outcome ? outcome.ok : ok;
      if (hostOk) {
        await pool.query(
          `UPDATE deployment_hosts
           SET status='SUCCEEDED', finished_at=now(), message='ok', applied_hash=$3
           WHERE deployment_id=$1 AND host_id=$2 AND status <> 'SKIPPED'`,
          [deploymentId, hostId, hostPolicyHashes.get(hostId) || null]
        );
        const baseline = await recordLiveBaseline(deploymentId, deployableHosts.find((h: any) => h.id === hostId), hostPolicyFiles.get(hostId)?.backend);
        if (!baseline.unreachable) {
          await recordPersistence(deploymentId, deployableHosts.find((h: any) => h.id === hostId), hostPolicyFiles.get(hostId)?.backend);
        }
        if (baseline.unreachable) {
          // The Ansible executor has no automatic revert (see docs/guide.md): report the lockout
          // instead of a success.
          await pool.query(
            `UPDATE deployment_hosts SET status='FAILED', message=$3
             WHERE deployment_id=$1 AND host_id=$2 AND status='SUCCEEDED'`,
            [deploymentId, hostId, truncateMessage(`Policy applied, but the host is not reachable over a new SSH connection afterwards (possible lockout; the Ansible executor has no automatic revert, restore access on the host or with scripts/restore-previous-policy.sh): ${baseline.unreachable}`)]
          );
        }
      } else {
        await pool.query(
          `UPDATE deployment_hosts
           SET status='FAILED', finished_at=now(), message=$3
           WHERE deployment_id=$1 AND host_id=$2 AND status <> 'SKIPPED'`,
          [deploymentId, hostId, truncateMessage(outcome?.error ? `ansible_failed: ${outcome.error}` : result.timedOut ? `ansible_failed: ${result.error ?? 'timed out'}` : 'ansible_failed')]
        );
      }
    }
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
    const unfinishedCount = (statusCounts['PENDING'] || 0) + (statusCounts['RUNNING'] || 0) + (statusCounts['PAUSED'] || 0);
    const total = succeededCount + failedCount + skippedCount;

    // Determine final status
    let finalStatus: string;
    if (failedCount > 0 && succeededCount > 0) {
      finalStatus = 'PARTIAL';
    } else if (failedCount > 0 || succeededCount === 0) {
      finalStatus = 'FAILED';
    } else {
      finalStatus = 'SUCCEEDED';
    }

    // Don't finalize while hosts are still pending (paused run) and never overwrite CANCELLED/PAUSED/EXPIRED.
    let finalized = false;
    if (unfinishedCount === 0) {
      const upd = await pool.query(
        `UPDATE deployments SET status=$2, finished_at=now()
         WHERE id=$1 AND status IN ('RUNNING', 'FAILED', 'PARTIAL', 'SUCCEEDED')
         RETURNING id`,
        [deploymentId, finalStatus]
      );
      finalized = Boolean(upd.rows[0]);
      if (finalized && finalStatus === 'SUCCEEDED') {
        await markVersionDeployed(pool, deploymentId);
      }
      if (finalized) {
        notifyDeploymentEvent(finalStatus === 'SUCCEEDED' ? 'DEPLOYMENT_COMPLETED' : 'DEPLOYMENT_FAILED', deploymentId);
        await recordRevertOutcome(deploymentId);
      }
    }

    if (!finalized) {
      const cur = await pool.query(`SELECT status FROM deployments WHERE id=$1`, [deploymentId]);
      await updateProgress(deploymentId, { phase: String(cur.rows[0]?.status ?? 'stopped').toLowerCase(), checked: deployHostCount, totalToCheck: deployHostCount, deployed: succeededCount + failedCount, totalToDeploy: deployHostCount, warnings });
      return { ok, exitCode, executionId };
    }

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

    await updateProgress(deploymentId, { phase: 'complete', checked: deployHostCount, totalToCheck: deployHostCount, deployed: deployHostCount, totalToDeploy: deployHostCount, warnings });

    return { ok, exitCode, executionId };
    } finally {
      // Idempotent: also covers errors thrown before the playbook ran.
      cleanupSecrets();
    }
}

/** Run a claimed deployment in the background; on error fail it (without clobbering CANCELLED/PAUSED). */
export function runDeploymentInBackground(deploymentId: string, ipAddress?: string, logPrefix = '[Deployment Start Error]') {
  setTimeout(async () => {
    try {
      await executeDeploymentStart(deploymentId, ipAddress);
    } catch (error: any) {
      // eslint-disable-next-line no-console
      console.error(logPrefix, error);
      try {
        await failDeployment(deploymentId, error?.message || 'Deployment start failed');
      } catch (e) {
        // eslint-disable-next-line no-console
        console.error('[Deployment] Failed to record deployment failure', e);
      }
    }
  }, 0);
}

/** Explain why a deployment could not be claimed for start. */
async function explainNotStartable(deploymentId: string, res: import('express').Response, allowed: string[]) {
  const depCheck = await pool.query(`SELECT status, requires_approval, approved_by FROM deployments WHERE id=$1`, [deploymentId]);
  const dep = depCheck.rows[0];
  if (!dep) return res.status(404).json({ error: 'not_found' });
  if (allowed.includes(dep.status) && dep.requires_approval && !dep.approved_by) {
    return res.status(409).json({
      error: 'deployment_requires_approval',
      message: 'This is a high-risk deployment. An approver or admin (other than its creator) must approve it before it can start.'
    });
  }
  return res.status(409).json({ error: 'not_startable', message: `Deployment is ${dep.status}; expected one of ${allowed.join(', ')}` });
}

deploymentsRouter.post('/deployments/:deploymentId/start', requireRole('operator', 'admin'), async (req, res) => {
  const deploymentId = req.params.deploymentId;

  // Validate the policy version is still deployable before claiming
  const verRes = await pool.query(
    `SELECT pv.status FROM deployments d JOIN policy_versions pv ON pv.id = d.policy_version_id WHERE d.id=$1`,
    [deploymentId]
  );
  if (!verRes.rows[0]) return res.status(404).json({ error: 'not_found' });
  if (!DEPLOYABLE_VERSION_STATUSES.includes(verRes.rows[0].status)) {
    return res.status(409).json({
      error: 'policy_version_not_approved',
      message: `The policy version is ${verRes.rows[0].status}; only APPROVED or DEPLOYED versions can be deployed.`
    });
  }

  // Atomically claim QUEUED/SCHEDULED -> RUNNING (prevents double-start and enforces approval)
  const claimed = await claimDeploymentForStart(deploymentId, ['QUEUED', 'SCHEDULED']);
  if (!claimed) return explainNotStartable(deploymentId, res, ['QUEUED', 'SCHEDULED']);

  await createAuditEvent({
    actorUserId: req.auth!.userId ?? null,
    action: 'DEPLOYMENT_STARTED',
    entityType: 'DEPLOYMENT',
    entityId: deploymentId,
    ipAddress: req.ip
  });
  notifyDeploymentEvent('DEPLOYMENT_STARTED', deploymentId, { startedBy: req.auth!.username });

  // Return 202 Accepted immediately — execution happens in background
  res.status(202).json({ ok: true, message: 'Deployment started. Monitor progress on the deployment detail page.', deploymentId });

  runDeploymentInBackground(deploymentId, req.ip);
});

/**
 * Approve a high-risk deployment (second person). Approver must not be the deployment creator.
 */
deploymentsRouter.post('/deployments/:deploymentId/approve', requireRole('approver', 'admin'), async (req, res) => {
  const deploymentId = req.params.deploymentId;
  const approverId = req.auth!.userId;
  if (!approverId) return res.status(401).json({ error: 'user_not_found' });

  const depRes = await pool.query(`SELECT status, created_by, requires_approval, approved_by FROM deployments WHERE id=$1`, [deploymentId]);
  const dep = depRes.rows[0];
  if (!dep) return res.status(404).json({ error: 'not_found' });
  if (!dep.requires_approval) return res.status(409).json({ error: 'approval_not_required', message: 'This deployment does not require approval.' });
  if (dep.approved_by) return res.status(409).json({ error: 'already_approved', message: 'This deployment has already been approved.' });
  if (dep.created_by && dep.created_by === approverId) {
    return res.status(403).json({
      error: 'cannot_approve_own_deployment',
      message: 'You cannot approve a deployment you created. A different approver is required for separation of duties.'
    });
  }

  const { rows } = await pool.query(
    `UPDATE deployments SET approved_by=$2, approved_at=now()
     WHERE id=$1 AND requires_approval=true AND approved_by IS NULL AND status IN ('QUEUED', 'SCHEDULED')
     RETURNING *`,
    [deploymentId, approverId]
  );
  if (!rows[0]) {
    return res.status(409).json({ error: 'not_approvable', message: `Deployment is ${dep.status}; only QUEUED or SCHEDULED deployments can be approved.` });
  }

  await createAuditEvent({
    actorUserId: approverId,
    action: 'DEPLOYMENT_APPROVED',
    entityType: 'DEPLOYMENT',
    entityId: deploymentId,
    ipAddress: req.ip,
    metadata: { approvedBy: req.auth!.username }
  });

  res.json({ deployment: rows[0] });
});

deploymentsRouter.post('/deployments/:deploymentId/pause', requireRole('operator', 'admin'), async (req, res) => {
  const deploymentId = req.params.deploymentId;

  // Atomically pause only a RUNNING deployment
  const upd = await pool.query(`UPDATE deployments SET status='PAUSED' WHERE id=$1 AND status='RUNNING' RETURNING id`, [deploymentId]);
  if (!upd.rows[0]) {
    const depRes = await pool.query(`SELECT status FROM deployments WHERE id=$1`, [deploymentId]);
    if (!depRes.rows[0]) return res.status(404).json({ error: 'deployment_not_found' });
    return res.status(409).json({ error: 'deployment_not_running', message: `Cannot pause deployment with status: ${depRes.rows[0].status}` });
  }

  // Hosts not yet started stay PENDING (deployed on resume). A host currently being deployed
  // finishes and records its real result; the executor stops before the next host.
  res.json({ ok: true });
});

deploymentsRouter.post('/deployments/:deploymentId/resume', requireRole('operator', 'admin'), async (req, res) => {
  const deploymentId = req.params.deploymentId;

  if (activeExecutions.has(deploymentId)) {
    return res.status(409).json({ error: 'deployment_still_stopping', message: 'The deployment is still finishing its current host. Try again in a moment.' });
  }

  // Legacy: hosts paused by older versions go back to PENDING so they are redeployed
  await pool.query(
    `UPDATE deployment_hosts SET status='PENDING', started_at=NULL, finished_at=NULL, message=NULL
     WHERE deployment_id=$1 AND status='PAUSED'
       AND EXISTS (SELECT 1 FROM deployments WHERE id=$1 AND status='PAUSED')`,
    [deploymentId]
  );

  const claimed = await claimDeploymentForStart(deploymentId, ['PAUSED']);
  if (!claimed) {
    const depRes = await pool.query(`SELECT status FROM deployments WHERE id=$1`, [deploymentId]);
    if (!depRes.rows[0]) return res.status(404).json({ error: 'deployment_not_found' });
    return res.status(409).json({ error: 'deployment_not_paused', message: `Cannot resume deployment with status: ${depRes.rows[0].status}` });
  }

  res.json({ ok: true });
  runDeploymentInBackground(deploymentId, req.ip, '[Deployment Resume Error]');
});

/**
 * Stop/cancel a deployment. Works for SCHEDULED, QUEUED, RUNNING and PAUSED deployments.
 * Hosts that have not finished are marked SKIPPED; a host mid-deploy records its real result.
 */
async function cancelDeployment(req: import('express').Request, res: import('express').Response) {
  const deploymentId = req.params.deploymentId;

  const upd = await pool.query(
    `UPDATE deployments SET status='CANCELLED', finished_at=now()
     WHERE id=$1 AND status IN ('SCHEDULED', 'QUEUED', 'RUNNING', 'PAUSED')
     RETURNING id`,
    [deploymentId]
  );
  if (!upd.rows[0]) {
    const depRes = await pool.query(`SELECT status FROM deployments WHERE id=$1`, [deploymentId]);
    if (!depRes.rows[0]) return res.status(404).json({ error: 'deployment_not_found' });
    return res.status(409).json({ error: 'deployment_not_stoppable', message: `Cannot stop deployment with status: ${depRes.rows[0].status}` });
  }

  await pool.query(
    `UPDATE deployment_hosts SET status='SKIPPED', finished_at=now(), message='Deployment stopped by user'
     WHERE deployment_id=$1 AND status IN ('PENDING', 'RUNNING', 'PAUSED')`,
    [deploymentId]
  );

  await createAuditEvent({
    actorUserId: req.auth!.userId,
    action: 'DEPLOYMENT_CANCELLED',
    entityType: 'DEPLOYMENT',
    entityId: deploymentId,
    ipAddress: req.ip,
    metadata: { by: req.auth!.username }
  });

  res.json({ ok: true });
}

deploymentsRouter.post('/deployments/:deploymentId/stop', requireRole('operator', 'admin'), cancelDeployment);
deploymentsRouter.post('/deployments/:deploymentId/cancel', requireRole('operator', 'admin'), cancelDeployment);

deploymentsRouter.post('/deployments/:deploymentId/retry-failed', requireRole('operator', 'admin'), async (req, res) => {
  const deploymentId = req.params.deploymentId;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const upd = await client.query(
      `UPDATE deployments
       SET status='QUEUED', finished_at=NULL, scheduled_at=NULL,
           progress=$2
       WHERE id=$1 AND status IN ('FAILED', 'PARTIAL')
       RETURNING *`,
      [deploymentId, JSON.stringify({ phase: 'queued', checked: 0, totalToCheck: 0, deployed: 0, totalToDeploy: 0, warnings: [] })]
    );
    if (!upd.rows[0]) {
      await client.query('ROLLBACK');
      const depRes = await pool.query(`SELECT status FROM deployments WHERE id=$1`, [deploymentId]);
      if (!depRes.rows[0]) return res.status(404).json({ error: 'deployment_not_found' });
      return res.status(409).json({ error: 'not_retryable', message: `Only FAILED or PARTIAL deployments can be retried (current status: ${depRes.rows[0].status}).` });
    }
    const hosts = await client.query(
      `UPDATE deployment_hosts SET status='PENDING', started_at=NULL, finished_at=NULL, message=NULL
       WHERE deployment_id=$1
         AND (status='FAILED' OR (status='SKIPPED' AND message LIKE 'Rollout halted:%'))
       RETURNING host_id`,
      [deploymentId]
    );
    await client.query('COMMIT');
    res.json({ ok: true, deployment: upd.rows[0], hostsReset: hosts.rowCount ?? hosts.rows.length });
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }
});

/**
 * Process scheduled deployments that are ready to start.
 * Called periodically by background job.
 * Each candidate is atomically claimed right before it runs, so concurrent workers / a manual
 * /start can never run the same deployment twice.
 * Returns count of deployments processed.
 */
export async function processScheduledDeployments(): Promise<number> {
  // Candidates only; the authoritative check is the per-row claim below.
  const scheduledRes = await pool.query(
    `SELECT id FROM deployments
     WHERE status IN ('SCHEDULED', 'QUEUED') AND scheduled_at IS NOT NULL AND scheduled_at <= now()
       AND (requires_approval = false OR approved_by IS NOT NULL)
     ORDER BY scheduled_at ASC
     LIMIT 10`
  );

  let processedCount = 0;
  for (const row of scheduledRes.rows) {
    const claimed = await claimDeploymentForStart(
      row.id,
      ['SCHEDULED', 'QUEUED'],
      'AND scheduled_at IS NOT NULL AND scheduled_at <= now()'
    );
    if (!claimed) continue; // started, cancelled or changed by someone else meanwhile
    notifyDeploymentEvent('DEPLOYMENT_STARTED', row.id, { startedBy: 'scheduler' });

    try {
      const result = await executeDeploymentStart(row.id, undefined);
      // eslint-disable-next-line no-console
      console.log(`[Scheduled Deployments] Auto-started deployment ${row.id} — ok=${result.ok}, exitCode=${result.exitCode}`);
    } catch (error: any) {
      // eslint-disable-next-line no-console
      console.error(`[Scheduled Deployments] Failed to auto-start deployment ${row.id}:`, error.message);
      // Mark the deployment as FAILED so it doesn't remain in a stuck state
      await failDeployment(row.id, error.message || 'Scheduled deployment start failed');
    }

    processedCount++;
  }

  return processedCount;
}
