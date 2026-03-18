import { Router } from 'express';

import { pool } from '../db/pool.js';
import { requireAuth } from '../middleware/auth.js';

export const dashboardRouter = Router();
dashboardRouter.use(requireAuth);

dashboardRouter.get('/dashboard/stats', async (_req, res) => {
  // Total deployments
  const totalRes = await pool.query(`SELECT COUNT(*) as count FROM deployments`);
  const totalDeployments = parseInt(totalRes.rows[0].count, 10);

  // Running/active deployments
  const runningRes = await pool.query(
    `SELECT COUNT(*) as count FROM deployments WHERE status IN ('QUEUED', 'RUNNING')`
  );
  const runningDeployments = parseInt(runningRes.rows[0].count, 10);

  // Status breakdown
  const statusRes = await pool.query(
    `SELECT status, COUNT(*) as count 
     FROM deployments 
     GROUP BY status 
     ORDER BY count DESC`
  );
  const statusBreakdown = statusRes.rows.map((r) => ({
    status: r.status,
    count: parseInt(r.count, 10)
  }));

  // Most active deployers (users who created deployments)
  const deployersRes = await pool.query(
    `SELECT 
       u.id,
       u.username,
       u.display_name,
       COUNT(d.id) as deployment_count
     FROM users u
     JOIN deployments d ON d.created_by = u.id
     GROUP BY u.id, u.username, u.display_name
     ORDER BY deployment_count DESC
     LIMIT 10`
  );
  const topDeployers = deployersRes.rows.map((r) => ({
    userId: r.id,
    username: r.username,
    displayName: r.display_name,
    deploymentCount: parseInt(r.deployment_count, 10)
  }));

  // Recent deployments (last 10)
  const recentRes = await pool.query(
    `SELECT 
       d.id,
       d.status,
       d.mode,
       d.target_count,
       d.created_at,
       d.finished_at,
       u.username as created_by_username,
       pv.version_number,
       ps.name as policy_set_name
     FROM deployments d
     LEFT JOIN users u ON d.created_by = u.id
     LEFT JOIN policy_versions pv ON d.policy_version_id = pv.id
     LEFT JOIN policy_sets ps ON pv.policy_set_id = ps.id
     ORDER BY d.created_at DESC
     LIMIT 10`
  );

  // Current running deployments with progress
  const currentRes = await pool.query(
    `SELECT 
       d.id,
       d.status,
       d.mode,
       d.target_count,
       d.created_at,
       d.started_at,
       ps.name as policy_set_name,
       pv.version_number,
       COUNT(DISTINCT dh.host_id) as total_hosts,
       COUNT(DISTINCT CASE WHEN dh.status = 'SUCCEEDED' THEN dh.host_id END) as succeeded_hosts,
       COUNT(DISTINCT CASE WHEN dh.status = 'FAILED' THEN dh.host_id END) as failed_hosts,
       COUNT(DISTINCT CASE WHEN dh.status = 'RUNNING' THEN dh.host_id END) as running_hosts
     FROM deployments d
     LEFT JOIN policy_versions pv ON d.policy_version_id = pv.id
     LEFT JOIN policy_sets ps ON pv.policy_set_id = ps.id
     LEFT JOIN deployment_hosts dh ON dh.deployment_id = d.id
     WHERE d.status IN ('QUEUED', 'RUNNING')
     GROUP BY d.id, d.status, d.mode, d.target_count, d.created_at, d.started_at, ps.name, pv.version_number
     ORDER BY d.created_at DESC`
  );

  const currentDeployments = currentRes.rows.map((r) => ({
    id: r.id,
    status: r.status,
    mode: r.mode,
    targetCount: parseInt(r.target_count || 0, 10),
    createdAt: r.created_at,
    startedAt: r.started_at,
    policySetName: r.policy_set_name,
    versionNumber: r.version_number,
    totalHosts: parseInt(r.total_hosts || 0, 10),
    succeededHosts: parseInt(r.succeeded_hosts || 0, 10),
    failedHosts: parseInt(r.failed_hosts || 0, 10),
    runningHosts: parseInt(r.running_hosts || 0, 10),
    progressPercent:
      r.total_hosts > 0
        ? Math.round(
            ((parseInt(r.succeeded_hosts || 0, 10) + parseInt(r.failed_hosts || 0, 10)) /
              parseInt(r.total_hosts, 10)) *
              100
          )
        : 0
  }));

  // Success rate (SUCCEEDED / total finished)
  const finishedRes = await pool.query(
    `SELECT 
       COUNT(*) FILTER (WHERE status = 'SUCCEEDED') as succeeded,
       COUNT(*) FILTER (WHERE status IN ('SUCCEEDED', 'FAILED')) as finished
     FROM deployments`
  );
  const succeeded = parseInt(finishedRes.rows[0].succeeded || 0, 10);
  const finished = parseInt(finishedRes.rows[0].finished || 0, 10);
  const successRate = finished > 0 ? Math.round((succeeded / finished) * 100) : 0;

  // Deployment activity over time (last 30 days)
  const activityRes = await pool.query(
    `SELECT 
       DATE(created_at) as date,
       COUNT(*) as total,
       COUNT(*) FILTER (WHERE status = 'SUCCEEDED') as succeeded,
       COUNT(*) FILTER (WHERE status = 'FAILED') as failed,
       COUNT(*) FILTER (WHERE status IN ('QUEUED', 'RUNNING')) as running
     FROM deployments
     WHERE created_at >= NOW() - INTERVAL '30 days'
     GROUP BY DATE(created_at)
     ORDER BY date ASC`
  );
  const deploymentActivity = activityRes.rows.map((r) => ({
    date: r.date,
    total: parseInt(r.total, 10),
    succeeded: parseInt(r.succeeded || 0, 10),
    failed: parseInt(r.failed || 0, 10),
    running: parseInt(r.running || 0, 10)
  }));

  // === Additional stats ===

  // Total managed hosts
  const hostsRes = await pool.query(`SELECT COUNT(*)::int as total, COUNT(*) FILTER (WHERE enabled = true)::int as enabled FROM hosts`);
  const totalHosts = hostsRes.rows[0].total;
  const enabledHosts = hostsRes.rows[0].enabled;

  // Total IoT assets
  const iotRes = await pool.query(`SELECT COUNT(*)::int as total FROM iot_assets`);
  const totalIotAssets = iotRes.rows[0].total;

  // Total policy sets and versions
  const policyCountRes = await pool.query(`SELECT COUNT(*)::int as sets FROM policy_sets`);
  const totalPolicySets = policyCountRes.rows[0].sets;

  // Most deployed policy set (by number of successful deployments)
  const mostDeployedRes = await pool.query(
    `SELECT ps.name, COUNT(d.id)::int as deploy_count
     FROM deployments d
     JOIN policy_versions pv ON pv.id = d.policy_version_id
     JOIN policy_sets ps ON ps.id = pv.policy_set_id
     WHERE d.status = 'SUCCEEDED'
     GROUP BY ps.name
     ORDER BY deploy_count DESC
     LIMIT 1`
  );
  const mostDeployedPolicy = mostDeployedRes.rows[0] ? { name: mostDeployedRes.rows[0].name, deployCount: mostDeployedRes.rows[0].deploy_count } : null;

  // Last security audit
  const lastAuditRes = await pool.query(
    `SELECT metadata, timestamp FROM audit_events
     WHERE action = 'SECURITY_AUDIT_RUN'
     ORDER BY timestamp DESC LIMIT 1`
  );
  const lastSecurityAudit = lastAuditRes.rows[0] ? {
    timestamp: lastAuditRes.rows[0].timestamp,
    summary: typeof lastAuditRes.rows[0].metadata === 'string' ? JSON.parse(lastAuditRes.rows[0].metadata)?.summary : lastAuditRes.rows[0].metadata?.summary,
  } : null;

  // Pending approvals count
  const pendingApprovalsRes = await pool.query(
    `SELECT COUNT(*)::int as count FROM policy_versions WHERE status = 'PENDING_APPROVAL'`
  );
  const pendingApprovals = pendingApprovalsRes.rows[0].count;

  // Expiring deployments (within 7 days)
  const expiringRes = await pool.query(
    `SELECT COUNT(*)::int as count FROM deployments
     WHERE expires_at IS NOT NULL AND expires_at <= now() + interval '7 days' AND expired = false
     AND status IN ('SUCCEEDED', 'PARTIAL')`
  );
  const expiringDeployments = expiringRes.rows[0].count;

  res.json({
    totalDeployments,
    runningDeployments,
    successRate,
    statusBreakdown,
    topDeployers,
    recentDeployments: recentRes.rows,
    currentDeployments,
    deploymentActivity,
    // New stats
    totalHosts,
    enabledHosts,
    totalIotAssets,
    totalPolicySets,
    mostDeployedPolicy,
    lastSecurityAudit,
    pendingApprovals,
    expiringDeployments,
  });
});


