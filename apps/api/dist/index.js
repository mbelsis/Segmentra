import 'dotenv/config';
import cors from 'cors';
import express from 'express';
import { env } from './lib/env.js';
import { authRouter } from './routes/auth.js';
import { adminRouter } from './routes/admin.js';
import { healthRouter } from './routes/health.js';
import { inventoryRouter } from './routes/inventory/index.js';
import { policiesRouter } from './routes/policies/index.js';
import { deploymentsRouter } from './routes/deployments.js';
import { sshCredentialsRouter } from './routes/ssh-credentials.js';
import { auditRouter } from './routes/audit.js';
import { dashboardRouter } from './routes/dashboard.js';
import { troubleshootRouter } from './routes/troubleshoot.js';
import complianceRouter from './routes/compliance.js';
import hostReadinessRouter from './routes/host-readiness.js';
import { topologyRouter } from './routes/topology.js';
import { recommendationsRouter } from './routes/recommendations.js';
import { integrationsRouter } from './routes/integrations.js';
import { policyTestingRouter } from './routes/policy-testing.js';
import { kubernetesRouter } from './routes/kubernetes.js';
import { iotAssetsRouter } from './routes/iot-assets.js';
import { flowCollectorsRouter } from './routes/flow-collectors.js';
import { enforcementPointsRouter } from './routes/enforcement-points.js';
import { notificationsRouter } from './routes/notifications.js';
import { securityAuditRouter } from './routes/security-audit.js';
const app = express();
app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use('/api/health', healthRouter);
app.use('/api/auth', authRouter);
app.use('/api/admin', adminRouter);
app.use('/api', inventoryRouter);
app.use('/api', policiesRouter);
app.use('/api', deploymentsRouter);
app.use('/api/ssh-credentials', sshCredentialsRouter);
app.use('/api', auditRouter);
app.use('/api', dashboardRouter);
app.use('/api/troubleshoot', troubleshootRouter);
app.use('/api/compliance', complianceRouter);
app.use('/api/host-readiness', hostReadinessRouter);
app.use('/api/topology', topologyRouter);
app.use('/api/recommendations', recommendationsRouter);
app.use('/api/integrations', integrationsRouter);
app.use('/api/policy-test', policyTestingRouter);
app.use('/api/k8s', kubernetesRouter);
app.use('/api/iot-assets', iotAssetsRouter);
app.use('/api/flow-collectors', flowCollectorsRouter);
app.use('/api/enforcement-points', enforcementPointsRouter);
app.use('/api/notifications', notificationsRouter);
app.use('/api/security-audit', securityAuditRouter);
// Global error handler middleware (must be last)
app.use((err, req, res, next) => {
    // eslint-disable-next-line no-console
    console.error('[Unhandled Error]', err);
    res.status(500).json({
        error: 'internal_server_error',
        message: err.message || 'An unexpected error occurred'
    });
});
// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
    // eslint-disable-next-line no-console
    console.error('[Unhandled Promise Rejection]', reason);
});
// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
    // eslint-disable-next-line no-console
    console.error('[Uncaught Exception]', error);
    // Don't exit immediately - let the error handler middleware catch it
});
// TODO: add inventory/policies/deployments/audit/admin routers
app.listen(env.PORT, () => {
    // eslint-disable-next-line no-console
    console.log(`Segmentra API listening on :${env.PORT}`);
    // Start periodic timeout check for stale host deployments (every 2 minutes)
    setInterval(async () => {
        try {
            // Import the function dynamically to avoid circular dependencies
            const { checkAndTimeoutStaleHosts } = await import('./routes/deployments.js');
            const timeoutCount = await checkAndTimeoutStaleHosts();
            if (timeoutCount > 0) {
                // eslint-disable-next-line no-console
                console.log(`[Timeout Check] Timed out ${timeoutCount} stale host deployment(s)`);
            }
        }
        catch (e) {
            // eslint-disable-next-line no-console
            console.error('[Timeout Check] Error checking stale hosts:', e);
        }
    }, 2 * 60 * 1000); // Check every 2 minutes
    // Start periodic scheduled deployment processor (every 1 minute)
    setInterval(async () => {
        try {
            const { processScheduledDeployments } = await import('./routes/deployments.js');
            const processedCount = await processScheduledDeployments();
            if (processedCount > 0) {
                // eslint-disable-next-line no-console
                console.log(`[Scheduled Deployments] Processed ${processedCount} scheduled deployment(s)`);
            }
        }
        catch (e) {
            // eslint-disable-next-line no-console
            console.error('[Scheduled Deployments] Error processing scheduled deployments:', e);
        }
    }, 60 * 1000); // Check every 1 minute
    // Start periodic audit session processor (every 1 minute)
    setInterval(async () => {
        try {
            const { processExpiredAuditSessions } = await import('./services/audit-scheduler.js');
            await processExpiredAuditSessions();
        }
        catch (e) {
            // eslint-disable-next-line no-console
            console.error('[Audit Scheduler] Error processing expired audit sessions:', e);
        }
    }, 60 * 1000); // Check every 1 minute
    // Start periodic tag rule evaluation (every 5 minutes)
    setInterval(async () => {
        try {
            const { evaluateAllRules } = await import('./services/tag-rule-engine.js');
            const result = await evaluateAllRules();
            if (result.rulesEvaluated > 0) {
                // eslint-disable-next-line no-console
                console.log(`[Tag Rules] Evaluated ${result.rulesEvaluated} rule(s), ${result.totalMatches} match(es)`);
            }
        }
        catch (e) {
            // eslint-disable-next-line no-console
            console.error('[Tag Rules] Error evaluating tag rules:', e);
        }
    }, 5 * 60 * 1000); // Check every 5 minutes
    // Start periodic deployment expiry processor (every 1 minute)
    // Checks for deployments with expires_at in the past and handles them
    setInterval(async () => {
        try {
            const { pool } = await import('./db/pool.js');
            const { sendNotification } = await import('./services/notifications.js');
            // Find expired deployments
            const { rows: expired } = await pool.query(`SELECT d.id, d.policy_version_id, d.expiry_action, d.expires_at,
           pv.version_number, ps.name as policy_set_name
         FROM deployments d
         JOIN policy_versions pv ON pv.id = d.policy_version_id
         JOIN policy_sets ps ON ps.id = pv.policy_set_id
         WHERE d.expires_at IS NOT NULL AND d.expires_at <= now() AND d.expired = false
           AND d.status IN ('SUCCEEDED', 'PARTIAL')`);
            for (const dep of expired) {
                const expiryAction = dep.expiry_action || 'NOTIFY_ONLY';
                // Mark as expired and update status to EXPIRED
                await pool.query(`UPDATE deployments SET expired = true, status = 'EXPIRED' WHERE id = $1`, [dep.id]);
                // Build notification subject and body based on expiry action
                let notificationSubject;
                let notificationBody;
                if (expiryAction === 'REMOVE') {
                    notificationSubject = `POLICY EXPIRED - Manual rollback required: ${dep.policy_set_name} v${dep.version_number}`;
                    notificationBody = {
                        deploymentId: dep.id,
                        policySetName: dep.policy_set_name,
                        versionNumber: dep.version_number,
                        expiryAction,
                        expiredAt: dep.expires_at,
                        actionRequired: 'The deployed firewall rules should be manually removed from all target hosts. Full automated rollback is planned for a future release.',
                    };
                    // eslint-disable-next-line no-console
                    console.log(`[Policy Expiry] Deployment ${dep.id} expired with REMOVE action — manual rollback required (${dep.policy_set_name} v${dep.version_number})`);
                }
                else if (expiryAction === 'REVERT') {
                    notificationSubject = `POLICY EXPIRED - Previous version should be redeployed: ${dep.policy_set_name} v${dep.version_number}`;
                    notificationBody = {
                        deploymentId: dep.id,
                        policySetName: dep.policy_set_name,
                        versionNumber: dep.version_number,
                        expiryAction,
                        expiredAt: dep.expires_at,
                        actionRequired: 'The previous policy version should be manually redeployed to all target hosts. Full automated revert is planned for a future release.',
                    };
                    // eslint-disable-next-line no-console
                    console.log(`[Policy Expiry] Deployment ${dep.id} expired with REVERT action — previous version should be redeployed (${dep.policy_set_name} v${dep.version_number})`);
                }
                else {
                    // NOTIFY_ONLY or any other value
                    notificationSubject = `Policy expired: ${dep.policy_set_name} v${dep.version_number}`;
                    notificationBody = {
                        deploymentId: dep.id,
                        policySetName: dep.policy_set_name,
                        versionNumber: dep.version_number,
                        expiryAction,
                        expiredAt: dep.expires_at,
                    };
                    // eslint-disable-next-line no-console
                    console.log(`[Policy Expiry] Deployment ${dep.id} expired (${dep.policy_set_name} v${dep.version_number}, action: ${expiryAction})`);
                }
                // Send notification
                await sendNotification({
                    eventType: 'POLICY_EXPIRED',
                    subject: notificationSubject,
                    body: notificationBody,
                });
                // Log audit event with action-specific metadata
                await pool.query(`INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
           VALUES (NULL, 'POLICY_EXPIRED', 'deployment', $1, $2)`, [dep.id, JSON.stringify({
                        policySetName: dep.policy_set_name,
                        versionNumber: dep.version_number,
                        expiryAction,
                        ...(expiryAction === 'REMOVE' ? { actionRequired: 'Manual rollback required' } : {}),
                        ...(expiryAction === 'REVERT' ? { actionRequired: 'Previous version should be redeployed' } : {}),
                    })]);
            }
            // Send "expiring soon" warnings (24 hours before expiry)
            const { rows: expiringSoon } = await pool.query(`SELECT d.id, d.expires_at, pv.version_number, ps.name as policy_set_name
         FROM deployments d
         JOIN policy_versions pv ON pv.id = d.policy_version_id
         JOIN policy_sets ps ON ps.id = pv.policy_set_id
         WHERE d.expires_at IS NOT NULL
           AND d.expires_at > now()
           AND d.expires_at <= now() + interval '24 hours'
           AND d.expired = false
           AND d.status IN ('SUCCEEDED', 'PARTIAL')
           AND NOT EXISTS (
             SELECT 1 FROM notification_log nl
             WHERE nl.event_type = 'POLICY_EXPIRING_SOON'
               AND nl.payload::text LIKE '%' || d.id::text || '%'
               AND nl.created_at > now() - interval '24 hours'
           )`);
            for (const dep of expiringSoon) {
                const hoursLeft = Math.round((new Date(dep.expires_at).getTime() - Date.now()) / 3600000);
                await sendNotification({
                    eventType: 'POLICY_EXPIRING_SOON',
                    subject: `Policy expiring in ${hoursLeft}h: ${dep.policy_set_name} v${dep.version_number}`,
                    body: {
                        deploymentId: dep.id,
                        policySetName: dep.policy_set_name,
                        versionNumber: dep.version_number,
                        expiresAt: dep.expires_at,
                        hoursRemaining: hoursLeft,
                    },
                });
            }
        }
        catch (e) {
            // eslint-disable-next-line no-console
            console.error('[Policy Expiry] Error processing expired deployments:', e);
        }
    }, 60 * 1000); // Check every 1 minute
    // Start periodic policy test session expiry processor (every 1 minute)
    // When a test session expires, SSH into the host to restore original rules and collect logs
    setInterval(async () => {
        try {
            const { pool } = await import('./db/pool.js');
            const { rows } = await pool.query(`SELECT pts.*, h.hostname, h.mgmt_ip, h.ssh_port, h.firewall_backend
         FROM policy_test_sessions pts
         JOIN hosts h ON h.id = pts.host_id
         WHERE pts.status = 'RUNNING' AND pts.scheduled_end_at <= now()`);
            if (rows.length === 0)
                return;
            const { restoreAuditSession, retrieveAuditLogs } = await import('@segmentra/executor');
            const { readSecretPlaintext } = await import('./services/secrets.js');
            const { parseFirewallLogs, groupCommunicationFlows } = await import('./services/log-parser.js');
            const fs = await import('node:fs');
            const path = await import('node:path');
            const os = await import('node:os');
            // Get SSH credentials once
            const credRes = await pool.query(`SELECT * FROM ssh_credentials WHERE scope_type='GLOBAL' ORDER BY created_at DESC LIMIT 1`);
            const cred = credRes.rows[0];
            if (!cred) {
                // eslint-disable-next-line no-console
                console.error('[Policy Test] No SSH credentials found, cannot auto-restore expired sessions');
                return;
            }
            const keyPem = (await readSecretPlaintext(cred.private_key_secret_id)).toString('utf8');
            for (const session of rows) {
                const tempKeyPath = path.join(os.tmpdir(), `policy_test_expire_${session.id}_${Date.now()}`);
                try {
                    fs.writeFileSync(tempKeyPath, keyPem, { encoding: 'utf8', mode: 0o600 });
                    const auditHost = {
                        hostname: session.hostname,
                        ip: String(session.mgmt_ip),
                        port: session.ssh_port || 22,
                        username: cred.username,
                        privateKeyPath: tempKeyPath,
                        backend: (session.firewall_backend === 'iptables' ? 'iptables' : 'nftables')
                    };
                    // Restore original firewall rules
                    if (session.backup_path) {
                        await restoreAuditSession(auditHost, session.backup_path);
                    }
                    // Retrieve and parse logs
                    let logContent = '';
                    if (session.log_file_path) {
                        const localLogPath = path.join(os.tmpdir(), `policy_test_log_${session.id}_${Date.now()}.log`);
                        const retrieveResult = await retrieveAuditLogs(auditHost, session.log_file_path, localLogPath);
                        if (retrieveResult.success && fs.existsSync(localLogPath)) {
                            logContent = fs.readFileSync(localLogPath, 'utf8');
                            fs.unlinkSync(localLogPath);
                        }
                    }
                    const parsedEntries = parseFirewallLogs(logContent);
                    const flows = groupCommunicationFlows(parsedEntries);
                    await pool.query(`UPDATE policy_test_sessions
             SET status = 'COLLECTING', completed_at = now(),
                 raw_log_data = $2
             WHERE id = $1`, [session.id, JSON.stringify({ entries: parsedEntries, flows })]);
                    // eslint-disable-next-line no-console
                    console.log(`[Policy Test] Auto-restored ${session.hostname}, collected ${parsedEntries.length} entries, ${flows.length} flows`);
                }
                catch (e) {
                    // eslint-disable-next-line no-console
                    console.error(`[Policy Test] Failed to auto-restore session ${session.id}:`, e.message);
                    await pool.query(`UPDATE policy_test_sessions SET status = 'FAILED', completed_at = now() WHERE id = $1`, [session.id]);
                }
                finally {
                    if (fs.existsSync(tempKeyPath)) {
                        try {
                            fs.unlinkSync(tempKeyPath);
                        }
                        catch { }
                    }
                }
            }
        }
        catch (e) {
            // eslint-disable-next-line no-console
            console.error('[Policy Test] Error processing expired test sessions:', e);
        }
    }, 60 * 1000); // Check every 1 minute
});
