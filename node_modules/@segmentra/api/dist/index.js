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
    // Start periodic policy test session expiry processor (every 1 minute)
    setInterval(async () => {
        try {
            const { pool } = await import('./db/pool.js');
            const { rows } = await pool.query(`SELECT id FROM policy_test_sessions WHERE status = 'RUNNING' AND scheduled_end_at <= now()`);
            for (const session of rows) {
                await pool.query(`UPDATE policy_test_sessions SET status = 'COLLECTING', completed_at = now() WHERE id = $1`, [session.id]);
                // eslint-disable-next-line no-console
                console.log(`[Policy Test] Auto-stopped expired test session ${session.id}`);
            }
        }
        catch (e) {
            // eslint-disable-next-line no-console
            console.error('[Policy Test] Error processing expired test sessions:', e);
        }
    }, 60 * 1000); // Check every 1 minute
});
