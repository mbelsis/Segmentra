import 'dotenv/config';
import './lib/async-errors.js';

import cors from 'cors';
import express from 'express';

import { ZodError } from 'zod';

import { env, parseTrustProxy } from './lib/env.js';
import { corsOptions } from './lib/cors.js';
import { warnIfKekDerivedFromJwtSecret } from './services/crypto.js';
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
import { backupRouter } from './routes/backup.js';
import { complianceReportsRouter } from './routes/compliance-reports.js';
import hostReadinessRouter from './routes/host-readiness.js';
import { topologyRouter } from './routes/topology.js';
import { recommendationsRouter } from './routes/recommendations.js';
import { integrationsRouter } from './routes/integrations.js';
import { policyTestingRouter } from './routes/policy-testing.js';
import { kubernetesRouter } from './routes/kubernetes.js';
import { iotAssetsRouter } from './routes/iot-assets.js';
import { iotExtrasRouter } from './routes/iot-extras.js';
import { flowCollectorsRouter } from './routes/flow-collectors.js';
import { enforcementPointsRouter } from './routes/enforcement-points.js';
import { notificationsRouter } from './routes/notifications.js';
import { securityAuditRouter } from './routes/security-audit.js';

warnIfKekDerivedFromJwtSecret();

const app = express();
// Behind a reverse proxy, set TRUST_PROXY so req.ip (used by the login rate limiter) is the client IP.
const trustProxy = parseTrustProxy(env.TRUST_PROXY);
if (trustProxy !== undefined) app.set('trust proxy', trustProxy);
// Same-origin nginx requests work without CORS; cross-origin clients require an allowlist in production.
app.use(cors(corsOptions(env.NODE_ENV, env.CORS_ORIGIN)));
app.use(express.json({ limit: '1mb' }));

app.use('/api/health', healthRouter);
app.use('/api/auth', authRouter);
app.use('/api/admin', adminRouter);
app.use('/api/backup', backupRouter);
app.use('/api', inventoryRouter);
app.use('/api', policiesRouter);
app.use('/api', deploymentsRouter);
app.use('/api/ssh-credentials', sshCredentialsRouter);
app.use('/api', auditRouter);
app.use('/api', dashboardRouter);
app.use('/api/troubleshoot', troubleshootRouter);
// Reports first: the host compliance router below is operator/admin only, reports are readable by every role.
app.use('/api/compliance/reports', complianceReportsRouter);
app.use('/api/compliance', complianceRouter);
app.use('/api/host-readiness', hostReadinessRouter);
app.use('/api/topology', topologyRouter);
app.use('/api/recommendations', recommendationsRouter);
app.use('/api/integrations', integrationsRouter);
app.use('/api/policy-test', policyTestingRouter);
app.use('/api/k8s', kubernetesRouter);
// IoT extras first: single-segment paths such as /protocols and /coverage must not be taken for an asset id.
app.use('/api/iot-assets', iotExtrasRouter);
app.use('/api/iot-assets', iotAssetsRouter);
app.use('/api/flow-collectors', flowCollectorsRouter);
app.use('/api/enforcement-points', enforcementPointsRouter);
app.use('/api/notifications', notificationsRouter);
app.use('/api/security-audit', securityAuditRouter);

const isProduction = env.NODE_ENV === 'production';

/** Map known error types (pg, zod, body-parser) to a client-facing status + payload. */
function mapError(err: any): { status: number; body: Record<string, unknown> } | null {
  if (err instanceof ZodError) {
    return { status: 400, body: { error: 'invalid_body', details: err.issues } };
  }
  // body-parser errors (malformed JSON, payload too large)
  if (err && typeof err.status === 'number' && err.status >= 400 && err.status < 500 && err.type) {
    return { status: err.status, body: { error: err.type === 'entity.parse.failed' ? 'invalid_json' : String(err.type) } };
  }
  const code = typeof err?.code === 'string' ? err.code : null;
  switch (code) {
    case '22P02': // invalid_text_representation (e.g. malformed uuid)
    case '22007': // invalid_datetime_format
    case '22008': // datetime_field_overflow
      return { status: 400, body: { error: 'invalid_input', message: 'One or more values have an invalid format.' } };
    case '23505':
      return { status: 409, body: { error: 'conflict', message: 'A record with these values already exists.', constraint: err.constraint } };
    case '23503':
      return {
        status: 409,
        body: {
          error: 'referenced_by_other_records',
          message: 'This record is in use by other records (or references a record that does not exist) and cannot be changed or deleted.',
          constraint: err.constraint
        }
      };
    case '23502':
      return { status: 400, body: { error: 'missing_required_field', message: `A required field is missing${err.column ? `: ${err.column}` : ''}.` } };
    case '23514':
      return { status: 400, body: { error: 'constraint_violation', message: 'A value violates a data constraint.', constraint: err.constraint } };
    default:
      return null;
  }
}

// Global error handler middleware (must be last)
app.use((err: any, req: express.Request, res: express.Response, _next: express.NextFunction) => {
  const mapped = mapError(err);
  if (mapped) {
    if (mapped.status >= 500 || !isProduction) {
      // eslint-disable-next-line no-console
      console.warn(`[Request Error] ${req.method} ${req.originalUrl} -> ${mapped.status}`, err?.message ?? err);
    }
    if (res.headersSent) return;
    return res.status(mapped.status).json(mapped.body);
  }

  // eslint-disable-next-line no-console
  console.error(`[Unhandled Error] ${req.method} ${req.originalUrl}`, err);
  if (res.headersSent) return;
  res.status(500).json({
    error: 'internal_server_error',
    message: isProduction ? 'An unexpected error occurred' : (err?.message || 'An unexpected error occurred')
  });
});

// Log unhandled promise rejections (async handler rejections are routed to the error middleware
// by lib/async-errors; anything reaching here is a bug in a background task).
process.on('unhandledRejection', (reason: unknown) => {
  // eslint-disable-next-line no-console
  console.error('[Unhandled Promise Rejection]', reason);
});

// An uncaught exception leaves the process in an undefined state: log it and exit so the
// supervisor (Docker/systemd) restarts a clean instance.
process.on('uncaughtException', (error: Error) => {
  // eslint-disable-next-line no-console
  console.error('[Uncaught Exception] Shutting down:', error);
  process.exit(1);
});

app.listen(env.PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`Segmentra API listening on :${env.PORT}`);

  // One-time (idempotent) encryption of integration / notification channel configs stored in
  // plaintext by versions before migration 031. Then start forwarding audit events to SIEM:
  // a trigger on audit_events NOTIFYs this process for every row (see siem-audit-listener.ts).
  void import('./services/config-secrets.js')
    .then(({ migratePlaintextConfigs }) => migratePlaintextConfigs())
    .then(({ integrations, channels }) => {
      if (integrations > 0 || channels > 0) {
        // eslint-disable-next-line no-console
        console.log(`[Secrets] Encrypted plaintext config of ${integrations} integration(s) and ${channels} notification channel(s)`);
      }
    })
    .catch((e) => {
      // eslint-disable-next-line no-console
      console.error('[Secrets] Error encrypting plaintext integration/notification configs:', e);
    });
  void import('./services/siem-audit-listener.js')
    .then(({ startSiemAuditListener }) => startSiemAuditListener())
    .catch((e) => {
      // eslint-disable-next-line no-console
      console.error('[SIEM] Error starting audit forwarder:', e);
    });

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
    } catch (e) {
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
    } catch (e) {
      // eslint-disable-next-line no-console
      console.error('[Scheduled Deployments] Error processing scheduled deployments:', e);
    }
  }, 60 * 1000); // Check every 1 minute

  // Start periodic audit session processor (every 1 minute)
  setInterval(async () => {
    try {
      const { processExpiredAuditSessions } = await import('./services/audit-scheduler.js');
      await processExpiredAuditSessions();
    } catch (e) {
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
    } catch (e) {
      // eslint-disable-next-line no-console
      console.error('[Tag Rules] Error evaluating tag rules:', e);
    }
  }, 5 * 60 * 1000); // Check every 5 minutes

  // Start periodic deployment expiry processor (every 1 minute).
  // Expired deployments are claimed atomically, then their expiry action runs:
  // NOTIFY_ONLY notifies, REMOVE strips Segmentra rules from the hosts, REVERT redeploys the
  // previous successfully deployed version. Also sends 24h "expiring soon" warnings.
  setInterval(async () => {
    try {
      const { processExpiredDeployments } = await import('./services/deployment-expiry.js');
      await processExpiredDeployments();
    } catch (e) {
      // eslint-disable-next-line no-console
      console.error('[Policy Expiry] Error processing expired deployments:', e);
    }
  }, 60 * 1000); // Check every 1 minute

  // Inventory discovery scheduler (every 1 minute). Runs left RUNNING by a previous process
  // are marked FAILED once at startup; due profiles are claimed atomically (SKIP LOCKED) and
  // each run executes in the background.
  void import('./services/discovery.js')
    .then(({ failStaleDiscoveryRuns }) => failStaleDiscoveryRuns({ all: true }))
    .then((n) => {
      // eslint-disable-next-line no-console
      if (n > 0) console.log(`[Discovery] Marked ${n} interrupted run(s) as FAILED`);
    })
    .catch((e) => {
      // eslint-disable-next-line no-console
      console.error('[Discovery] Error cleaning up interrupted runs:', e);
    });
  setInterval(async () => {
    try {
      const { processScheduledDiscovery } = await import('./services/discovery.js');
      const started = await processScheduledDiscovery();
      if (started > 0) {
        // eslint-disable-next-line no-console
        console.log(`[Discovery] Started ${started} scheduled discovery run(s)`);
      }
    } catch (e) {
      // eslint-disable-next-line no-console
      console.error('[Discovery] Error processing scheduled discovery:', e);
    }
  }, 60 * 1000); // Check every 1 minute

  // Start periodic policy test session expiry processor (every 1 minute)
  // When a test session expires, SSH into the host to restore original rules and collect logs.
  // Sessions whose restore failed stay RUNNING (with scheduled_end_at pulled forward) and are retried here.
  setInterval(async () => {
    try {
      const { pool } = await import('./db/pool.js');
      const { rows } = await pool.query(
        `SELECT pts.*, h.hostname, h.mgmt_ip, h.ssh_port, h.firewall_backend
         FROM policy_test_sessions pts
         JOIN hosts h ON h.id = pts.host_id
         WHERE pts.status = 'RUNNING' AND pts.scheduled_end_at <= now()`
      );
      if (rows.length === 0) return;

      const { restoreAndCollectSession } = await import('./lib/policy-test-session.js');
      for (const session of rows) {
        const result = await restoreAndCollectSession(session);
        if (result.ok) {
          // eslint-disable-next-line no-console
          console.log(`[Policy Test] Auto-restored ${session.hostname}, collected ${result.entryCount} entries, ${result.flowCount} flows`);
        } else {
          // eslint-disable-next-line no-console
          console.error(`[Policy Test] Restore failed for session ${session.id} (${session.hostname}); will retry: ${result.error}`);
        }
      }
    } catch (e) {
      // eslint-disable-next-line no-console
      console.error('[Policy Test] Error processing expired test sessions:', e);
    }
  }, 60 * 1000); // Check every 1 minute
});

