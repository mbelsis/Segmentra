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
});


