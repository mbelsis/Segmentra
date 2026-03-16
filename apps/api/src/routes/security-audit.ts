import { Router } from 'express';

import { pool } from '../db/pool.js';
import { requireAuth, requireRole } from '../middleware/auth.js';
import { runExcessiveRulesAudit } from '../services/excessive-rules-audit.js';
import { sendNotification } from '../services/notifications.js';

export const securityAuditRouter = Router();
securityAuditRouter.use(requireAuth, requireRole('viewer', 'operator', 'approver', 'admin'));

// Run the excessive rules / security posture audit
securityAuditRouter.get('/scan', async (req, res) => {
  try {
    const result = await runExcessiveRulesAudit();

    // Log audit event
    await pool.query(
      `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
       VALUES ((SELECT id FROM users WHERE username=$1 LIMIT 1), 'SECURITY_AUDIT_RUN', 'security_audit', 'scan', $2)`,
      [req.auth!.username, JSON.stringify({ summary: result.summary })]
    );

    // Send notification if critical findings
    if (result.summary.critical > 0 || result.summary.high > 0) {
      await sendNotification({
        eventType: 'EXCESSIVE_RULES_DETECTED',
        subject: `Security Audit: ${result.summary.critical} critical, ${result.summary.high} high findings`,
        body: {
          critical: result.summary.critical,
          high: result.summary.high,
          medium: result.summary.medium,
          total: result.summary.total,
          triggeredBy: req.auth!.username,
        },
      });
    }

    res.json(result);
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

// Get a summary (lighter — just counts, no full findings)
securityAuditRouter.get('/summary', async (_req, res) => {
  try {
    const result = await runExcessiveRulesAudit();
    res.json({ summary: result.summary });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});
