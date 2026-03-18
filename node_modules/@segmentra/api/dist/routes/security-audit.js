import { Router } from 'express';
import { pool } from '../db/pool.js';
import { requireAuth, requireRole } from '../middleware/auth.js';
import { runExcessiveRulesAudit } from '../services/excessive-rules-audit.js';
import { sendNotification } from '../services/notifications.js';
export const securityAuditRouter = Router();
securityAuditRouter.use(requireAuth, requireRole('viewer', 'operator', 'approver', 'admin'));
// Run a new security scan and persist results
securityAuditRouter.get('/scan', async (req, res) => {
    try {
        const result = await runExcessiveRulesAudit();
        // Get user ID
        const userRes = await pool.query(`SELECT id FROM users WHERE username=$1 LIMIT 1`, [req.auth.username]);
        const userId = userRes.rows[0]?.id ?? null;
        // Persist scan results
        const { rows: savedRows } = await pool.query(`INSERT INTO security_audit_results (findings, summary, triggered_by)
       VALUES ($1, $2, $3) RETURNING id, created_at`, [JSON.stringify(result.findings), JSON.stringify(result.summary), userId]);
        // Log audit event
        await pool.query(`INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
       VALUES ($1, 'SECURITY_AUDIT_RUN', 'security_audit', $2, $3)`, [userId, savedRows[0].id, JSON.stringify({ summary: result.summary })]);
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
                    triggeredBy: req.auth.username,
                },
            });
        }
        res.json({ ...result, scanId: savedRows[0].id, scannedAt: savedRows[0].created_at });
    }
    catch (e) {
        res.status(500).json({ error: e.message });
    }
});
// Get the latest scan results (without re-running)
securityAuditRouter.get('/latest', async (_req, res) => {
    try {
        const { rows } = await pool.query(`SELECT sar.*, u.username as triggered_by_username
       FROM security_audit_results sar
       LEFT JOIN users u ON u.id = sar.triggered_by
       ORDER BY sar.created_at DESC LIMIT 1`);
        if (!rows[0])
            return res.json({ findings: [], summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 }, scannedAt: null });
        const findings = typeof rows[0].findings === 'string' ? JSON.parse(rows[0].findings) : rows[0].findings;
        const summary = typeof rows[0].summary === 'string' ? JSON.parse(rows[0].summary) : rows[0].summary;
        res.json({
            findings,
            summary,
            scanId: rows[0].id,
            scannedAt: rows[0].created_at,
            triggeredBy: rows[0].triggered_by_username,
        });
    }
    catch (e) {
        res.status(500).json({ error: e.message });
    }
});
// Get scan history
securityAuditRouter.get('/history', async (_req, res) => {
    try {
        const { rows } = await pool.query(`SELECT sar.id, sar.summary, sar.created_at, u.username as triggered_by_username
       FROM security_audit_results sar
       LEFT JOIN users u ON u.id = sar.triggered_by
       ORDER BY sar.created_at DESC LIMIT 20`);
        res.json({
            history: rows.map(r => ({
                id: r.id,
                summary: typeof r.summary === 'string' ? JSON.parse(r.summary) : r.summary,
                scannedAt: r.created_at,
                triggeredBy: r.triggered_by_username,
            })),
        });
    }
    catch (e) {
        res.status(500).json({ error: e.message });
    }
});
// Get a summary (lighter — just counts from latest scan, no re-run)
securityAuditRouter.get('/summary', async (_req, res) => {
    try {
        const { rows } = await pool.query(`SELECT summary FROM security_audit_results ORDER BY created_at DESC LIMIT 1`);
        if (!rows[0]) {
            return res.json({ summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 } });
        }
        const summary = typeof rows[0].summary === 'string' ? JSON.parse(rows[0].summary) : rows[0].summary;
        res.json({ summary });
    }
    catch (e) {
        res.status(500).json({ error: e.message });
    }
});
