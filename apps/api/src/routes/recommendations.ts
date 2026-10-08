import { Router } from 'express';
import { z } from 'zod';

import { pool } from '../db/pool.js';
import { requireAuth, requireRole } from '../middleware/auth.js';
import { generateRecommendations, applyRecommendation, RecommendationError } from '../services/recommendation-engine.js';

export const recommendationsRouter = Router();
recommendationsRouter.use(requireAuth);

// List recommendations
recommendationsRouter.get('/', requireRole('viewer', 'operator', 'approver', 'admin'), async (req, res) => {
  const status = req.query.status ? String(req.query.status) : null;
  const hostId = req.query.hostId ? String(req.query.hostId) : null;

  let query = `SELECT pr.*, h.hostname, h.mgmt_ip,
    fas.duration_minutes as audit_duration, fas.started_at as audit_started_at
   FROM policy_recommendations pr
   JOIN hosts h ON h.id = pr.host_id
   JOIN firewall_audit_sessions fas ON fas.id = pr.audit_session_id
   WHERE 1=1`;
  const params: any[] = [];
  let paramIdx = 1;

  if (status) {
    query += ` AND pr.status = $${paramIdx++}`;
    params.push(status);
  }
  if (hostId) {
    query += ` AND pr.host_id = $${paramIdx++}`;
    params.push(hostId);
  }
  query += ` ORDER BY pr.created_at DESC`;

  const { rows } = await pool.query(query, params);
  res.json({ recommendations: rows });
});

// Get single recommendation
recommendationsRouter.get('/:id', requireRole('viewer', 'operator', 'approver', 'admin'), async (req, res) => {
  const { rows } = await pool.query(
    `SELECT pr.*, h.hostname, h.mgmt_ip FROM policy_recommendations pr
     JOIN hosts h ON h.id = pr.host_id WHERE pr.id = $1`,
    [req.params.id]
  );
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });
  res.json({ recommendation: rows[0] });
});

// Generate recommendations from audit session
recommendationsRouter.post('/generate', requireRole('operator', 'admin'), async (req, res) => {
  const bodySchema = z.object({
    auditSessionId: z.string().uuid(),
    hostId: z.string().uuid(),
  });
  const parsed = bodySchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body', details: parsed.error.issues });

  try {
    // Recommendation row + audit event are written in one transaction inside the service.
    const result = await generateRecommendations(
      parsed.data.auditSessionId,
      parsed.data.hostId,
      req.auth!.userId ?? null
    );
    if (!result.recommendationId) {
      return res.status(200).json({
        ...result,
        message: 'No new rules to recommend: all observed flows are already covered by pending recommendations or deployed rules',
      });
    }
    res.status(201).json(result);
  } catch (e: any) {
    if (e instanceof RecommendationError) return res.status(e.status).json({ error: e.code, message: e.message });
    throw e;
  }
});

// Accept recommendation
recommendationsRouter.post('/:id/accept', requireRole('operator', 'admin'), async (req, res) => {
  const userRes = await pool.query(`SELECT id FROM users WHERE username=$1 LIMIT 1`, [req.auth!.username]);
  const userId = userRes.rows[0]?.id ?? null;

  const { rows } = await pool.query(
    `UPDATE policy_recommendations SET status = 'ACCEPTED', reviewed_by = $2, reviewed_at = now()
     WHERE id = $1 AND status = 'PENDING' RETURNING *`,
    [req.params.id, userId]
  );
  if (!rows[0]) return res.status(404).json({ error: 'not_found_or_not_pending' });

  await pool.query(
    `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ($1, $2, $3, $4, $5)`,
    [userId, 'RECOMMENDATION_ACCEPT', 'policy_recommendation', req.params.id, JSON.stringify({ recommendationId: req.params.id })]
  );

  res.json({ recommendation: rows[0] });
});

// Reject recommendation
recommendationsRouter.post('/:id/reject', requireRole('operator', 'admin'), async (req, res) => {
  const userRes = await pool.query(`SELECT id FROM users WHERE username=$1 LIMIT 1`, [req.auth!.username]);
  const userId = userRes.rows[0]?.id ?? null;

  const { rows } = await pool.query(
    `UPDATE policy_recommendations SET status = 'REJECTED', reviewed_by = $2, reviewed_at = now()
     WHERE id = $1 AND status = 'PENDING' RETURNING *`,
    [req.params.id, userId]
  );
  if (!rows[0]) return res.status(404).json({ error: 'not_found_or_not_pending' });

  await pool.query(
    `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ($1, $2, $3, $4, $5)`,
    [userId, 'RECOMMENDATION_REJECT', 'policy_recommendation', req.params.id, JSON.stringify({ recommendationId: req.params.id })]
  );

  res.json({ recommendation: rows[0] });
});

// Apply accepted recommendation (creates DRAFT policy version)
recommendationsRouter.post('/:id/apply', requireRole('operator', 'admin'), async (req, res) => {
  const userRes = await pool.query(`SELECT id FROM users WHERE username=$1 LIMIT 1`, [req.auth!.username]);
  const userId = userRes.rows[0]?.id ?? null;

  const bodySchema = z.object({
    policySetId: z.string().uuid().optional(),
  });
  const parsed = bodySchema.safeParse(req.body ?? {});
  if (!parsed.success) return res.status(400).json({ error: 'invalid_body', details: parsed.error.issues });

  try {
    const result = await applyRecommendation(req.params.id, userId, parsed.data.policySetId);
    res.status(201).json(result);
  } catch (e: any) {
    if (e instanceof RecommendationError) return res.status(e.status).json({ error: e.code, message: e.message });
    throw e;
  }
});
