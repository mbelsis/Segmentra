import { Router } from 'express';

import { pool } from '../db/pool.js';
import { requireAuth, requireRole } from '../middleware/auth.js';

export const auditRouter = Router();
auditRouter.use(requireAuth, requireRole('viewer', 'operator', 'approver', 'admin'));

auditRouter.get('/audit', async (req, res) => {
  const actor = String(req.query.actor ?? '');
  const action = String(req.query.action ?? '');
  const entityType = String(req.query.entityType ?? '');
  const from = String(req.query.from ?? '');
  const to = String(req.query.to ?? '');

  const where: string[] = ['1=1'];
  const params: any[] = [];

  if (actor) {
    params.push(actor);
    where.push(`u.username = $${params.length}`);
  }
  if (action) {
    params.push(action);
    where.push(`a.action = $${params.length}`);
  }
  if (entityType) {
    params.push(entityType);
    where.push(`a.entity_type = $${params.length}`);
  }
  if (from) {
    params.push(from);
    where.push(`a.timestamp >= $${params.length}::timestamptz`);
  }
  if (to) {
    params.push(to);
    where.push(`a.timestamp <= $${params.length}::timestamptz`);
  }

  const { rows } = await pool.query(
    `SELECT a.*, u.username AS actor_username
     FROM audit_events a
     LEFT JOIN users u ON u.id = a.actor_user_id
     WHERE ${where.join(' AND ')}
     ORDER BY a.timestamp DESC
     LIMIT 500`,
    params
  );
  res.json({ events: rows });
});



