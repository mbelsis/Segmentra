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

  // Paging: ?limit= (1..5000, default 500) and ?before=<nextCursor of the previous page>. The cursor is the
  // (timestamp, id) of the last event returned, with the timestamp at full microsecond precision so no
  // event is skipped or repeated between pages.
  const limit = clampAuditLimit(req.query.limit);
  const before = String(req.query.before ?? '');
  if (before) {
    const cursor = decodeAuditCursor(before);
    if (!cursor) return res.status(400).json({ error: 'invalid_cursor', message: 'before must be a nextCursor returned by this endpoint.' });
    params.push(cursor.ts, cursor.id);
    where.push(`(a.timestamp, a.id) < ($${params.length - 1}::timestamptz, $${params.length}::uuid)`);
  }
  params.push(limit + 1);

  const { rows } = await pool.query(
    `SELECT a.*, u.username AS actor_username,
            to_char(a.timestamp AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS _cursor_ts
     FROM audit_events a
     LEFT JOIN users u ON u.id = a.actor_user_id
     WHERE ${where.join(' AND ')}
     ORDER BY a.timestamp DESC, a.id DESC
     LIMIT $${params.length}`,
    params
  );
  const hasMore = rows.length > limit;
  const page = hasMore ? rows.slice(0, limit) : rows;
  const last = page[page.length - 1];
  const nextCursor = hasMore && last ? encodeAuditCursor(String(last._cursor_ts), String(last.id)) : null;
  const events = page.map(({ _cursor_ts, ...e }) => e);
  res.json({ events, nextCursor, limit });
});

export const AUDIT_DEFAULT_LIMIT = 500;
export const AUDIT_MAX_LIMIT = 5000;

export function clampAuditLimit(raw: unknown): number {
  const n = parseInt(String(raw ?? ''), 10);
  if (!Number.isFinite(n)) return AUDIT_DEFAULT_LIMIT;
  return Math.min(AUDIT_MAX_LIMIT, Math.max(1, n));
}

export function encodeAuditCursor(ts: string, id: string): string {
  return Buffer.from(`${ts}|${id}`, 'utf8').toString('base64url');
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const CURSOR_TS_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/;

export function decodeAuditCursor(cursor: string): { ts: string; id: string } | null {
  let text: string;
  try {
    text = Buffer.from(cursor, 'base64url').toString('utf8');
  } catch {
    return null;
  }
  const [ts, id, ...rest] = text.split('|');
  if (rest.length || !ts || !id || !CURSOR_TS_RE.test(ts) || !UUID_RE.test(id)) return null;
  return { ts, id };
}
