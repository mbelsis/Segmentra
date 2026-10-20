import { Router } from 'express';

import { pool } from '../db/pool.js';
import { requireAuth, requireRole } from '../middleware/auth.js';
import { buildBackup, importBackup, parseBackupDocument } from '../services/backup.js';

/**
 * Configuration backup and restore (admin only).
 *   GET  /api/backup/export            -> JSON document (download)
 *   POST /api/backup/import?dryRun=1   -> { dryRun, counts, warnings, problems }
 * See services/backup.ts for what the document contains and how an import behaves.
 */
export const backupRouter = Router();
backupRouter.use(requireAuth, requireRole('admin'));

backupRouter.get('/export', async (req, res) => {
  const { document, warnings } = await buildBackup(req.auth!.username);
  await pool.query(
    `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, metadata)
     VALUES ($1, 'BACKUP_EXPORT', 'backup', uuid_generate_v4(), $2)`,
    [req.auth!.userId, JSON.stringify({ by: req.auth!.username, counts: document.counts, warnings })]
  );
  const stamp = (document.exportedAt ?? new Date().toISOString()).replace(/[:.]/g, '-').slice(0, 19);
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="segmentra-backup-${stamp}.json"`);
  res.setHeader('X-Segmentra-Backup-Warnings', String(warnings.length));
  res.send(JSON.stringify({ ...document, warnings }, null, 2));
});

backupRouter.post('/import', async (req, res) => {
  const dryRun = String(req.query.dryRun ?? '') === 'true' || String(req.query.dryRun ?? '') === '1';
  let raw: unknown = req.body;
  // Accept either the document itself or { content: "<json text>" } (file upload from the UI)
  if (raw && typeof raw === 'object' && 'content' in (raw as any) && typeof (raw as any).content === 'string') {
    try {
      raw = JSON.parse((raw as any).content);
    } catch (e: any) {
      return res.status(400).json({ error: 'invalid_json', message: e?.message ?? 'not valid JSON' });
    }
  }
  if (raw && typeof raw === 'object' && 'warnings' in (raw as any)) delete (raw as any).warnings; // from a downloaded export
  const parsed = parseBackupDocument(raw);
  if (!parsed.document) {
    return res.status(400).json({ error: 'invalid_backup', problems: parsed.problems });
  }
  const result = await importBackup(parsed.document, { dryRun, actorUserId: req.auth!.userId, actorUsername: req.auth!.username });
  return res.json(result);
});
